import time
import json
import os
import asyncio
import logging
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import FrozenSet, Optional
from .base import BaseTool, ToolResult, FirewallAdapterFactory

logger = logging.getLogger("secagentx.firewall")

# Prometheus 指标（可选导入，无依赖时降级，记录告警）
try:
    from backend.monitoring.metrics import record_block
    _HAS_METRICS = True
except Exception as e:
    _HAS_METRICS = False
    import logging
    logging.getLogger("secagentx.firewall").warning(f"监控指标模块加载失败: {e}（不影响封禁功能）")
    def record_block(backend="disabled"): pass


BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", "data/blacklist/blacklist.json")

# 默认置信度门控阈值
# 可通过环境变量或 config.yaml 的 auto_operation.thresholds 覆盖
DEFAULT_BLOCK_CONFIDENCE_THRESHOLD = 0.70
DEFAULT_UNBLOCK_CONFIDENCE_THRESHOLD = 0.85
WHITELIST_IPS = os.getenv("FIREWALL_WHITELIST", "10.0.0.1,192.168.1.1,172.16.0.1").split(",")


@dataclass(frozen=True)
class FirewallExecutionContext:
    """服务端创建的防火墙执行上下文。

    该对象不属于 LLM 工具 schema。只有经过认证的 API 或已验证的联邦同步
    可以构造它，用来跳过置信度门控；白名单和熔断器始终不可绕过。
    """

    actor: str
    source: str
    allowed_actions: FrozenSet[str]
    reason: str = ""

    @classmethod
    def authenticated_api(
        cls, actor: str, permission: str, reason: str = ""
    ) -> "FirewallExecutionContext":
        permission_actions = {
            "firewall:block": frozenset({"block"}),
            "firewall:unblock": frozenset({"unblock"}),
        }
        actions = permission_actions.get(permission)
        if not actor or actions is None:
            raise ValueError("无效的防火墙人工授权上下文")
        return cls(
            actor=actor,
            source="authenticated_api",
            allowed_actions=actions,
            reason=reason,
        )

    @classmethod
    def federation_peer(
        cls, peer_id: str, reason: str = ""
    ) -> "FirewallExecutionContext":
        if not peer_id:
            raise ValueError("联邦节点标识不能为空")
        return cls(
            actor=f"federation:{peer_id}",
            source="federation_peer",
            allowed_actions=frozenset({"block", "unblock"}),
            reason=reason,
        )

    @classmethod
    def local_console(
        cls, action: str, actor: str = "local-console", reason: str = ""
    ) -> "FirewallExecutionContext":
        """为仅绑定回环地址的本机控制台创建人工处置上下文。"""
        if action not in {"block", "unblock"}:
            raise ValueError("无效的本机防火墙操作")
        return cls(
            actor=actor,
            source="local_console",
            allowed_actions=frozenset({action}),
            reason=reason,
        )

    def allows_confidence_override(self, action: str) -> bool:
        return (
            self.source in {"local_console", "federation_peer"}
            and action in self.allowed_actions
        )


class FirewallTool(BaseTool):
    """
    防火墙管理工具 — 通过适配器模式支持多种后端

    环境变量 FIREWALL_BACKEND 控制后端类型:
      - "disabled" : 禁止执行变更（企业安全默认）
      - "mock"     : 本地 JSON 模拟（仅测试）
      - "iptables" : 真实 iptables 封禁（生产 Linux）
      - "nftables" : nftables 封禁（现代 Linux，iptables 替代品）
      - "aliyun"   : 阿里云安全组 API（需安装 alibabacloud_ecs20140526）
      - "tencent"  : 腾讯云安全组 API（需安装 tencentcloud-sdk-python-vpc）
      - "aws"      : AWS 安全组 / WAF IP Set（需安装 boto3）
    """
    name = "firewall_manage"
    description = "管理防火墙规则：封禁IP、解封IP、查询封禁状态。自动封禁需要置信度≥阈值。"
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["block", "unblock", "list", "check"],
                "description": "操作类型: block封禁, unblock解封, list列出所有, check检查单个IP"
            },
            "ip": {
                "type": "string",
                "description": "目标IP地址"
            },
            "reason": {
                "type": "string",
                "description": "封禁原因说明"
            },
            "duration_minutes": {
                "type": "integer",
                "description": "封禁时长(分钟), 默认120分钟",
                "default": 120
            },
            "confidence": {
                "type": "number",
                "description": "分析置信度(0.0~1.0)，低于阈值时自动封禁被阻止",
                "default": 0.0
            },
        },
        "required": ["action"]
    }

    def __init__(self, block_threshold: float = DEFAULT_BLOCK_CONFIDENCE_THRESHOLD,
                 unblock_threshold: float = DEFAULT_UNBLOCK_CONFIDENCE_THRESHOLD,
                 whitelist: Optional[list[str]] = None,
                 backend: str = None):
        # ==================== 适配器模式核心：通过工厂创建后端 ====================
        self._backend = FirewallAdapterFactory.create(backend)
        # =========================================================================

        self._block_threshold = block_threshold
        self._unblock_threshold = unblock_threshold
        self._whitelist = WHITELIST_IPS if whitelist is None else whitelist
        self._whitelist_networks = []
        for entry in self._whitelist:
            entry = str(entry).strip()
            if not entry:
                continue
            try:
                self._whitelist_networks.append(
                    ipaddress.ip_network(entry, strict=False)
                )
            except ValueError:
                logger.warning("忽略无效防火墙白名单项: %s", entry)
        self.agent_id = "firewall_tool"
        self._backend_type = backend or os.getenv("FIREWALL_BACKEND", "disabled")

    @staticmethod
    def _normalize_ip(ip: str) -> tuple[Optional[str], Optional[str]]:
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None, f"无效的 IP 地址: {ip}"

        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            return None, f"不允许操作特殊用途 IP 地址: {address}"
        return str(address), None

    def _is_whitelisted(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return any(address in network for network in self._whitelist_networks)

    async def execute(self, action: str = "list", ip: str = "",
                      reason: str = "", duration_minutes: int = 120,
                      confidence: float = 0.0,
                      *, authorization_context: Optional[FirewallExecutionContext] = None
                      ) -> ToolResult:
        start = time.time()
        confidence_override = (
            isinstance(authorization_context, FirewallExecutionContext)
            and authorization_context.allows_confidence_override(action)
        )

        if action == "block":
            if not ip:
                return ToolResult(success=False, error="封禁操作需要指定IP地址")

            ip, ip_error = self._normalize_ip(ip)
            if ip_error:
                return ToolResult(success=False, error=ip_error)

            # ═══════════════════ 熔断器检查 ═══════════════════
            try:
                from backend.security.circuit_breaker import circuit_breaker
                if not circuit_breaker.check():
                    elapsed = (time.time() - start) * 1000
                    cb_status = circuit_breaker.get_status()
                    return ToolResult(
                        success=False,
                        data={
                            "action": "rejected",
                            "ip": ip,
                            "reason": "熔断器已触发",
                            "circuit_breaker": cb_status,
                        },
                        error=(
                            f"熔断器已触发 (状态: {cb_status['state']}, "
                            f"今日封禁: {cb_status['blocks_today']}/{cb_status['daily_limit']})"
                        ),
                        duration_ms=elapsed,
                    )
            except Exception as e:
                elapsed = (time.time() - start) * 1000
                logger.error("熔断器检查失败，拒绝执行封禁: %s", e)
                return ToolResult(
                    success=False,
                    data={"action": "rejected", "ip": ip,
                          "reason": "安全检查失败"},
                    error="熔断器安全检查失败，已拒绝封禁",
                    duration_ms=elapsed,
                )

            # ═══════════════════ 置信度门控 ═══════════════════
            if not confidence_override and confidence < self._block_threshold:
                elapsed = (time.time() - start) * 1000
                return ToolResult(
                    success=False,
                    data={
                        "action": "rejected",
                        "ip": ip,
                        "confidence": confidence,
                        "threshold": self._block_threshold,
                        "message": (
                            f"自动封禁被阻止：置信度 {confidence:.0%} < "
                            f"阈值 {self._block_threshold:.0%}。"
                            "如需人工处置，请使用具备 firewall:block 权限的 API。"
                        ),
                    },
                    error=(
                        f"置信度不足: {confidence:.0%} < {self._block_threshold:.0%}, "
                        f"自动封禁被阻止"
                    ),
                    duration_ms=elapsed,
                )

            # ═══════════════════ 白名单保护 ═══════════════════
            if self._is_whitelisted(ip):
                elapsed = (time.time() - start) * 1000
                return ToolResult(
                    success=False,
                    data={
                        "action": "rejected",
                        "ip": ip,
                        "reason": f"IP {ip} 在白名单中，不允许自动封禁",
                    },
                    error=f"IP {ip} 在白名单中，不允许自动封禁",
                    duration_ms=elapsed,
                )

            # ═══════════════════ 通过适配器执行真实封禁 ═══════════════════
            success, err = await self._backend.block_ip(ip, reason, duration_minutes)
            if not success:
                elapsed = (time.time() - start) * 1000
                return ToolResult(success=False, error=err, duration_ms=elapsed)

            # 记录审计日志和熔断器状态（重要：失败时记录告警，不静默吞掉）
            try:
                from backend.security.audit import audit_repo
                from backend.security.circuit_breaker import circuit_breaker
                audit_repo.log(
                    actor=(authorization_context.actor
                           if confidence_override else self.agent_id),
                    action_type="block",
                    target=ip,
                    detail={
                        "reason": reason, "duration": duration_minutes,
                        "confidence": confidence, "backend": self._backend_type,
                        "source": (authorization_context.source
                                   if confidence_override else "agent"),
                    },
                    confidence=confidence,
                    result="success",
                    reason=reason or "自动封禁",
                )
                circuit_breaker.record_block()
            except Exception as e:
                logger.warning(f"审计日志/熔断器记录失败: {e}（不影响封禁功能）")

            # 记录 Prometheus 指标
            record_block(backend=self._backend_type)

            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data={
                "action": "blocked",
                "ip": ip,
                "reason": reason,
                "confidence": confidence,
                "duration_minutes": duration_minutes,
                "backend": self._backend_type,
                "message": f"IP {ip} 已通过 [{self._backend_type}] 封禁 (置信度: {confidence:.0%})，时长 {duration_minutes} 分钟",
            }, duration_ms=elapsed)

        elif action == "unblock":
            if not ip:
                return ToolResult(success=False, error="解封操作需要指定IP地址")

            ip, ip_error = self._normalize_ip(ip)
            if ip_error:
                return ToolResult(success=False, error=ip_error)

            # 解封也需要置信度门控（默认更严格）
            if not confidence_override and confidence < self._unblock_threshold:
                elapsed = (time.time() - start) * 1000
                return ToolResult(
                    success=False,
                    data={
                        "action": "rejected",
                        "ip": ip,
                        "message": (
                            f"自动解封被阻止：置信度 {confidence:.0%} < "
                            f"阈值 {self._unblock_threshold:.0%}。威胁尚未确认解除。"
                        ),
                    },
                    error=f"置信度不足: {confidence:.0%} < {self._unblock_threshold:.0%}, 自动解封被阻止",
                    duration_ms=elapsed,
                )

            # ═══════════════════ 通过适配器执行真实解封 ═══════════════════
            success, err = await self._backend.unblock_ip(ip)
            if not success:
                elapsed = (time.time() - start) * 1000
                return ToolResult(success=False, error=err, duration_ms=elapsed)

            # 记录审计日志
            try:
                from backend.security.audit import audit_repo
                audit_repo.log(
                    actor=(authorization_context.actor
                           if confidence_override else self.agent_id),
                    action_type="unblock",
                    target=ip,
                    detail={
                        "reason": reason,
                        "backend": self._backend_type,
                        "source": (authorization_context.source
                                   if confidence_override else "agent"),
                    },
                    confidence=confidence,
                    result="success",
                    reason=reason or "自动解封",
                )
            except Exception as e:
                logger.warning(f"审计日志记录失败（解封）: {e}（不影响解封功能）")

            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data={
                "action": "unblocked",
                "ip": ip,
                "message": f"IP {ip} 已通过 [{self._backend_type}] 解封",
            }, duration_ms=elapsed)

        elif action == "list":
            rules = await self._backend.list_rules()
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data={
                "action": "list",
                "backend": self._backend_type,
                "total": len(rules),
                "rules": rules,
            }, duration_ms=elapsed)

        elif action == "check":
            if not ip:
                return ToolResult(success=False, error="检查操作需要指定IP地址")
            ip, ip_error = self._normalize_ip(ip)
            if ip_error:
                return ToolResult(success=False, error=ip_error)
            result = await self._backend.check_ip(ip)
            elapsed = (time.time() - start) * 1000
            result["action"] = "check"
            result["backend"] = self._backend_type
            return ToolResult(success=True, data=result, duration_ms=elapsed)

        return ToolResult(success=False, error=f"未知操作: {action}")
