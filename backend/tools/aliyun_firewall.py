"""
阿里云安全组防火墙适配器

通过阿里云 SDK 管理 ECS 安全组规则，实现 IP 封禁/解封。

环境变量:
  ALIBABA_CLOUD_ACCESS_KEY_ID      — 阿里云 AccessKey ID
  ALIBABA_CLOUD_ACCESS_KEY_SECRET  — 阿里云 AccessKey Secret
  ALIYUN_SECURITY_GROUP_ID         — 安全组 ID（必填）
  ALIYUN_REGION_ID                 — 区域（默认 cn-beijing）
  ALIYUN_INTERFACE                 — 网卡类型（intranet/internet，默认 intranet）

注意:
  - 需要对安全组有 "AuthorizeSecurityGroup" 和 "RevokeSecurityGroup" 权限
  - 建议使用 RAM 子账号，授予最小权限
  - 生产环境建议使用 VPC 内网 API Endpoint
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from .base import FirewallAdapter

logger = logging.getLogger("secagentx.firewall.aliyun")


class AliyunFirewallAdapter(FirewallAdapter):
    """
    阿里云安全组防火墙后端

    使用阿里云 ECS SDK（不是 HTTP API），
    通过安全组规则实现 IP 封禁。

    如何获取安全组 ID:
      1. 登录阿里云控制台 → ECS → 安全组
      2. 找到目标安全组，复制 ID（如 sg-bp1axxxxxx）
      3. 配置在 .env: ALIYUN_SECURITY_GROUP_ID=sg-bp1axxxxxx

    权限要求（RAM 策略）:
      ecs:AuthorizeSecurityGroup
      ecs:RevokeSecurityGroup
      ecs:DescribeSecurityGroupAttribute
    """

    def __init__(self):
        self.access_key_id = os.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
        self.access_key_secret = os.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
        self.security_group_id = os.getenv("ALIYUN_SECURITY_GROUP_ID", "")
        self.region_id = os.getenv("ALIYUN_REGION_ID", "cn-beijing")
        self.interface = os.getenv("ALIYUN_INTERFACE", "intranet")

        # 缓存已封禁的 IP 列表
        self._cached_rules: list[dict] = []
        self._cache_time = 0.0

        self._client = None
        self._has_credentials = bool(
            self.access_key_id and self.access_key_secret and self.security_group_id
        )

    @property
    def client(self):
        """延迟初始化阿里云 ECS Client"""
        if self._client is None and self._has_credentials:
            try:
                from alibabacloud_ecs20140526.client import Client as EcsClient
                from alibabacloud_ecs20140526 import models as ecs_models
                from alibabacloud_tea_openapi import models as open_api_models

                config = open_api_models.Config(
                    access_key_id=self.access_key_id,
                    access_key_secret=self.access_key_secret,
                    region_id=self.region_id,
                )
                # 使用 VPC 内网 Endpoint（更快更安全）
                config.endpoint = f"ecs.{self.region_id}.aliyuncs.com"
                self._client = EcsClient(config)
            except ImportError:
                logger.critical(
                    "阿里云 SDK 未安装。请执行: pip install alibabacloud_ecs20140526"
                )
                raise
            except Exception as e:
                logger.error(f"阿里云客户端初始化失败: {e}")
                raise
        return self._client

    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        """封禁 IP：添加安全组入方向拒绝规则"""
        if not self._has_credentials:
            return False, "阿里云凭证未配置（ALIBABA_CLOUD_ACCESS_KEY_ID / SECRET）"

        try:
            from alibabacloud_ecs20140526 import models as ecs_models
            import asyncio

            # 阿里云 SDK 是同步的，在线程池中运行
            def _do_block():
                request = ecs_models.AuthorizeSecurityGroupRequest(
                    security_group_id=self.security_group_id,
                    ip_protocol="ALL",
                    port_range="-1/-1",
                    source_cidr_ip=f"{ip}/32",
                    policy="drop",
                    nic_type=self.interface,
                    description=f"SecAgentX: {reason[:120]}" if reason else "SecAgentX: auto-block",
                    priority=100,
                )
                resp = self.client.authorize_security_group(request)
                return resp.body.request_id

            request_id = await asyncio.to_thread(_do_block)
            logger.info(
                f"阿里云封禁成功: ip={ip}, sg={self.security_group_id}, "
                f"request_id={request_id}"
            )
            # 清除缓存
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            # 规则已存在不算错误
            if "InvalidAuthorization.Duplicate" in err_str:
                return True, "rule already exists"
            logger.error(f"阿里云封禁失败: {ip}: {e}")
            return False, f"阿里云封禁失败: {err_str[:200]}"

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        """解封 IP：删除安全组入方向规则"""
        if not self._has_credentials:
            return False, "阿里云凭证未配置"

        try:
            from alibabacloud_ecs20140526 import models as ecs_models
            import asyncio

            def _do_unblock():
                request = ecs_models.RevokeSecurityGroupRequest(
                    security_group_id=self.security_group_id,
                    ip_protocol="ALL",
                    port_range="-1/-1",
                    source_cidr_ip=f"{ip}/32",
                    policy="drop",
                    nic_type=self.interface,
                )
                resp = self.client.revoke_security_group(request)
                return resp.body.request_id

            request_id = await asyncio.to_thread(_do_unblock)
            logger.info(
                f"阿里云解封成功: ip={ip}, sg={self.security_group_id}, "
                f"request_id={request_id}"
            )
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            # 规则不存在不算错误
            err_str = str(e)
            if "InvalidAuthorization.NotFound" in err_str:
                return True, "rule not found (already removed)"
            logger.error(f"阿里云解封失败: {ip}: {e}")
            return False, f"阿里云解封失败: {err_str[:200]}"

    async def list_rules(self) -> list[dict]:
        """列出所有 SecAgentX 封禁的 IP 规则"""
        if not self._has_credentials:
            return []

        # 使用缓存（最多缓存 30 秒）
        import time
        if self._cached_rules and time.time() - self._cache_time < 30:
            return self._cached_rules

        try:
            from alibabacloud_ecs20140526 import models as ecs_models
            import asyncio

            def _do_list():
                request = ecs_models.DescribeSecurityGroupAttributeRequest(
                    security_group_id=self.security_group_id,
                    nic_type=self.interface,
                )
                resp = self.client.describe_security_group_attribute(request)
                rules = []
                for perm in resp.body.permissions.permission:
                    if perm.policy == "drop" and perm.direction == "ingress":
                        # 只返回 SecAgentX 管理的规则
                        desc = (perm.description or "").lower()
                        if "secagentx" in desc:
                            rules.append({
                                "ip": perm.source_cidr_ip.replace("/32", ""),
                                "reason": perm.description.replace("SecAgentX: ", ""),
                                "policy": perm.policy,
                                "priority": perm.priority,
                                "create_time": perm.create_time or "",
                            })
                return rules

            self._cached_rules = await asyncio.to_thread(_do_list)
            self._cache_time = time.time()
            return self._cached_rules

        except Exception as e:
            logger.error(f"阿里云查询规则失败: {e}")
            return []

    async def check_ip(self, ip: str) -> dict:
        """检查指定 IP 是否被封禁"""
        rules = await self.list_rules()
        for r in rules:
            if r["ip"] == ip:
                return {"is_blocked": True, "rule": r}
        return {"is_blocked": False}

    async def health_check(self) -> bool:
        """检查阿里云 API 是否可用"""
        if not self._has_credentials:
            return False
        try:
            rules = await self.list_rules()
            return True
        except Exception as e:
            logger.warning(f"阿里云健康检查失败: {e}")
            return False

    async def close(self):
        """关闭客户端连接"""
        self._client = None
        self._cached_rules = []

