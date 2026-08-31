import time
import re
import json
from datetime import datetime, timezone
from typing import Optional
from .base import BaseTool, ToolResult


FALSE_POSITIVE_PATTERNS = [
    (r'npm|pip|apt-get|yum|brew|nuget|go\s+install|cargo\s+install', '包管理器流量'),
    (r'github\.com|gitlab|bitbucket|gitee|git\s+clone|git\s+pull', '代码仓库流量'),
    (r'cdn\.|cloudflare|akamai|jsdelivr|unpkg|cdnjs', 'CDN静态资源'),
    (r'google-analytics|gtag|baidu.*stats|cnzz|clarity\.microsoft', '统计分析/埋点'),
    (r'nessus|openvas|nmap|sqlmap|burp|zap|acunetix|nikto', '安全工具扫描(内部)'),
    (r'heartbeat|keepalive|health.*check|healthz|ping|healthcheck', '心跳/健康检查'),
    (r'login.*success|logout.*success|loginsuccess|loginsucceeded', '正常登录成功'),
    (r'localhost|127\.0\.0\.1|::1|10\.\d+\.\d+\.\d+|172\.1[6-9]\.|192\.168\.', '内网地址'),
    (r'test|debug|demo|sample|internal.*test|staging|dev-', '测试环境流量'),
    (r"let's encrypt|ssl.*verify|certificate.*check|ocsp", '证书自动验证'),
    (r'cron|scheduler|systemd|init\.d|rc\.local', '系统定时任务'),
    (r'windows\s+update|microsoft\s+update|apple\s+update', '系统自动更新'),
    (r'docker|k8s|kubernetes|kubelet|etcd|container', '容器平台通信'),
]

# 默认白名单（被 main.py 的 config 覆盖）
# 完整列表从 config.yaml: auto_operation.block_protection.whitelist_ips 读取
WHITELIST_IPS = ['10.0.0.1', '10.0.1.1', '192.168.1.1', '172.16.0.1']
AGGREGATE_THRESHOLD = 5
AGGREGATE_WINDOW_SECONDS = 60


class AlertFilterTool(BaseTool):
    name = "alert_filter"
    description = "告警误报检测工具：规则引擎过滤、白名单检查、聚合检测，支持批量处理"
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["single_judge", "batch_judge", "get_stats"],
                "description": "操作类型"
            },
            "alert": {
                "type": "object",
                "description": "告警数据"
            },
            "alerts": {
                "type": "array",
                "description": "告警列表"
            }
        },
        "required": ["action"]
    }

    ALERT_HISTORY_MAX_KEYS = 50000  # 最多跟踪 5 万个不同的 key

    def __init__(self):
        self._alert_history: dict[str, list[datetime]] = {}
        self._stats = {
            "total_processed": 0,
            "rule_filtered": 0,
            "whitelist_filtered": 0,
            "aggregation_merged": 0,
            "llm_confirmed_real": 0,
            "llm_confirmed_fp": 0,
            "suspicious": 0,
        }

    async def execute(self, action: str = "get_stats", alert: Optional[dict] = None,
                      alerts: Optional[list] = None) -> ToolResult:
        start = time.time()

        if action == "single_judge":
            if not alert:
                return ToolResult(success=False, error="缺少告警数据")
            result = self._judge_single(alert)
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data=result, duration_ms=elapsed)

        elif action == "batch_judge":
            if not alerts:
                return ToolResult(success=False, error="缺少告警列表")
            results = [self._judge_single(a) for a in alerts]
            total = len(results)
            fp_count = sum(1 for r in results if r["final_judgment"] == "false_positive")
            real_count = sum(1 for r in results if r["final_judgment"] == "real_attack")
            susp_count = sum(1 for r in results if r["final_judgment"] == "suspicious")
            pending = sum(1 for r in results if r["final_judgment"] == "pending_llm")
            rule_resolved = fp_count  # 规则已确认的误报数
            unresolved = total - fp_count - real_count  # LLM 待研判 + 可疑
            fp_rate = f"{fp_count / total * 100:.1f}%" if total > 0 else "0%"
            unresolved_rate = f"{unresolved / total * 100:.1f}%" if total > 0 else "0%"
            elapsed = (time.time() - start) * 1000
            return ToolResult(success=True, data={
                "total_alerts": total,
                "false_positives": fp_count,
                "real_alerts": real_count,
                "suspicious": susp_count,
                "pending_llm": pending,
                "false_positive_rate": fp_rate,          # 规则引擎已确认误报率
                "unresolved_rate": unresolved_rate,      # 待进一步研判的比例
                "details": results,
                "stats": dict(self._stats),
            }, duration_ms=elapsed)

        elif action == "get_stats":
            return ToolResult(success=True, data=dict(self._stats), duration_ms=0)

        return ToolResult(success=False, error=f"未知操作: {action}")

    def _judge_single(self, alert: dict) -> dict:
        self._stats["total_processed"] += 1

        result = {
            "alert_id": alert.get("id", ""),
            "alert_title": alert.get("title", ""),
            "original_severity": alert.get("severity", ""),
            "source_ip": alert.get("src_ip", ""),
            "destination_ip": alert.get("dst_ip", ""),
            "steps": [],
            "final_judgment": "suspicious",
            "final_severity": "待观察",
            "confidence": "low",
        }

        # Layer 1: 白名单检查
        if alert.get("src_ip") in WHITELIST_IPS:
            result["steps"].append({
                "layer": 1, "name": "白名单检查",
                "action": "标记误报",
                "reason": f"源IP {alert['src_ip']} 在白名单中",
            })
            result["final_judgment"] = "false_positive"
            result["final_severity"] = "已过滤"
            result["confidence"] = "high"
            self._stats["whitelist_filtered"] += 1
            return result

        # Layer 2: 规则引擎过滤
        check_text = f"{alert.get('title', '')} {alert.get('description', '')} {alert.get('type', '')}"
        rule_match = self._check_rules(check_text)
        if rule_match["matched"]:
            result["steps"].append({
                "layer": 2, "name": "规则引擎",
                "action": "标记误报",
                "reason": rule_match["reason"],
                "keyword": rule_match["keyword"],
            })
            result["final_judgment"] = "false_positive"
            result["final_severity"] = "已过滤"
            result["confidence"] = "high"
            self._stats["rule_filtered"] += 1
            return result

        # Layer 3: 聚合检测
        aggregation = self._check_aggregation(alert)
        if aggregation["aggregated"]:
            result["steps"].append({
                "layer": 3, "name": "聚合检测",
                "action": "告警合并",
                "reason": f"同类告警在{AGGREGATE_WINDOW_SECONDS}秒内出现{aggregation['count']}次",
            })
            self._stats["aggregation_merged"] += 1

        # Layer 4: 需要LLM深度研判
        result["steps"].append({
            "layer": 4, "name": "等待LLM研判",
            "action": "需AI模型深度分析",
            "reason": "规则层无法明确判定，需分析上下文",
        })
        result["needs_llm_analysis"] = True
        result["final_judgment"] = "pending_llm"
        result["final_severity"] = "待研判"
        result["confidence"] = "low"
        return result

    def _check_rules(self, text: str) -> dict:
        for pattern, reason in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return {"matched": True, "reason": reason, "keyword": pattern}
        return {"matched": False, "reason": ""}

    def _check_aggregation(self, alert: dict) -> dict:
        key = f"{alert.get('src_ip', '')}:{alert.get('title', '')}"
        now = datetime.now(timezone.utc)

        # 防 OOM：超过限制时清空最旧的 20%
        if len(self._alert_history) > self.ALERT_HISTORY_MAX_KEYS:
            sorted_keys = sorted(
                self._alert_history.keys(),
                key=lambda k: self._alert_history[k][-1] if self._alert_history[k] else now,
            )
            evict = max(int(len(sorted_keys) * 0.2), 1)
            for k in sorted_keys[:evict]:
                self._alert_history.pop(k, None)

        if key not in self._alert_history:
            self._alert_history[key] = []
        self._alert_history[key] = [
            t for t in self._alert_history[key]
            if (now - t).total_seconds() < AGGREGATE_WINDOW_SECONDS
        ]
        self._alert_history[key].append(now)
        count = len(self._alert_history[key])
        return {"aggregated": count >= AGGREGATE_THRESHOLD, "count": count}

    # get_simulated_alerts 已移除——工具不返回虚假数据

