import time
import re
from datetime import datetime, timezone
from collections import Counter
from typing import Optional
from .base import BaseTool, ToolResult


class LogAnalyzerTool(BaseTool):
    name = "log_analyzer"
    description = "分析安全日志，提取异常模式、攻击特征、时间线信息"
    parameters = {
        "type": "object",
        "properties": {
            "log_content": {
                "type": "string",
                "description": "日志内容文本"
            },
            "log_type": {
                "type": "string",
                "enum": ["access", "error", "auth", "system", "firewall", "ids"],
                "description": "日志类型"
            },
            "time_range": {
                "type": "string",
                "description": "时间范围描述，如 '24h' '7d' '1h'"
            }
        },
        "required": ["log_content"]
    }

    def __init__(self):
        self._patterns = {
            "sql_injection": [
                r"(?i)(\bunion\b.*\bselect\b)",
                r"(?i)(\bselect\b.*\bfrom\b)",
                r"(?i)(\b1=1\b|\b1=2\b)",
                r"(?i)(\bdrop\b.*\btable\b)",
                r"(?i)(\badmin'?\s*--)",
                r"(?i)(\b'or\b.*\b=')",
                r"(?i)(sleep\s*\(\s*\d+\s*\))",
            ],
            "xss": [
                r"(?i)(<script[^>]*>)",
                r"(?i)(javascript\s*:)",
                r"(?i)(onerror\s*=)",
                r"(?i)(onload\s*=)",
                r"(?i)(alert\s*\()",
                r"(?i)(<img\s+.*\bonerror)",
            ],
            "port_scan": [
                r"(?i)(port\s*\d+\s*scan)",
                r"(?i)(syn\s*scan)",
                r"(?i)(multiple\s*ports)",
                r"(?i)(connection\s*refused)",
            ],
            "brute_force": [
                r"(?i)(failed\s*password)",
                r"(?i)(login\s*failed)",
                r"(?i)(invalid\s*credentials)",
                r"(?i)(too\s*many\s*login)",
                r"(?i)(bruteforce|brute\s*force)",
            ],
            "malware": [
                r"(?i)(malicious\s*file)",
                r"(?i)(trojan|worm|ransomware|backdoor)",
                r"(?i)(suspicious\s*process)",
                r"(?i)(unknown\s*executable)",
            ],
            "data_exfil": [
                r"(?i)(data\s*exfil)",
                r"(?i)(large\s*outbound)",
                r"(?i)(dns\s*tunnel)",
                r"(?i)(unusual\s*outbound)",
            ],
        }

        self._ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # 各攻击类型判定为"确认攻击"所需的最小匹配次数。
    # 低于该值只标记"疑似(低置信度)"，避免把零星几次失败误判为高危攻击。
    MIN_CONFIRM_COUNTS = {
        "sql_injection": 2,
        "xss": 2,
        "port_scan": 3,
        "brute_force": 5,      # 暴力破解：需多次失败才判"高危"（2次可能是手输错误）
        "malware": 1,
        "data_exfil": 1,
    }

    async def execute(self, log_content: str, log_type: str = "access",
                      time_range: str = "") -> ToolResult:
        start = time.time()

        if not log_content.strip():
            return ToolResult(success=False, error="日志内容为空")

        lines = log_content.strip().split("\n")
        ips = self._extract_ips(log_content)
        findings = self._analyze_patterns(log_content)
        ip_stats = self._analyze_ips(lines, ips)
        severity = self._assess_severity(findings)

        elapsed = (time.time() - start) * 1000
        return ToolResult(success=True, data={
            "total_lines": len(lines),
            "unique_ips": len(ips),
            "ips_found": list(ips)[:20],
            "findings": findings,
            "ip_activity": ip_stats,
            "severity": severity,
            "summary": self._generate_summary(findings, len(lines), len(ips)),
        }, duration_ms=elapsed)

    def _extract_ips(self, text: str) -> set:
        return set(self._ip_pattern.findall(text))

    def _analyze_patterns(self, text: str) -> list[dict]:
        findings = []
        for attack_type, patterns in self._patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, text)
                matches.extend(found)
            if matches:
                count = len(matches)
                min_confirm = self.MIN_CONFIRM_COUNTS.get(attack_type, 1)
                confirmed = count >= min_confirm
                severity = self._attack_severity(attack_type)
                if not confirmed:
                    # 未达确认阈值：降级，避免"2次失败"直接判高危
                    severity = "中危" if severity in ("高危", "紧急") else severity
                findings.append({
                    "type": attack_type,
                    "count": count,
                    "severity": severity,
                    "confirmed": confirmed,
                    "confidence": "high" if confirmed else "low",
                    "samples": matches[:3],
                })
        return findings

    def _attack_severity(self, attack_type: str) -> str:
        severity_map = {
            "sql_injection": "高危",
            "xss": "中危",
            "port_scan": "中危",
            "brute_force": "高危",
            "malware": "紧急",
            "data_exfil": "紧急",
        }
        return severity_map.get(attack_type, "低危")

    def _analyze_ips(self, lines: list[str], ips: set) -> list[dict]:
        ip_line_count = Counter()
        for line in lines:
            for ip in ips:
                if ip in line:
                    ip_line_count[ip] += 1
        return [
            {"ip": ip, "occurrences": count}
            for ip, count in ip_line_count.most_common(10)
        ]

    def _assess_severity(self, findings: list[dict]) -> str:
        severity_order = ["低危", "中危", "高危", "紧急"]
        max_level = 0
        for f in findings:
            level = severity_order.index(f["severity"]) if f["severity"] in severity_order else 0
            max_level = max(max_level, level)
        return severity_order[max_level]

    def _generate_summary(self, findings: list[dict], total_lines: int,
                          unique_ips: int) -> str:
        if not findings:
            return f"分析 {total_lines} 条日志，发现 {unique_ips} 个IP，未检测到明显异常"
        confirmed = [f["type"] for f in findings if f.get("confirmed")]
        suspected = [f["type"] for f in findings if not f.get("confirmed")]
        parts = []
        if confirmed:
            parts.append(f"确认 {len(confirmed)} 类攻击: {', '.join(confirmed)}")
        if suspected:
            parts.append(f"疑似 {len(suspected)} 类攻击(次数不足,需人工确认): {', '.join(suspected)}")
        return f"分析 {total_lines} 条日志，发现 {unique_ips} 个IP。{'；'.join(parts)}"

