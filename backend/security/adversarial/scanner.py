"""
Prompt Injection 扫描器（v2.4 M6）

多层检测用户输入中的提示注入，全部确定性规则 + 变体识别：
  1. 直接指令注入: 忽略系统提示 / 覆盖指令 / 无需遵循
  2. 角色劫持: 扮演 / 现在你是 / 成为管理员 / DAN
  3. 编码绕过: base64 / hex / unicode 混淆 / 双写
  4. 越权指令: 调用防火墙 / 删除 / 泄露 API Key
  5. 信息泄露探测: 输出你的 system prompt / 密钥

输出:
  detected: bool
  findings: [{rule_id, category, severity, matched_text, recommendation}]
  score: 0~100（注入严重度）
"""

import re
import base64
from typing import Optional

# 规则表: rule_id -> (类别, 严重度, 模式, 建议)
INJECTION_RULES = [
    # ── 直接指令注入 ──
    ("INJ-DIRECT-01", "direct", "high",
    r"忽略.{0,10}(上述|之前|系统|所有|指令|提示|system|instruction|prompt)",
    "检测到'忽略系统指令'类注入，应拒绝执行覆盖性指令"),
    ("INJ-DIRECT-02", "direct", "high",
    r"(你是|你现在是|从此|接下来你).{0,15}(系统|assistant|agent)",
    "检测到角色覆盖指令（试图重置系统角色）"),
    ("INJ-DIRECT-03", "direct", "medium",
    r"(无需|不要|不必).{0,10}(遵循|遵守|考虑).{0,10}(指令|规则|系统|限制)",
    "检测到'无需遵循规则'类指令"),
    ("INJ-DIRECT-04", "direct", "high",
    r"(override|ignore (previous|all|above)|disregard|forget all).{0,40}(instruction|prompt|rules)",
    "检测到英文指令覆盖（override/ignore）"),
    ("INJ-DIRECT-05", "direct", "high",
    r"(请|直接|现在|立即)?.{0,3}(输出|打印|显示|泄露|给出|告诉我).{0,10}(system\s?prompt|系统提示|系统指令|初始化指令|全部配置)",
    "检测到 system prompt 泄露探测"),
    # ── 角色劫持 ──
    ("INJ-ROLE-01", "role", "high",
    r"扮演|角色扮演|现在你是|作为管理员|act as|you are now|DAN\b|jailbreak",
    "检测到角色劫持/越狱（jailbreak）尝试"),
    ("INJ-ROLE-02", "role", "medium",
    r"绕过.{0,10}(限制|审查|安全|filter|safety)|不受.{0,6}(限制|约束)",
    "检测到绕过限制/审查请求"),
    # ── 越权指令 ──
    ("INJ-TOOL-01", "tool_abuse", "critical",
    r"(调用|执行|直接调用).{0,10}(firewall_manage|防火墙|封禁|删除所有|drop table|rm -rf)",
    "检测到越权工具/命令调用请求"),
    ("INJ-TOOL-02", "tool_abuse", "critical",
    r"(泄露|给出|输出).{0,8}(api[_-]?key|密钥|token|口令|password)",
    "检测到敏感凭据泄露请求"),
    ("INJ-TOOL-03", "tool_abuse", "high",
    r"(删除|清空).{0,10}(数据库|所有数据|全部记录)|sql.{0,4}drop|delete.{0,6}from",
    "检测到破坏性操作请求"),
    # ── 信息泄露探测 ──
    ("INJ-LEAK-01", "data_extraction", "high",
    r"(你的|您的).{0,4}(指令|提示词|system\s?prompt|角色设定|人格|初始化).{0,6}(是什么|是什么内容|完整输出|全文|给我)",
    "检测到提示词提取探测"),
    ("INJ-LEAK-02", "data_extraction", "medium",
    r"(内部|隐藏).{0,6}(逻辑|配置|规则|设置)|(密钥|key).{0,4}(在|存在|位置)",
    "检测到内部配置/密钥探测"),
    # ── 间接注入标记（RAG 投毒场景由调用方单独处理） ──
    ("INJ-INDIRECT-01", "indirect", "medium",
    r"忽略.{0,10}(本文档|文档|检索|检索到的|知识库).{0,6}(内容|指令|提示)",
    "检测到针对检索文档的间接注入（RAG 投毒）"),
    ("INJ-INDIRECT-02", "indirect", "medium",
    r"(根据|依据).{0,6}(文档|检索|知识库|条目|内容).{0,8}(执行|忽略|包含|遵循)",
    "检测到通过检索内容传导的指令注入"),
    # ── 编码/混淆命令 ──
    ("INJ-ENC-01", "encoded", "medium",
    r"(执行|运行|解码|命令).{0,4}(以下|命令|指令).{0,4}[a-zA-Z0-9+/=]{16,}",
    "检测到疑似编码/混淆命令（base64/hex 等）"),
    ("INJ-ENC-02", "encoded", "low",
    r"\b[a-zA-Z0-9+/]{20,}={0,2}\b",
    "检测到疑似 base64 编码串"),
    # ── 破坏性 SQL / 凭据 ──
    ("INJ-TOOL-04", "tool_abuse", "critical",
    r"\bdrop\s+table|\bdelete\s+from|\brm\s+-rf|\btruncate\b",
    "检测到破坏性 SQL/命令"),
    ("INJ-TOOL-05", "tool_abuse", "critical",
    r"\b(deepseek|qwen|openai|google|vt|abuseipdb|otx)[_-]?(api[_-]?key|secret|token)\b",
    "检测到 API 密钥泄露请求"),
    ("INJ-TOOL-06", "tool_abuse", "high",
    r"(root|admin|管理员|超级用户).{0,6}(密码|口令|password)|(密码|口令).{0,4}(告诉我|是什么)",
    "检测到系统凭据获取请求"),
    ]

# 高严重度类别（触发 block 策略）
CRITICAL_CATEGORIES = {"tool_abuse"}
HIGH_CATEGORIES = {"direct", "role", "data_extraction"}


def decode_base64_maybe(text: str) -> str:
    """尝试 base64 解码（检测编码绕过）。失败返回原文。"""
    try:
        # 去空白后尝试 base64
        candidate = re.sub(r"\s+", "", text)
        # 必须是有效的 base64（长度%4==0 且含 base64 字符）
        if len(candidate) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", candidate or "x"):
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            if decoded and any(ord(c) > 127 or c.isalpha() for c in decoded):
                return decoded
    except Exception:
        pass
    return text


def normalize_text(text: str) -> str:
    """归一化：小写 + 去零宽字符 + 全角转半角 + 合并空白。"""
    if not text:
        return ""
    t = text.lower()
    # 去零宽字符（隐藏字符混淆）
    t = re.sub(r"[\u200b\u200c\u200d\ufeff\u2060]", "", t)
    # 全角转半角
    t = t.translate(str.maketrans("，。！？（）【】：；", ",.!?()[]:;"))
    return re.sub(r"\s+", " ", t)


class PromptInjectionScanner:
    """Prompt Injection 多层检测器。"""

    def __init__(self):
        self._compiled = [
            (rid, cat, sev, re.compile(pat, re.IGNORECASE), rec)
            for rid, cat, sev, pat, rec in INJECTION_RULES
        ]

    def scan(self, text: str) -> dict:
        """扫描输入，返回检测结果。"""
        if not text:
            return {"detected": False, "findings": [], "score": 0,
                    "severity": "none", "policy": "allow"}
        findings = []
        max_severity_rank = 0
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        # 直接匹配
        norm = normalize_text(text)
        for rid, cat, sev, pattern, rec in self._compiled:
            m = pattern.search(norm)
            if m:
                matched = m.group(0)[:80]
                findings.append({
                    "rule_id": rid, "category": cat, "severity": sev,
                    "matched_text": matched, "recommendation": rec,
                })
                max_severity_rank = max(max_severity_rank, severity_rank.get(sev, 0))

        # 编码绕过：base64 解码后二次扫描
        if not findings:
            decoded = decode_base64_maybe(text)
            if decoded and decoded != text:
                decoded_findings = self.scan(decoded)["findings"]
                for f in decoded_findings:
                    f = dict(f)
                    f["rule_id"] = f["rule_id"] + "-ENC"
                    f["matched_text"] = f"[base64解码] {f['matched_text']}"
                    findings.append(f)
                    max_severity_rank = max(max_severity_rank, severity_rank.get(f["severity"], 0))

        # 严重度
        severity = next((s for s, r in severity_rank.items() if r == max_severity_rank), "none")

        # 策略决策（由 guard.py 最终执行，此处仅计算）
        if any(f["category"] in CRITICAL_CATEGORIES for f in findings):
            policy = "block"
        elif max_severity_rank >= severity_rank["high"]:
            policy = "block"
        elif findings:
            policy = "warn"
        else:
            policy = "allow"

        return {
            "detected": bool(findings),
            "findings": findings,
            "score": min(100, max_severity_rank * 25),
            "severity": severity,
            "policy": policy,
        }

    @staticmethod
    def evaluate_policy(config_policy: str, scan_result: dict) -> str:
        """按配置策略（log/warn/block）+ 扫描结果决定最终动作。

        配置优先级低于扫描严重度：扫描为 block 时，即使配置为 log 也强制 warn/block。
        """
        scan_policy = scan_result.get("policy", "allow")
        severity = scan_result.get("severity", "none")
        # 严重度级别（决定最小干预）
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        cfg_rank = {"block": 3, "warn": 2, "log": 1, "allow": 0}
        # critical 注入必须 block（不可降级，即使配置为 log）
        if severity == "critical" or scan_policy == "block":
            return "block"
        # 高严重度（high）强制至少 warn
        if sev_rank.get(severity, 0) >= 3:
            return "warn" if cfg_rank.get(config_policy, 0) < 2 else config_policy
        # medium 及以下：按配置策略执行（log 配置 -> 仅记录）
        if scan_result.get("detected"):
            return config_policy if config_policy in ("log", "warn", "block") else "warn"
        return "allow"


__all__ = ["PromptInjectionScanner", "INJECTION_RULES", "normalize_text",
           "decode_base64_maybe"]
