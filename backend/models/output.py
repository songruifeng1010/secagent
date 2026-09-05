"""
结构化输出模型 — SecAgentX Agent 输出格式改造（文本 → JSON 结构化）

设计目标:
  1. Agent 级输出为顶层 JSON（AgentResult），不再"文本内嵌 JSON"
  2. 编排器最终结果为顶层 JSON（FinalResult），含置信度聚合 + 风险评分
  3. 人类可读文本由确定性渲染器产出（result_to_text / final_to_markdown），
     与结构化结果共用同一数据源，不依赖 LLM 自由文本格式

兼容迁移（决策确认）:
  - 旧字段 `content` / `summary` / `structured` / `confidence_aggregate`
    / `risk_scorecard` / `tool_call_history` 全部保留
  - 新增顶层 `structured_result`（JSON）
  - `score` = risk_scorecard.risk_score（与 confidence 解耦，独立字段）

字段设计:
  - 全部带默认值，LLM 输出部分字段也能校验通过
  - enum 字段提供容错 coercion（英文/中文/大小写/百分比字符串）
  - extra 字段忽略（容忍 LLM 输出多余键）
"""
from __future__ import annotations

import json
import re
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ═══════════════════════ 枚举 ═══════════════════════

class Verdict(str, Enum):
    """安全判定结论"""
    MALICIOUS = "malicious"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "低危"
    MID = "中危"
    HIGH = "高危"
    CRITICAL = "紧急"


class RecommendedAction(str, Enum):
    """建议处置动作"""
    BLOCK = "block"
    MONITORING = "monitoring"
    ESCALATE = "escalate"
    NONE = "none"


class AgentStatus(str, Enum):
    """Agent 执行状态"""
    SUCCESS = "success"
    DEGRADED = "degraded"
    FAILED = "failed"


# ═══════════════════════ 容错 coercion ═══════════════════════

_VERDICT_MAP = {
    "malicious": Verdict.MALICIOUS, "bad": Verdict.MALICIOUS,
    "attack": Verdict.MALICIOUS, "evil": Verdict.MALICIOUS,
    "benign": Verdict.BENIGN, "normal": Verdict.BENIGN, "clean": Verdict.BENIGN,
    "false_positive": Verdict.BENIGN, "fp": Verdict.BENIGN, "legit": Verdict.BENIGN,
    "suspicious": Verdict.SUSPICIOUS, "suspected": Verdict.SUSPICIOUS,
    "unknown": Verdict.UNKNOWN, "unknown_": Verdict.UNKNOWN,
}

_RISK_MAP = {
    "低危": RiskLevel.LOW, "low": RiskLevel.LOW, "info": RiskLevel.LOW, "informational": RiskLevel.LOW,
    "中危": RiskLevel.MID, "medium": RiskLevel.MID, "mid": RiskLevel.MID,
    "高危": RiskLevel.HIGH, "high": RiskLevel.HIGH,
    "紧急": RiskLevel.CRITICAL, "critical": RiskLevel.CRITICAL, "urgent": RiskLevel.CRITICAL,
}

_ACTION_MAP = {
    "block": RecommendedAction.BLOCK, "ban": RecommendedAction.BLOCK, "封禁": RecommendedAction.BLOCK,
    "monitoring": RecommendedAction.MONITORING, "monitor": RecommendedAction.MONITORING,
    "观察": RecommendedAction.MONITORING, "watch": RecommendedAction.MONITORING,
    "escalate": RecommendedAction.ESCALATE, "升级": RecommendedAction.ESCALATE, "人工": RecommendedAction.ESCALATE,
    "none": RecommendedAction.NONE, "无": RecommendedAction.NONE, "无需": RecommendedAction.NONE,
    "no_action": RecommendedAction.NONE,
}


def _coerce_str_key(mapping: dict, v, default):
    """按字符串 key 匹配枚举，支持大小写/空白清理。"""
    if v is None:
        return default
    if isinstance(v, Enum):
        return v
    s = str(v).strip().lower()
    # 直接匹配
    if s in mapping:
        return mapping[s]
    # 去掉下划线/横线再匹配（false_positive → falsepositive）
    s2 = s.replace("_", "").replace("-", "").replace(" ", "")
    for k, e in mapping.items():
        if k.replace("_", "").replace("-", "").replace(" ", "") == s2:
            return e
    return default


def _coerce_float(v, default: float = 0.0, lo: float = 0.0, hi: float = 1.0) -> float:
    """
    容错转浮点数：
      - '0.85' / 0.85 → 0.85
      - '85%' / '85%' → 0.85（仅带 % 后缀的字符串按百分比折算）
      - 1.7 → clamp 到 1.0（数值不做百分比折算，只截断）
    """
    if v is None:
        return default
    pct = False
    try:
        if isinstance(v, str):
            s = v.strip()
            if s.endswith("%"):
                pct = True
                s = s[:-1].strip()
            val = float(s)
        else:
            val = float(v)
    except (ValueError, TypeError):
        return default
    if pct:
        val = val / 100.0
    return max(lo, min(hi, val))


# ═══════════════════════ Agent 级结果 ═══════════════════════

class IoCSet(BaseModel):
    """威胁指标集合"""
    model_config = ConfigDict(extra="ignore")

    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """
    结构化发现（证据包的核心单元）— 各专业 Agent 只输出"看到的事实 + 证据可靠度"。

    决策融合设计（Sense-Decide 分离）:
      - Agent 不直接裁决风险，只报告事实与证据可信度
      - 最终 verdict / risk_level 由 Decision Fusion 层统一裁决
    """
    model_config = ConfigDict(extra="ignore")

    type: str = "observation"          # 发现类型: malicious_behavior / intel_hit / benign_evidence ...
    fact: str = ""                      # 事实描述
    evidence_confidence: float = 0.5    # 该证据本身的可靠度 0~1（非风险判定）
    source: str = ""                    # 来源（工具/日志/情报源）
    related_technique: str = ""         # 关联 MITRE 技术（可选）
    detail: dict = Field(default_factory=dict)  # 扩展信息

    @field_validator("evidence_confidence", mode="before")
    @classmethod
    def _v_evidence_confidence(cls, v):
        return _coerce_float(v, default=0.5)


class AgentResult(BaseModel):
    """
    Agent 结构化输出（顶层 JSON）— 证据包形态。

    决策融合设计（Sense-Decide 分离）:
      - Agent 只输出 evidence/findings + evidence_confidence（感知层）
      - verdict / risk_level 保留为【兼容字段】：过渡期由 LLM 附带输出，
        最终唯一 final verdict 由 Decision Fusion 层裁决，不再以 Agent verdict 为准。
    """
    model_config = ConfigDict(extra="ignore")

    agent_id: str = ""
    agent_name: str = ""
    status: AgentStatus = AgentStatus.SUCCESS
    # ── 感知层输出（主要） ──
    findings: list[Finding] = Field(default_factory=list)
    evidence_confidence: float = 0.5    # 本 Agent 证据包总体可靠度（供融合加权）
    leaning: Verdict = Verdict.UNKNOWN  # 初步倾向（建议，非决策）—— fusion 的可选输入
    leaning_confidence: float = 0.5
    # ── 兼容字段（过渡期保留，三阶段迁移后由 fusion 唯一裁决） ──
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = 0.5
    risk_level: RiskLevel = RiskLevel.MID
    technique_ids: list[str] = Field(default_factory=list)
    key_evidence: list[str] = Field(default_factory=list)
    iocs: IoCSet = Field(default_factory=IoCSet)
    recommended_action: RecommendedAction = RecommendedAction.MONITORING
    missing_sources: list[str] = Field(default_factory=list)
    degraded: bool = False
    summary_text: str = ""
    # ── 结构化增强（v2.5：模板化报告支撑） ──
    risk_summary: str = ""            # 风险摘要（≤200 字，置于最前）
    detail: str = ""                  # 详细分析（长文本放此，供折叠展示）
    template_type: str = ""           # 事件模板分类（漏洞分析/攻击检测/安全配置/威胁情报/应急响应）
    template_schema: dict = Field(default_factory=dict)  # 模板化字段（不同分类不同结构）
    table: list = Field(default_factory=list)            # 表格化证据（第五步：使用表格）
    tool_calls: list[dict] = Field(default_factory=list)
    duration_ms: float = 0.0

    # ─── 容错 coercion ───
    @field_validator("verdict", mode="before")
    @classmethod
    def _v_verdict(cls, v):
        return _coerce_str_key(_VERDICT_MAP, v, Verdict.UNKNOWN)

    @field_validator("leaning", mode="before")
    @classmethod
    def _v_leaning(cls, v):
        return _coerce_str_key(_VERDICT_MAP, v, Verdict.UNKNOWN)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _v_risk(cls, v):
        return _coerce_str_key(_RISK_MAP, v, RiskLevel.MID)

    @field_validator("recommended_action", mode="before")
    @classmethod
    def _v_action(cls, v):
        return _coerce_str_key(_ACTION_MAP, v, RecommendedAction.MONITORING)

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        return _coerce_float(v, default=0.5)

    @field_validator("evidence_confidence", mode="before")
    @classmethod
    def _v_evidence_confidence(cls, v):
        return _coerce_float(v, default=0.5)

    @field_validator("leaning_confidence", mode="before")
    @classmethod
    def _v_leaning_confidence(cls, v):
        return _coerce_float(v, default=0.5)

    @field_validator("status", mode="before")
    @classmethod
    def _v_status(cls, v):
        return _coerce_str_key(
            {"success": AgentStatus.SUCCESS, "degraded": AgentStatus.DEGRADED,
             "failed": AgentStatus.FAILED, "error": AgentStatus.FAILED},
            v, AgentStatus.SUCCESS,
        )

    @field_validator("iocs", mode="before")
    @classmethod
    def _v_iocs(cls, v):
        if isinstance(v, IoCSet):
            return v
        if isinstance(v, dict):
            try:
                return IoCSet.model_validate(v)
            except Exception:
                return IoCSet()
        return IoCSet()

    @field_validator("findings", mode="before")
    @classmethod
    def _v_findings(cls, v):
        if not isinstance(v, (list, tuple)):
            return []
        out = []
        for item in v:
            if isinstance(item, Finding):
                out.append(item)
            elif isinstance(item, dict):
                try:
                    out.append(Finding.model_validate(item))
                except Exception:
                    continue
        return out

    # ── 便捷：evidence_confidence 未显式给出时，从 findings 均值推断 ──
    @model_validator(mode="after")
    def _infer_evidence_confidence(self):
        if self.evidence_confidence == 0.5 and self.findings:
            vals = [f.evidence_confidence for f in self.findings if f.evidence_confidence]
            if vals:
                self.evidence_confidence = round(sum(vals) / len(vals), 4)
        # 兼容：leaning 未给时，用 verdict 兜底（过渡期）
        if self.leaning == Verdict.UNKNOWN and self.verdict != Verdict.UNKNOWN:
            self.leaning = self.verdict
        if self.leaning_confidence == 0.5 and self.confidence != 0.5:
            self.leaning_confidence = self.confidence
        return self


def repair_json_object(text: str) -> Optional[dict]:
    """
    从 LLM 返回文本中尽力提取/修复 JSON 对象。

    处理:
      - markdown 围栏 ```json ... ```
      - 前后杂散文本（截取首个 { 到末个 }）
      - 尾逗号、单引号等轻量修复

    失败返回 None（由调用方降级）。
    """
    if not isinstance(text, str) or not text.strip():
        return None
    t = text.strip()
    # 剥 markdown 围栏
    fence = re.search(r'```(?:json)?\s*(.*?)```', t, re.DOTALL | re.IGNORECASE)
    if fence:
        t = fence.group(1).strip()
    # 截取 { ... }
    start = t.find("{")
    end = t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = t[start:end + 1]

    def _parse(s: str):
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

    parsed = _parse(candidate)
    if parsed:
        return parsed

    # 轻量修复：去尾逗号 / 去注释行 / 单引号→双引号
    fixed = re.sub(r',\s*([}\]])', r'\1', candidate)
    fixed = re.sub(r'^\s*//.*$', '', fixed, flags=re.MULTILINE)
    fixed = re.sub(r'^\s*#.*$', '', fixed, flags=re.MULTILINE)
    parsed = _parse(fixed)
    if parsed:
        return parsed
    fixed2 = re.sub(r"(?<!\\)'", '"', fixed)
    parsed = _parse(fixed2)
    if parsed:
        return parsed
    return None


def parse_agent_result(data: Optional[dict]) -> dict:
    """
    将 LLM / 文本解析出的 dict 规范化为 AgentResult 结构（容错）。

    校验失败时尽量保留已识别字段，其余用默认值兜底 —— 结构化永不阻断主链路。
    """
    if not isinstance(data, dict):
        data = {}
    try:
        return AgentResult.model_validate(data).model_dump(mode="json")
    except Exception:
        result = AgentResult().model_dump(mode="json")
        for k, v in data.items():
            if k in result and v is not None:
                result[k] = v
        # 再对 enum 字段做一次容错
        try:
            return AgentResult.model_validate(result).model_dump(mode="json")
        except Exception:
            return result


# ═══════════════════════ 编排器最终结果 ═══════════════════════

class FinalVerdict(BaseModel):
    """最终综合判定（由确定性聚合产出，LLM 不得改写）"""
    model_config = ConfigDict(extra="ignore")

    verdict: Verdict = Verdict.UNKNOWN
    risk_probability: float = 0.0      # 风险概率（v2.6：与置信度分离）
    confidence: float = 0.0            # 置信度（判断的确定性）
    risk_level: RiskLevel = RiskLevel.LOW
    recommended_action: RecommendedAction = RecommendedAction.MONITORING

    @field_validator("verdict", mode="before")
    @classmethod
    def _v_verdict(cls, v):
        return _coerce_str_key(_VERDICT_MAP, v, Verdict.UNKNOWN)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _v_risk(cls, v):
        return _coerce_str_key(_RISK_MAP, v, RiskLevel.LOW)

    @field_validator("recommended_action", mode="before")
    @classmethod
    def _v_action(cls, v):
        return _coerce_str_key(_ACTION_MAP, v, RecommendedAction.MONITORING)

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        return _coerce_float(v, default=0.0)


class FinalSummary(BaseModel):
    """
    LLM 在最终阶段只产出的解释性总结（JSON）。

    置信度 / 风险评分等数值由确定性计算产出，LLM 不得出现在此模型中。
    """
    model_config = ConfigDict(extra="ignore")

    summary_text: str = ""
    suggested_action: str = ""
    needs_human_reason: str = ""


class SummaryResult(BaseModel):
    """
    Summary Agent（报告生成员）的结构化输出（v2.5）。

    输入：所有专业 Agent 的结构化结果 + 用户问题
    输出：模板化最终综合报告（长文本在 detail，短摘要在前，使用表格）
    """
    model_config = ConfigDict(extra="ignore")

    risk_summary: str = ""               # 风险摘要（≤200 字，最前）
    summary_text: str = ""               # 一句话总述
    core_findings: list[str] = Field(default_factory=list)   # 核心发现（2-5 条）
    recommended_actions: list[str] = Field(default_factory=list)  # 推荐动作（按优先级）
    detail: str = ""                     # 详细分析（长文本，供折叠）
    template_type: str = ""              # 事件模板分类
    table: list = Field(default_factory=list)   # 表格化证据
    suggested_action: str = ""           # 建议动作（block/monitoring/escalate/none）
    needs_human_reason: str = ""         # 需人工介入原因

    # ─── 容错：LLM 可能输出 dict（priority/action）而非纯字符串 ───
    @field_validator("core_findings", mode="before")
    @classmethod
    def _v_core_findings(cls, v):
        return _norm_str_list(v)

    @field_validator("recommended_actions", mode="before")
    @classmethod
    def _v_recommended_actions(cls, v):
        return _norm_str_list(v)

    @field_validator("table", mode="before")
    @classmethod
    def _v_table(cls, v):
        if not isinstance(v, (list, tuple)):
            return []
        out = []
        for item in v:
            if isinstance(item, dict) and item:
                out.append(item)
            elif isinstance(item, str):
                out.append({"内容": item})
        return out


def _norm_str_list(v) -> list:
    """把 list[dict|str] 规范化为 list[str]（LLM 可能输出对象数组）。"""
    if not isinstance(v, (list, tuple)):
        return []
    out = []
    for item in v:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict) and item:
            # 常见形态: {"priority": "P0", "action": "xxx"} 或 {"name": "xxx", "desc": "yyy"}
            if "action" in item or "desc" in item or "description" in item:
                pri = item.get("priority", "")
                body = item.get("action") or item.get("desc") or item.get("description") or ""
                out.append(f"[{pri}] {body}" if pri else str(body))
            else:
                out.append(" | ".join(f"{k}: {v}" for k, v in item.items()))
    return out


def parse_summary_result(data: Optional[dict]) -> dict:
    """规范化 SummaryResult（容错）。"""
    if not isinstance(data, dict):
        data = {}
    try:
        return SummaryResult.model_validate(data).model_dump(mode="json")
    except Exception:
        result = SummaryResult().model_dump(mode="json")
        for k, v in data.items():
            if k in result and v is not None:
                result[k] = v
        try:
            return SummaryResult.model_validate(result).model_dump(mode="json")
        except Exception:
            return result


# ═══════════════════════ 事件分类（Classifier Agent, v2.5） ═══════════════════════

# 事件模板分类（第六步）：不同分类 → 不同输出模板
# v2.6 变更：增加"安全知识"意图（Intent Classifier 层），用于识别纯知识性问题
#（如"什么是SQLite"），此类问题不是安全事件，风险评分给 50 分中性基线。
TEMPLATE_TYPES = ["安全知识", "漏洞分析", "攻击检测", "安全配置", "威胁情报", "应急响应"]

# 各意图的风险评分基线（v2.6：意图识别后先定基线，再被 Agent 证据修正）
INTENT_RISK_BASELINE = {
    "安全知识": 50,      # 纯知识咨询：中性基线（非事件，非零风险，居中）
    "漏洞分析": 60,      # 漏洞相关：默认中危基线
    "攻击检测": 70,      # 攻击行为：默认高危基线
    "安全配置": 50,      # 配置加固：中性基线
    "威胁情报": 60,      # 情报分析：中危基线
    "应急响应": 80,      # 应急处置：默认高危基线
}

# 关键词预判（Classifier 兜底 + 引导 LLM 判断）
TEMPLATE_KEYWORDS = {
    "安全知识": ["什么是", "什么叫做", "是什么", "介绍", "解释", "科普", "原理", "教程", "学习", "基础知识", "简介", "有哪些", "sqlite是什么", "tcp是什么", "udp是什么", "了解"],
    "漏洞分析": ["cve", "漏洞", "补丁", "exp", "exploit", "poc", "漏洞扫描", "rce", "远程代码执行", "regreSSHion", "openssh"],
    "攻击检测": ["攻击", "暴力破解", "爆破", "sql注入", "xss", "webshell", "后门", "木马", "ddos", "cc攻击", "钓鱼", "入侵", "提权", "横向移动", "勒索", "告警", "入侵检测", "感染", "恶意行为"],
    "安全配置": ["加固", "配置", "策略", "基线", "防火墙规则", "权限", "弱口令", "密码策略", "端口开放", "关闭", "启用", "等保", "合规", "安全配置", "优化", "最佳实践", "建议"],
    "威胁情报": ["情报", "ioc", "恶意ip", "恶意域名", "apt", "威胁组织", "溯源", "关联", "威胁", "情报源", "blacklist", "黑名单", "ip信誉"],
    "应急响应": ["应急", "处置", "封禁", "隔离", "响应", "止血", "恢复", "清除", "排查", "事件响应", "forensic", "取证"],
}


class ClassifierResult(BaseModel):
    """Classifier Agent（事件分类器 / 意图识别器）的结构化输出（v2.6）。"""
    model_config = ConfigDict(extra="ignore")

    template_type: str = "安全知识"    # 安全知识|漏洞分析|攻击检测|安全配置|威胁情报|应急响应
    category_reason: str = ""          # 分类依据
    priority: str = "中"               # 优先级 高/中/低
    risk_baseline: int = 50            # 意图风险评分基线（v2.6：由意图决定）
    is_knowledge_query: bool = False   # 是否为纯知识性问题（v2.6）
    answer_mode: str = "analysis"      # free | rag | analysis（v2.8）

    @field_validator("template_type", mode="before")
    @classmethod
    def _v_template(cls, v):
        s = str(v or "").strip()
        for t in TEMPLATE_TYPES:
            if t in s or s in t:
                return t
        # 英文/别名映射
        alias = {
            "knowledge": "安全知识", "learn": "安全知识", "whatis": "安全知识", "intro": "安全知识",
            "vuln": "漏洞分析", "vulnerability": "漏洞分析", "cve": "漏洞分析",
            "attack": "攻击检测", "detection": "攻击检测", "intrusion": "攻击检测",
            "config": "安全配置", "hardening": "安全配置", "security_config": "安全配置",
            "intel": "威胁情报", "threat_intel": "威胁情报", "threat": "威胁情报",
            "response": "应急响应", "incident": "应急响应", "responder": "应急响应",
        }
        for k, t in alias.items():
            if k in s.lower():
                return t
        return "安全知识"


def classify_template(text: str) -> str:
    """关键词预判意图分类（Classifier Agent 的兜底/引导）。"""
    text_l = (text or "").lower()
    scores = {t: 0 for t in TEMPLATE_TYPES}
    for t, kws in TEMPLATE_KEYWORDS.items():
        for kw in kws:
            if kw in text_l or kw in text:
                scores[t] += 1
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "安全知识"


_SECURITY_KNOWLEDGE_TERMS = (
    "sql注入", "xss", "webshell", "勒索", "恶意软件", "攻击方式", "攻击技术",
    "ddos", "横向移动", "提权", "等保", "合规", "mitre", "attack", "cve-",
    "漏洞", "应急处置", "安全加固", "威胁情报", "入侵检测", "零信任",
)
_ANSWER_MODE_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ANSWER_MODE_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![\w.-])"
)

# 面向用户的展示模式。answer_mode 是内部路由（free/rag/analysis），
# response_mode 是前端展示契约，二者刻意分离，避免把知识检索误渲染成事件报告。
RESPONSE_MODES = {
    "plain_text",             # 概念、定义、原理、普通问答
    "ioc_card",               # IP/域名/哈希等 IOC 查询
    "investigation_report",   # 告警、攻击、漏洞和综合研判
    "incident_report",        # 应急响应和处置任务
    "checklist",              # 配置、加固、合规和操作清单
}
_KNOWLEDGE_QUESTION_MARKERS = (
    "什么是", "什么叫", "是什么", "概念", "含义", "原理", "介绍",
    "解释", "科普", "简介", "怎么理解", "如何理解", "区别是什么",
)
_ACTION_QUERY_MARKERS = (
    "检测", "分析", "查询", "告警", "日志", "排查", "封禁", "处置",
    "修复", "加固", "防御", "防止", "是否恶意", "怎么做", "如何做",
)


def is_plain_knowledge_query(text: str, template_type: str = "", answer_mode: str = "") -> bool:
    """判断是否应以无卡片的纯文本回答。

    这条规则覆盖 LLM 分类器偶尔把“什么是 SQL 注入”标成攻击检测的情况，
    但会避开“如何防御/检测/分析”这类需要行动建议的安全任务。
    """
    query = (text or "").strip().lower()
    if not query:
        return False
    marker_hit = any(marker in query for marker in _KNOWLEDGE_QUESTION_MARKERS)
    if not marker_hit:
        return (
            template_type == "安全知识"
            and answer_mode in {"free", "rag"}
            and not any(marker in query for marker in _ACTION_QUERY_MARKERS)
        )
    return not any(marker in query for marker in _ACTION_QUERY_MARKERS)


def select_response_mode(
    template_type: str,
    text: str = "",
    *,
    answer_mode: str = "",
    needs_human: bool = False,
) -> str:
    """根据意图和问题场景选择前端展示契约。"""
    if is_plain_knowledge_query(text, template_type, answer_mode):
        return "plain_text"
    if template_type == "威胁情报":
        return "ioc_card"
    # 需要人工复核是状态，不等同于应急处置场景；例如漏洞报告证据不足时
    # 仍应保持“漏洞分析”展示，避免把所有异常都命名为应急报告。
    if template_type == "应急响应":
        return "incident_report"
    if template_type == "安全配置":
        return "checklist"
    return "investigation_report"


def predict_answer_mode(template_type: str, text: str) -> str:
    """确定性预判回答路径，避免把 IOC 查询误当闲聊或知识问答。"""
    if template_type != "安全知识":
        return "analysis"

    query = (text or "").strip()
    query_lower = query.lower()
    if _ANSWER_MODE_IP_RE.search(query) or _ANSWER_MODE_DOMAIN_RE.search(query):
        return "analysis"
    if any(term in query_lower for term in _SECURITY_KNOWLEDGE_TERMS):
        return "rag"
    return "free"


def get_intent_risk_baseline(template_type: str) -> int:
    """按意图类型返回风险评分基线（v2.6：风险评分和置信度分离后，基线先于证据）。"""
    return INTENT_RISK_BASELINE.get(template_type, 50)


def parse_classifier_result(data: Optional[dict]) -> dict:
    """规范化 ClassifierResult（容错）。"""
    if not isinstance(data, dict):
        data = {}
    try:
        return ClassifierResult.model_validate(data).model_dump(mode="json")
    except Exception:
        result = ClassifierResult().model_dump(mode="json")
        for k, v in data.items():
            if k in result and v is not None:
                result[k] = v
        try:
            return ClassifierResult.model_validate(result).model_dump(mode="json")
        except Exception:
            return result


class FinalResult(BaseModel):
    """
    编排器最终结构化结果（顶层 JSON）

    对应 `true_react_complete` / `true_react_max_rounds` / 超时熔断事件
    新增的 `structured_result` 字段。
    """
    model_config = ConfigDict(extra="ignore")

    status: str = "completed"          # completed | max_rounds | timeout | error
    response_mode: str = "investigation_report"  # 前端展示契约（不等同于 answer_mode）
    conversation_id: str = ""
    rounds: int = 0
    total_tool_calls: int = 0
    total_agent_calls: int = 0
    needs_human: bool = False
    summary_text: str = ""
    verdict: FinalVerdict = Field(default_factory=FinalVerdict)
    confidence_aggregate: dict = Field(default_factory=dict)
    risk_scorecard: dict = Field(default_factory=dict)
    agent_results: list[AgentResult] = Field(default_factory=list)
    tool_call_history: list = Field(default_factory=list)  # engine.history.to_dict() 为 list
    score: int = 0                      # = risk_scorecard.risk_score
    # ── Decision Fusion（v2.4） ──
    fusion_result: dict = Field(default_factory=dict)   # 融合引擎完整输出（含 belief/conflicts）
    decision_path: list = Field(default_factory=list)   # 决策依据链（前端渲染）
    # ── Summary Agent 模板化报告（v2.5） ──
    summary_report: dict = Field(default_factory=dict)  # SummaryResult 完整内容（risk_summary/core_findings/...）
    # ── Evidence Chain 证据链（v2.6） ──
    # 回答"为什么 / 依据是什么 / 调用了什么工具"：
    # 每项 {agent_id, agent_name, evidence(结论), basis(依据), tools([工具名]), confidence}
    evidence_chain: list = Field(default_factory=list)

    @field_validator("tool_call_history", mode="before")
    @classmethod
    def _v_tool_history(cls, v):
        if isinstance(v, dict):
            return [v]
        if isinstance(v, (list, tuple)):
            return list(v)
        return []

    @field_validator("agent_results", mode="before")
    @classmethod
    def _v_agent_results(cls, v):
        if not isinstance(v, (list, tuple)):
            return []
        out = []
        for item in v:
            try:
                out.append(AgentResult.model_validate(item))
            except Exception:
                out.append(AgentResult())
        return out

    @field_validator("decision_path", mode="before")
    @classmethod
    def _v_decision_path(cls, v):
        if isinstance(v, (list, tuple)):
            return list(v)
        if isinstance(v, dict):
            return [v]
        return []

    @field_validator("fusion_result", mode="before")
    @classmethod
    def _v_fusion_result(cls, v):
        if isinstance(v, dict):
            return v
        return {}

    @field_validator("verdict", mode="before")
    @classmethod
    def _v_verdict(cls, v):
        if isinstance(v, FinalVerdict):
            return v
        if isinstance(v, dict):
            try:
                return FinalVerdict.model_validate(v)
            except Exception:
                return FinalVerdict()
        return FinalVerdict()


def parse_final_summary(data: Optional[dict]) -> FinalSummary:
    """容错解析 LLM 最终总结。"""
    if not isinstance(data, dict):
        return FinalSummary()
    try:
        return FinalSummary.model_validate(data)
    except Exception:
        return FinalSummary()


def build_final_result(**kwargs) -> FinalResult:
    """
    便捷构建 FinalResult，并保证 score 与 risk_scorecard 一致。

    调用方传入字段与 FinalResult 一致；score 若未显式给出，
    自动取 risk_scorecard.risk_score。
    """
    fr = FinalResult.model_validate(kwargs)
    # 决策：score 采用 risk_score，不依赖 confidence
    if kwargs.get("score") is None and fr.risk_scorecard:
        fr.score = int(fr.risk_scorecard.get("risk_score", 0) or 0)
    return fr


# ═══════════════════════ 确定性文本渲染器 ═══════════════════════
# 渲染器与结构化结果共用同一数据源 —— 文本是 JSON 的"视图"，不是独立生成物。

_VERDICT_LABEL = {
    Verdict.MALICIOUS.value: "恶意",
    Verdict.BENIGN.value: "正常",
    Verdict.SUSPICIOUS.value: "可疑",
    Verdict.UNKNOWN.value: "无法判定",
}


def _norm(value) -> Optional[dict]:
    """把 AgentResult / FinalResult / dict 统一成 JSON-safe dict。"""
    if value is None:
        return None
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    return None


def result_to_text(result: Union[dict, AgentResult]) -> str:
    """把 AgentResult JSON 确定性渲染为人类可读 markdown。"""
    d = _norm(result) or {}
    lines = []

    # 摘要（LLM 叙事）
    summary = (d.get("summary_text") or "").strip()
    if summary:
        lines.append(summary.strip())
        lines.append("")

    # 风险摘要（v2.5：≤200 字，置于最前）
    risk_summary = (d.get("risk_summary") or "").strip()
    if risk_summary:
        lines.append(f"> **风险摘要**: {risk_summary}")
        lines.append("")

    # 表格化证据（v2.5）
    table = d.get("table") or []
    if table and isinstance(table, list):
        lines.append("")
        lines.append("**明细**")
        rows = [t for t in table if isinstance(t, dict) and t]
        if rows:
            headers = []
            for r in rows:
                for k in r.keys():
                    if k not in headers:
                        headers.append(k)
            lines.append("| " + " | ".join(str(h) for h in headers) + " |")
            lines.append("|" + "---|" * len(headers))
            for r in rows:
                lines.append("| " + " | ".join(str(r.get(h, "")) for h in headers) + " |")

    # 判定
    verdict = d.get("verdict", "unknown")
    conf = d.get("confidence", 0.5)
    risk = d.get("risk_level", "中危")
    action = d.get("recommended_action", "monitoring")
    label = _VERDICT_LABEL.get(verdict, verdict)
    action_label = {
        "block": "封禁", "monitoring": "持续监控", "escalate": "升级人工", "none": "无需处置",
    }.get(action, action)
    lines.append("---")
    lines.append("### 分析结论（结构化）")
    lines.append(f"- **判定**: {label}（{verdict}）")
    lines.append(f"- **置信度**: {conf:.0%}" if isinstance(conf, float) else f"- **置信度**: {conf}")
    lines.append(f"- **风险等级**: {risk}")
    lines.append(f"- **建议动作**: {action_label}")

    # 降级/失败标记
    if d.get("degraded"):
        lines.append("- 本 Agent 曾降级重试")
    if d.get("status") == AgentStatus.FAILED.value:
        lines.append("- ❌ 本 Agent 执行失败")

    # 证据
    evidence = d.get("key_evidence") or []
    if evidence:
        lines.append("")
        lines.append("**关键证据**:")
        for ev in evidence:
            lines.append(f"- {ev}")

    # 技术映射
    techs = d.get("technique_ids") or []
    if techs:
        lines.append("")
        lines.append(f"**MITRE ATT&CK**: {', '.join(techs)}")

    # IOC
    iocs = d.get("iocs") or {}
    if isinstance(iocs, dict) and any(iocs.get(k) for k in ("ips", "domains", "hashes")):
        lines.append("")
        lines.append("**威胁指标 (IOC)**:")
        for k, label_k in (("ips", "IP"), ("domains", "域名"), ("hashes", "哈希")):
            vals = iocs.get(k) or []
            if vals:
                lines.append(f"- {label_k}: {', '.join(str(v) for v in vals)}")

    # 情报缺失
    missing = d.get("missing_sources") or []
    if missing:
        lines.append("")
        lines.append(f"情报源缺失: {', '.join(str(m) for m in missing)}（缺失按未知处理，不视为无恶意）")

    # 详细分析（v2.5：长文本放 detail，供折叠展示）
    detail = (d.get("detail") or "").strip()
    if detail and detail not in (summary, risk_summary):
        lines.append("")
        lines.append("### 详细分析")
        lines.append(detail)

    return "\n".join(lines).strip()


def _fmt_conf(c) -> str:
    """格式置信度，None 显示占位。"""
    if c is None:
        return "无结构化裁决"
    try:
        return f"{float(c):.0%}"
    except (TypeError, ValueError):
        return str(c)


def final_to_markdown(final: Union[dict, FinalResult]) -> str:
    """
    把 FinalResult JSON 确定性渲染为完整可读报告（markdown）。

    组成:
      1. 状态头（status / needs_human / 耗时）
      2. LLM 叙事 summary_text（若存在）
      3. 确定性综合判定（verdict / confidence / risk_level / action / score）
      4. 确定性置信度聚合明细（可复现）
      5. 可解释风险评分卡（逐维度）
      6. 各 Agent 结构化结论摘要
    """
    d = _norm(final) or {}
    lines = []

    status = d.get("status", "completed")
    status_label = {
        "completed": "分析完成", "max_rounds": "达到最大轮次",
        "timeout": "分析超时熔断", "error": "分析异常",
    }.get(status, status)
    lines.append(f"## 综合分析结果")
    lines.append(f"**状态**: {status_label}")
    if d.get("needs_human"):
        lines.append("> **需人工介入**")
    if d.get("rounds") is not None:
        lines.append(f"**分析轮次**: {d.get('rounds')} 轮 | "
                     f"**工具调用**: {d.get('total_tool_calls', 0)} | "
                     f"**Agent 调用**: {d.get('total_agent_calls', 0)}")
    lines.append("")

    # LLM 叙事
    summary = (d.get("summary_text") or "").strip()
    if summary:
        lines.append(summary.strip())
        lines.append("")

    # 确定性综合判定
    vd = d.get("verdict") or {}
    if isinstance(vd, dict):
        verdict = vd.get("verdict", "unknown")
        conf = vd.get("confidence", 0.0)
        risk = vd.get("risk_level", "低危")
        action = vd.get("recommended_action", "monitoring")
        action_label = {
            "block": "封禁", "monitoring": "持续监控", "escalate": "升级人工", "none": "无需处置",
        }.get(action, action)
        label = _VERDICT_LABEL.get(verdict, verdict)
        lines.append("---")
        lines.append("### 最终判定（确定性聚合，可复现）")
        lines.append(f"- **判定**: {label}（{verdict}）")
        lines.append(f"- **置信度**: {_fmt_conf(conf)}")
        lines.append(f"- **风险等级**: {risk}")
        lines.append(f"- **建议动作**: {action_label}")
        lines.append(f"- **风险评分**: {d.get('score', 0)}")

    # 确定性置信度聚合明细
    # 修复：融合裁决存在时（fusion_result 非空），旧加权聚合仅为参考，
    # 显式标注"非最终裁决"，避免与最终判定中的融合置信度并列打架
    agg = d.get("confidence_aggregate") or {}
    has_fusion = bool(d.get("fusion_result"))
    if agg:
        lines.append("")
        lines.append("### 置信度聚合明细" + ("（参考 · 非最终裁决）" if has_fusion else ""))
        lines.append(f"- **综合置信度**: {_fmt_conf(agg.get('confidence'))}（{agg.get('verdict', 'unknown')}）")
        lines.append(f"- **需人工介入**: {'是' if agg.get('needs_human') else '否'}")
        for det in (agg.get("details") or []):
            tag = ""
            if det.get("degraded"):
                tag = " 已降级"
            if det.get("failed"):
                tag = " ❌失败"
            lines.append(f"- {det.get('agent_id')}: 权重 {_fmt_conf(det.get('weight'))} × "
                         f"置信度 {_fmt_conf(det.get('confidence'))}{tag}")
        if agg.get("coverage") is not None:
            lines.append(f"- 情报覆盖度: {_fmt_conf(agg.get('coverage'))}（缺失源按'未知'处理）")

    # 风险评分卡
    sc = d.get("risk_scorecard") or {}
    if sc:
        lines.append("")
        lines.append("### 可解释风险评分")
        lines.append(f"- **最终风险评分**: {sc.get('risk_score', 0)}（{sc.get('risk_level', '低危')}）")
        lines.append(f"- **需人工介入**: {'是' if sc.get('needs_human') else '否'}")
        for dim in (sc.get("dimensions") or []):
            sign = "+" if dim.get("delta", 0) >= 0 else ""
            lines.append(f"- {dim.get('name')}: {sign}{dim.get('delta')}（{dim.get('reason')}）")
        if sc.get("summarized"):
            lines.append(f"- 汇总: {sc.get('summarized')}")
        if sc.get("rules_hit"):
            lines.append(f"- 命中规则: {', '.join(str(r) for r in sc.get('rules_hit'))}")

    # 决策依据链（Decision Fusion, v2.4）
    decision_path = d.get("decision_path") or []
    if decision_path:
        lines.append("")
        lines.append("### 决策依据链（Decision Fusion）")
        for step in decision_path:
            if isinstance(step, dict):
                tag = step.get("tag", "")
                tag_mark = {
                    "evidence": "", "conflict": "", "fusion": "🧮 ", "decision": "🔖 ",
                }.get(tag, "")
                lines.append(f"{tag_mark}{step.get('step', '')}. {step.get('desc', '')}")
            else:
                lines.append(f"- {step}")
    # 融合冲突
    fr = d.get("fusion_result") or {}
    conflicts = fr.get("conflicts") or []
    if conflicts:
        lines.append("")
        lines.append("### 证据冲突")
        for c in conflicts[:5]:
            lines.append(f"- {c.get('between')}: 冲突系数 {_fmt_conf(c.get('coefficient'))}"
                         f"（{c.get('resolution', '')}）")

    # 各 Agent 结论摘要
    agents = d.get("agent_results") or []
    if agents:
        lines.append("")
        lines.append("### 各 Agent 结论")
        for a in agents:
            if isinstance(a, BaseModel):
                a = a.model_dump()
            if not isinstance(a, dict):
                continue
            name = a.get("agent_name") or a.get("agent_id") or "agent"
            v = a.get("verdict", "unknown")
            c = a.get("confidence")
            risk = a.get("risk_level", "")
            degraded_tag = " 已降级" if a.get("degraded") else ""
            fail_tag = " ❌失败" if a.get("status") == "failed" else ""
            lines.append(f"- **{name}**: {v}（置信度 {_fmt_conf(c)}，风险 {risk}）{degraded_tag}{fail_tag}")

    return "\n".join(lines).strip()


# ═══════════════════════ Decision Fusion 决策融合模型 ═══════════════════════
# Sense-Decide 分离：
#   各专业 Agent（感知层）只输出 EvidencePackage（findings + evidence_confidence）
#   Decision Fusion（决策层）统一裁决 → FusionResult（唯一 final verdict）
#   Fusion 引擎为可替换模块（接口见 backend/decision_fusion/base.py）


class EvidencePackage(BaseModel):
    """
    标准化的证据包 —— Fusion 引擎的输入单元。

    由 AgentResult 转换而来；也可能由工具结果 / 历史信誉等构造。
    """
    model_config = ConfigDict(extra="ignore")

    agent_id: str = ""
    agent_name: str = ""
    status: str = "success"             # success | degraded | failed
    findings: list[Finding] = Field(default_factory=list)
    evidence_confidence: float = 0.5
    leaning: Verdict = Verdict.UNKNOWN  # 初步倾向（建议，非决策）
    leaning_confidence: float = 0.5
    coverage: Optional[float] = None    # 情报覆盖度
    missing_sources: list[str] = Field(default_factory=list)
    iocs: IoCSet = Field(default_factory=IoCSet)
    technique_ids: list[str] = Field(default_factory=list)
    degraded: bool = False
    failed: bool = False

    @field_validator("leaning", mode="before")
    @classmethod
    def _v_leaning(cls, v):
        return _coerce_str_key(_VERDICT_MAP, v, Verdict.UNKNOWN)

    @field_validator("evidence_confidence", "leaning_confidence", mode="before")
    @classmethod
    def _v_conf(cls, v):
        return _coerce_float(v, default=0.5)

    @field_validator("findings", mode="before")
    @classmethod
    def _v_findings(cls, v):
        if not isinstance(v, (list, tuple)):
            return []
        out = []
        for item in v:
            if isinstance(item, Finding):
                out.append(item)
            elif isinstance(item, dict):
                try:
                    out.append(Finding.model_validate(item))
                except Exception:
                    continue
        return out

    @field_validator("coverage", mode="before")
    @classmethod
    def _v_coverage(cls, v):
        if v is None:
            return None
        return _coerce_float(v, default=0.0)

    @field_validator("iocs", mode="before")
    @classmethod
    def _v_iocs(cls, v):
        if isinstance(v, IoCSet):
            return v
        if isinstance(v, dict):
            try:
                return IoCSet.model_validate(v)
            except Exception:
                return IoCSet()
        return IoCSet()


def build_evidence_package(data: Optional[dict]) -> Optional[EvidencePackage]:
    """从 AgentResult dict 容错构造 EvidencePackage；无效返回 None。"""
    if not isinstance(data, dict):
        return None
    try:
        return EvidencePackage.model_validate(data)
    except Exception:
        return None


class EvidenceMass(BaseModel):
    """单个证据包在融合后的信念质量（可审计）"""
    model_config = ConfigDict(extra="ignore")

    agent_id: str = ""
    agent_name: str = ""
    weight: float = 0.0                 # 归一化权重（固定权重 × 证据可靠度 × 覆盖惩罚）
    belief: float = 0.0                # 支持恶意/良性命题的信念
    plausibility: float = 0.0          # 似真度（信念 + 未知 mass）
    leaning: str = "unknown"
    degraded: bool = False
    failed: bool = False


class FusionConflict(BaseModel):
    """跨 Agent 冲突记录"""
    model_config = ConfigDict(extra="ignore")

    between: str = ""
    coefficient: float = 0.0           # Dempster 冲突系数 K（0~1）
    leaning_a: str = ""
    leaning_b: str = ""
    resolution: str = ""


class FusionVerdict(BaseModel):
    """融合裁决（唯一 final verdict，来自确定性融合）

    v2.6 变更：风险概率（risk_probability）与置信度（confidence）分离
      - risk_probability: 事件为恶意的概率（0~1），基于 belief_malicious（可能性）
      - confidence:       判断的确定性（0~1），基于 belief 的集中度（有多少证据支持这个判断）
      二者含义不同：概率高 ≠ 确定性高（证据少时概率可能居中但确定性低）。
    """
    model_config = ConfigDict(extra="ignore")

    verdict: Verdict = Verdict.UNKNOWN
    belief_malicious: float = 0.0
    belief_benign: float = 0.0
    belief_unknown: float = 1.0
    risk_probability: float = 0.0      # 风险概率（事件为恶意的可能性，0~1）
    confidence: float = 0.0            # 置信度（判断的确定性，0~1）
    risk_level: RiskLevel = RiskLevel.LOW
    recommended_action: RecommendedAction = RecommendedAction.MONITORING
    needs_human: bool = False

    @field_validator("verdict", mode="before")
    @classmethod
    def _v_verdict(cls, v):
        return _coerce_str_key(_VERDICT_MAP, v, Verdict.UNKNOWN)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _v_risk(cls, v):
        return _coerce_str_key(_RISK_MAP, v, RiskLevel.LOW)

    @field_validator("recommended_action", mode="before")
    @classmethod
    def _v_action(cls, v):
        return _coerce_str_key(_ACTION_MAP, v, RecommendedAction.MONITORING)


class FusionResult(BaseModel):
    """
    Decision Fusion 引擎的统一输出 —— 唯一的最终裁决来源。

    语义:
      - verdict/confidence/risk_level/risk_score 全部来自确定性融合（L1+L2）
      - LLM（L3）只填 summary_text / decision_path 文字，不得改写数值
      - engine 字段标识使用的引擎（可替换模块，便于审计与切换）
    """
    model_config = ConfigDict(extra="ignore")

    engine: str = "dempster_shafer"    # 使用的融合引擎
    method: str = "dempster_shafer"
    status: str = "completed"          # completed | degraded | error
    verdict: FusionVerdict = Field(default_factory=FusionVerdict)
    conflict_coefficient: float = 0.0  # 全局冲突系数 K
    conflicts: list[FusionConflict] = Field(default_factory=list)
    evidence_masses: list[EvidenceMass] = Field(default_factory=list)
    decision_path: list[dict] = Field(default_factory=list)  # 决策依据链（前端渲染）
    risk_score: int = 0
    risk_scorecard: dict = Field(default_factory=dict)
    summary_text: str = ""
    agent_count: int = 0
    evidence_count: int = 0

    @field_validator("verdict", mode="before")
    @classmethod
    def _v_verdict(cls, v):
        if isinstance(v, FusionVerdict):
            return v
        if isinstance(v, dict):
            try:
                return FusionVerdict.model_validate(v)
            except Exception:
                return FusionVerdict()
        return FusionVerdict()

    @field_validator("conflicts", mode="before")
    @classmethod
    def _v_conflicts(cls, v):
        if not isinstance(v, (list, tuple)):
            return []
        out = []
        for item in v:
            if isinstance(item, FusionConflict):
                out.append(item)
            elif isinstance(item, dict):
                try:
                    out.append(FusionConflict.model_validate(item))
                except Exception:
                    continue
        return out

    @field_validator("evidence_masses", mode="before")
    @classmethod
    def _v_masses(cls, v):
        if not isinstance(v, (list, tuple)):
            return []
        out = []
        for item in v:
            if isinstance(item, EvidenceMass):
                out.append(item)
            elif isinstance(item, dict):
                try:
                    out.append(EvidenceMass.model_validate(item))
                except Exception:
                    continue
        return out


def _coerce_fusion_verdict(fv: dict) -> dict:
    """把 FusionVerdict 转 JSON-safe dict（枚举→字符串）。"""
    try:
        return FusionVerdict.model_validate(fv).model_dump(mode="json")
    except Exception:
        return FusionVerdict().model_dump(mode="json")


def build_fusion_result(**kwargs) -> FusionResult:
    """便捷构建 FusionResult；score 兜底取 risk_score。"""
    fr = FusionResult.model_validate(kwargs)
    if kwargs.get("risk_score") is None and fr.risk_scorecard:
        fr.risk_score = int(fr.risk_scorecard.get("risk_score", 0) or 0)
    return fr
