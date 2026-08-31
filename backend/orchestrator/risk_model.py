"""
加权风险评分模型（Risk Score Model）— v3.0

范围: 0 ~ 100（Clamp）
公式: Risk = Behavior×w_beh + Intel×w_intel + Asset×w_asset + Context×w_ctx
默认权重: 行为 40% / 情报 30% / 资产 20% / 上下文 10%（config.yaml 可参数化）

设计原则（延续 v2.4 项目纪律）:
  1. 确定性: 所有子分来自规则表，同一输入 → 同一分数（可复现、可审计）。
  2. 缺失≠干净: 维度信息缺失 / 查询失败 / Agent 未裁决 → 子分记 50（中性基线），
     绝不因"没查到"而记低分，同时 tag=unknown + needs_human=true。
  3. 可审计: 每个子分带 rule_id + 加权明细，可追溯到规则。
  4. 与决策融合一致: 行为/情报维度只消费 fusion_result（融合信念），
     不直接读取单个 Agent verdict —— 消除"单一 Agent 撬动风险分"的隐患。
  5. 良性证据可降分: 确认良性 → 子分压到 15~25，使总分回落（保留旧模型减分语义）。

用法:
    ctx = {
        "fusion_result": {...},       # Decision Fusion 结果（行为/情报维度以此为准）
        "evidence_packages": [...],   # 各 Agent 证据包（情报覆盖度/失败标记）
        "agent_results": [...],       # 兼容兜底：fusion_result 缺失时旧逻辑用
        "asset": {...},               # 可选：资产画像（{criticality, exposed, ...}）
        "ip": "1.2.3.4",              # 目标 IP
        "ip_info": {...},             # 可选：geoip 结果
        "event_history": [...],       # 可选：该 IP 历史事件列表
        "alert_meta": {...},          # 可选：告警元数据（severity/mitre_tactic/...）
    }
    result = WeightedRiskScorer.score(ctx)

输出:
    {
      "risk_score": 0~100,
      "risk_level": "低危|中危|高危|紧急",
      "dimensions": [ {name, score, weight, weighted, reason, rule_id, tag} ],
      "needs_human": bool,
      "rules_hit": [...],
      "summarized": "...",
      "model": "weighted",           # 标识使用加权模型
      "weights": {...},              # 实际使用权重
    }
"""
import logging
from typing import Optional

logger = logging.getLogger("secagentx.orchestrator.risk_model")

# ──────────────────────────────────────────────────────────────
# 默认权重（config.yaml 可参数化覆盖）
# 规则 id 命名: RULE-<维度>-<序号>
# ──────────────────────────────────────────────────────────────

DEFAULT_WEIGHTS = {
    "behavior": 0.38,
    "intel": 0.28,
    "asset": 0.20,
    "context": 0.09,
    # 预留给 RAG 接地质量；当前评分维度仍保持四维输出以兼容已有 API。
    "knowledge": 0.05,
}

# 风险等级阈值（0~100）
# 等级划分: 0~39 低危 / 40~59 中危 / 60~79 高危 / 80~100 紧急
# 字典值为各等级的【进入分数下限】
LEVEL_THRESHOLDS = {
    "低危": 0,
    "中危": 40,
    "高危": 60,
    "紧急": 80,
}

# 未知/中性基线子分：信息缺失时记此分，不视为干净
UNKNOWN_BASELINE = 50
# 确认良性时的低分
BENIGN_SCORE = 15

# 良性基础设施关键词（IP 归属 → 降分：公网告警真实性存疑）
BENIGN_INFRA_KEYWORDS = (
    "cloudflare", "google", "amazon", "aws", "azure", "microsoft",
    "cloudfront", "akamai", "fastly", "cdn", "cloud", "dns",
)

# 匿名/动态通道关键词（IP 归属 → 加分：规避检测可能性高）
ANON_PROXY_KEYWORDS = (
    "proxy", "vpn", "tor", "anonym", "dynamic", "hosting", "nat",
)

# MITRE 高风险战术（上下文维度：命中 → 加分）
HIGH_RISK_TACTICS = (
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "lateral-movement", "collection",
    "command-and-control", "impact", "reconnaissance", "resource-development",
    "initial_access", "execution", "privilege_escalation", "defense_evasion",
    "credential_access", "lateral_movement", "command_and_control",
    "权限提升", "横向移动", "命令与控制", "初始访问", "防御规避", "凭据访问",
)


def _is_private_or_reserved(ip: str) -> bool:
    """是否为私有/保留/回环/链路本地等不可路由公网地址"""
    try:
        from ipaddress import ip_address
        addr = ip_address(ip)
        return (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_unspecified
        )
    except ValueError:
        return False


def _clamp_score(score: float) -> int:
    """Clamp 到 0~100 并取整。"""
    return int(max(0.0, min(100.0, round(score))))


def _get_fusion(ctx: dict) -> Optional[dict]:
    """获取 Decision Fusion 结果。"""
    return ctx.get("fusion_result") or None


def _find_package(ctx: dict, agent_id: str) -> Optional[dict]:
    """查找某 Agent 的证据包（覆盖度/失败标记）。"""
    for p in ctx.get("evidence_packages", []) or []:
        if p.get("agent_id") == agent_id:
            return p
    for r in ctx.get("agent_results", []) or []:
        if r.get("agent_id") == agent_id:
            return r
    return None


# ═══════════════════════ 维度子评分函数 ═══════════════════════
# 每个函数接收 ctx，返回 {score, rule_id, reason, tag}
# tag: pos(风险加分) / neg(风险减分) / unknown(信息缺失) / neutral(中性)


def _score_behavior(ctx: dict) -> dict:
    """行为维度：基于 Fusion 恶意信念（0~100 子分）。"""
    fusion = _get_fusion(ctx)
    if fusion is None:
        # 兜底（fusion 未启用/异常）：读 analyst-001 证据包
        for r in ctx.get("agent_results", []):
            if r.get("agent_id") != "analyst-001":
                continue
            if r.get("failed"):
                return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-BEH-06",
                        "reason": "分析师分析失败，行为维度按未知处理", "tag": "unknown"}
            verdict = r.get("verdict")
            conf = r.get("confidence")
            if verdict == "malicious" and conf is not None and conf >= 0.7:
                return {"score": 95, "rule_id": "RULE-BEH-01",
                        "reason": f"分析师确认恶意行为（置信度 {conf:.0%}）", "tag": "pos"}
            if verdict == "malicious":
                return {"score": 80, "rule_id": "RULE-BEH-02",
                        "reason": f"分析师倾向恶意（置信度 {conf:.0%}）", "tag": "pos"}
            if verdict == "suspicious":
                return {"score": 60, "rule_id": "RULE-BEH-03",
                        "reason": "行为可疑，存在部分恶意特征", "tag": "pos"}
            if verdict == "benign":
                return {"score": BENIGN_SCORE, "rule_id": "RULE-BEH-04",
                        "reason": "分析师判定为良性/误报", "tag": "neg"}
            return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-BEH-05",
                    "reason": "行为证据不足，按未知处理（不视为干净）", "tag": "unknown"}
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-BEH-05",
                "reason": "未获取行为分析结果，按未知处理", "tag": "unknown"}

    # 正常路径：消费 Fusion 融合信念
    fv = fusion.get("verdict") or {}
    verdict = fv.get("verdict", "unknown")
    conf = fv.get("confidence", 0.0)
    b_mal = fv.get("belief_malicious") or 0.0
    b_ben = fv.get("belief_benign") or 0.0

    if verdict == "malicious" and conf >= 0.7:
        return {"score": 95, "rule_id": "RULE-BEH-01",
                "reason": f"融合裁决恶意行为（信念 {b_mal:.0%}）", "tag": "pos"}
    if verdict == "malicious":
        return {"score": 80, "rule_id": "RULE-BEH-02",
                "reason": f"融合倾向恶意（信念 {b_mal:.0%}）", "tag": "pos"}
    if verdict == "suspicious":
        return {"score": 60, "rule_id": "RULE-BEH-03",
                "reason": f"行为可疑（恶意信念 {b_mal:.0%}）", "tag": "pos"}
    if verdict == "benign":
        return {"score": BENIGN_SCORE, "rule_id": "RULE-BEH-04",
                "reason": f"融合判定良性（良性信念 {b_ben:.0%}）", "tag": "neg"}
    return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-BEH-05",
            "reason": f"证据不足（未知信念占主导），按未知处理", "tag": "unknown"}


def _score_intel(ctx: dict) -> dict:
    """情报维度：基于 Fusion 信念 + 情报覆盖度（缺失源不能"装干净"）。"""
    fusion = _get_fusion(ctx)
    intel = _find_package(ctx, "intel-001")

    coverage = None
    missing = []
    if intel is not None:
        coverage = intel.get("coverage")
        missing = intel.get("missing_sources") or []

    if fusion is None:
        # 兜底：旧逻辑读 intel 证据包
        if intel is None:
            return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-05",
                    "reason": "未获取威胁情报，按未知处理", "tag": "unknown"}
        if intel.get("failed"):
            return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-06",
                    "reason": "情报查询失败，按未知处理", "tag": "unknown"}
        verdict = intel.get("verdict")
        conf = intel.get("confidence")
        if verdict == "malicious" and conf is not None and conf >= 0.7:
            return {"score": 95, "rule_id": "RULE-INTEL-01",
                    "reason": "威胁情报确认恶意（多源交叉验证）", "tag": "pos"}
        if verdict == "malicious":
            return {"score": 80, "rule_id": "RULE-INTEL-02",
                    "reason": f"威胁情报显示恶意（置信度 {conf:.0%}）", "tag": "pos"}
        if verdict == "suspicious":
            return {"score": 60, "rule_id": "RULE-INTEL-03",
                    "reason": "威胁情报显示可疑", "tag": "pos"}
        if verdict == "benign" and (coverage is None or coverage >= 1.0):
            return {"score": BENIGN_SCORE, "rule_id": "RULE-INTEL-04",
                    "reason": "多源情报确认无恶意（降低误报风险）", "tag": "neg"}
        if coverage is not None and coverage < 1.0:
            return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-07",
                    "reason": f"情报源部分缺失（{len(missing)} 个源不可用），按未知处理", "tag": "unknown"}
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-05",
                "reason": "情报未形成明确结论，按未知处理", "tag": "unknown"}

    # 正常路径：消费 Fusion 信念
    fv = fusion.get("verdict") or {}
    verdict = fv.get("verdict", "unknown")
    conf = fv.get("confidence", 0.0)
    if intel is None or intel.get("failed"):
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-06",
                "reason": "情报未参与融合或查询失败，按未知处理", "tag": "unknown"}

    if verdict == "malicious" and conf >= 0.7:
        return {"score": 95, "rule_id": "RULE-INTEL-01",
                "reason": "融合确认恶意（含情报多源交叉验证）", "tag": "pos"}
    if verdict == "malicious":
        return {"score": 80, "rule_id": "RULE-INTEL-02",
                "reason": f"融合显示恶意（置信度 {conf:.0%}）", "tag": "pos"}
    if verdict == "suspicious":
        return {"score": 60, "rule_id": "RULE-INTEL-03",
                "reason": "融合显示可疑", "tag": "pos"}
    if verdict == "benign" and (coverage is None or coverage >= 1.0):
        return {"score": BENIGN_SCORE, "rule_id": "RULE-INTEL-04",
                "reason": "多源情报确认无恶意（降低误报风险）", "tag": "neg"}
    if coverage is not None and coverage < 1.0:
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-07",
                "reason": f"情报源部分缺失（{len(missing)} 个源不可用），按未知处理", "tag": "unknown"}
    return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-INTEL-05",
            "reason": "情报未形成明确结论，按未知处理", "tag": "unknown"}


# 资产关键性 → 基础子分（资产维度）
_ASSET_CRITICALITY_SCORE = {
    "critical": 90, "核心": 90, "核心资产": 90,
    "high": 75, "高": 75, "高价值": 75, "高价值资产": 75,
    "medium": 60, "中": 60, "普通": 60, "一般": 60,
    "low": 30, "低": 30, "低价值": 30, "测试": 30,
}


def _score_asset(ctx: dict) -> dict:
    """资产维度：目标资产的业务价值 + 暴露面（0~100 子分）。"""
    asset = ctx.get("asset") or {}
    if not asset:
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-ASSET-05",
                "reason": "无资产画像信息，按未知（中性）处理", "tag": "unknown"}

    criticality = str(asset.get("criticality") or asset.get("level") or "").strip()
    base = _ASSET_CRITICALITY_SCORE.get(criticality.lower() if isinstance(criticality, str) else criticality)
    if base is None:
        # 兜底：未识别关键性 → 中性 55
        base = 55
        rule_id = "RULE-ASSET-03"
    else:
        rule_id = "RULE-ASSET-01"

    # 暴露面加成：公网暴露 / 含敏感数据 → 加分
    exposed = bool(asset.get("exposed") or asset.get("is_public") or False)
    has_pii = bool(asset.get("contains_pii") or asset.get("sensitive") or False)
    if has_pii:
        base = min(100, base + 15)
    if exposed:
        base = min(100, base + 10)

    if has_pii or exposed:
        rule_id = "RULE-ASSET-01"
    reason = f"资产价值 {criticality or '未知'}，暴露={'是' if exposed else '否'}，含敏感数据={'是' if has_pii else '否'}"

    if base >= 75:
        return {"score": base, "rule_id": rule_id, "reason": reason, "tag": "pos"}
    if base <= 30:
        return {"score": base, "rule_id": "RULE-ASSET-02", "reason": reason, "tag": "neg"}
    return {"score": base, "rule_id": rule_id, "reason": reason, "tag": "neutral"}


def _score_context(ctx: dict) -> dict:
    """上下文维度：IP 归属 + 历史信誉 + 告警元数据（0~100 子分）。"""
    ip = ctx.get("ip")
    clues = []

    # ── IP 归属线索 ──
    if ip:
        if _is_private_or_reserved(ip):
            clues.append(("neg", 20, "IP 为私有/保留地址，公网告警真实性存疑"))
        else:
            ip_info = ctx.get("ip_info") or {}
            org_text = " ".join(str(ip_info.get(k, "")) for k in ("org", "isp", "as", "note"))
            low = org_text.lower()
            if any(k in low for k in ANON_PROXY_KEYWORDS):
                clues.append(("pos", 80, "IP 归属匿名代理/动态通道，规避检测可能性高"))
            elif any(k in low for k in BENIGN_INFRA_KEYWORDS):
                clues.append(("neg", 25, "IP 归属良性基础设施，公网告警真实性存疑"))

    # ── 历史信誉线索 ──
    history = ctx.get("event_history")
    if history is not None and ip:
        if history:
            high = [e for e in history if (e.get("severity") or "") in ("高危", "紧急")]
            if high:
                clues.append(("pos", 75, f"{ip} 历史有 {len(high)} 条高危/紧急事件"))
            elif all(e.get("status") == "resolved" for e in history):
                clues.append(("neg", 30, f"{ip} 历史 {len(history)} 条事件均正常处置"))
            else:
                clues.append(("neg", 40, f"{ip} 历史 {len(history)} 条事件无高危记录"))
        else:
            clues.append(("neg", 40, f"{ip} 无历史记录，缺乏信任积累"))

    # ── 告警元数据线索 ──
    alert_meta = ctx.get("alert_meta") or {}
    severity = str(alert_meta.get("severity") or "")
    if severity in ("高危", "紧急"):
        clues.append(("pos", 70, f"告警严重度 {severity}"))
    tactic = str(alert_meta.get("mitre_tactic") or alert_meta.get("mitre_tactic_id") or "")
    if tactic and any(t in str(tactic).lower() for t in HIGH_RISK_TACTICS):
        clues.append(("pos", 65, f"命中高风险 MITRE 战术 {tactic}"))

    # ── 汇总 ──
    if not clues:
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-CTX-05",
                "reason": "无上下文信息，按未知（中性）处理", "tag": "unknown"}

    pos = [c for c in clues if c[0] == "pos"]
    neg = [c for c in clues if c[0] == "neg"]
    if pos and not neg:
        score = max(c[1] for c in pos)
        tag, rule_id = "pos", "RULE-CTX-01"
    elif neg and not pos:
        score = min(c[1] for c in neg)
        tag, rule_id = "neg", "RULE-CTX-02"
    elif pos and neg:
        # 混合：取 pos 最大值与 neg 最小值的中间偏风险
        score = int((max(c[1] for c in pos) + min(c[1] for c in neg)) / 2)
        tag, rule_id = "neutral", "RULE-CTX-03"
    else:
        # 防御：线索存在但均非 pos/neg（理论上不发生）
        return {"score": UNKNOWN_BASELINE, "rule_id": "RULE-CTX-05",
                "reason": "上下文线索无法归类，按未知（中性）处理", "tag": "unknown"}
    reason = "；".join(c[2] for c in clues)
    return {"score": score, "rule_id": rule_id, "reason": reason, "tag": tag}


# 维度注册表（顺序即展示顺序）
DIMENSIONS = [
    ("行为证据", "behavior", _score_behavior, 0.40),
    ("威胁情报", "intel", _score_intel, 0.30),
    ("资产价值", "asset", _score_asset, 0.20),
    ("上下文线索", "context", _score_context, 0.10),
]


class WeightedRiskScorer:
    """加权风险评分器（0~100）— 纯确定性，无 IO、无 LLM。"""

    @classmethod
    def score(cls, ctx: Optional[dict] = None,
              weights: Optional[dict] = None,
              dynamic_weights: bool = False,
              dynamic_config: Optional[dict] = None) -> dict:
        """计算加权风险评分（0~100）。

        weights 可覆盖默认权重；未知维度名自动忽略，缺失维度按默认权重。
        """
        ctx = ctx or {}
        w = dict(DEFAULT_WEIGHTS)
        if weights:
            # 兼容旧四维调用：调用方明确给出完整四维权重时，不额外稀释为
            # knowledge 预留份额；动态引擎仍可直接使用五维默认基线。
            if "knowledge" not in weights and all(
                key in weights for key in ("behavior", "intel", "asset", "context")
            ):
                w["knowledge"] = 0.0
            for k, v in weights.items():
                if k in w and isinstance(v, (int, float)) and v >= 0:
                    w[k] = float(v)
        adjustments = []
        if dynamic_weights:
            from .dynamic_weights import DynamicWeightEngine
            dynamic = DynamicWeightEngine.compute(ctx, base_weights=w,
                                                  config=dynamic_config)
            w = dynamic["weights"]
            adjustments = dynamic["adjustments"]

        # 输出权重包含 knowledge 预留维度并保证总和为 1。
        total_w = sum(w.values()) or 1.0
        norm_w = {k: v / total_w for k, v in w.items()}

        # 四个既有评分维度单独归一化，避免加入预留 knowledge 权重后
        # 无知识上下文的历史风险分数整体下移。
        active_keys = {key for _, key, _, _ in DIMENSIONS}
        active_total = sum(norm_w.get(k, 0.0) for k in active_keys) or 1.0
        score_w = {k: norm_w.get(k, 0.0) / active_total for k in active_keys}

        dimensions = []
        rules_hit = []
        total = 0.0
        for name, key, fn, default_w in DIMENSIONS:
            try:
                res = fn(ctx)
            except Exception as e:
                logger.warning("风险评分维度 %s 计算异常: %s", name, e)
                res = {"score": UNKNOWN_BASELINE, "rule_id": "RULE-ERR",
                       "reason": f"{name} 评分异常，按未知处理", "tag": "unknown"}
            weight = score_w.get(key, default_w)
            dim_score = _clamp_score(res["score"])
            weighted = round(dim_score * weight, 2)
            total += weighted
            dimensions.append({
                "name": name,
                "score": dim_score,
                "weight": round(weight, 4),
                "weighted": weighted,
                "reason": res["reason"],
                "rule_id": res["rule_id"],
                "tag": res.get("tag", "neutral"),
            })
            rules_hit.append(res["rule_id"])

        risk_score = _clamp_score(total)
        level = cls._map_level(risk_score)
        needs_human = cls._needs_human(risk_score, dimensions)
        result = {
            "risk_score": risk_score,
            "risk_level": level,
            "dimensions": dimensions,
            "rules_hit": rules_hit,
            "needs_human": needs_human,
            "summarized": cls._summarize(dimensions, risk_score, level),
            "model": "weighted",
            "weights": norm_w,
        }
        if dynamic_weights:
            result["weights_dynamic"] = True
            result["weight_adjustments"] = adjustments
        return result

    @staticmethod
    def _map_level(score: int) -> str:
        if score >= LEVEL_THRESHOLDS["紧急"]:
            return "紧急"
        if score >= LEVEL_THRESHOLDS["高危"]:
            return "高危"
        if score >= LEVEL_THRESHOLDS["中危"]:
            return "中危"
        return "低危"

    @staticmethod
    def _needs_human(score: int, dimensions: list) -> bool:
        """关键维度（行为/情报）信息缺失 → 需人工复核（缺失≠干净）。

        决策: unknown 处理 risk_score=50 + needs_human=true（用户决策点 4）。
        只要关键维度有明确结论（无论高低分），不强制人工；
        任一关键维度信息缺失（如情报源缺失）→ 人工复核。
        """
        unknown_rules = {
            "RULE-BEH-05", "RULE-BEH-06",
            "RULE-INTEL-05", "RULE-INTEL-06", "RULE-INTEL-07",
        }
        return any(d["rule_id"] in unknown_rules for d in dimensions)

    @staticmethod
    def _summarize(dimensions: list, total: int, level: str) -> str:
        parts = "，".join(
            f"{d['name']} {d['score']}×{d['weight']:.0%}={d['weighted']:.0f}"
            for d in dimensions
        )
        return f"{parts}，最终 {total}（{level}）"


__all__ = ["WeightedRiskScorer", "DIMENSIONS", "DEFAULT_WEIGHTS",
           "LEVEL_THRESHOLDS", "UNKNOWN_BASELINE", "BENIGN_SCORE"]
