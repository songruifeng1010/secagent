"""
可解释风险评分器 — 统一门面（v3.0 双引擎）

架构:
  - RiskScorer（门面）: 按 config.yaml 的 risk_model.enabled 分发：
      * enabled=true  → WeightedRiskScorer（新：0~100 加权模型，默认）
      * enabled=false → LegacyRiskScorer（旧：无界规则加法模型，fallback）
  - 输出结构保持兼容（risk_score / risk_level / dimensions / needs_human /
    rules_hit / summarized），前端 risk_card 无需改动。

新模型（加权，0~100）:
  Risk = Behavior×40% + Intel×30% + Asset×20% + Context×10%
  详见 backend/orchestrator/risk_model.py

旧模型（LegacyRiskScorer，fallback）:
  行为/情报消费 Fusion 结果，IP 真实性/历史信誉不变；
  规则表直接加减，无界（可负/超 100）。
"""
import logging
from typing import Optional

from .risk_model import WeightedRiskScorer

logger = logging.getLogger("secagentx.orchestrator.risk")


# ─── 兼容导出（v2.4 旧测试/旧调用方） ───
# DIMENSIONS 指向旧模型的四维度（行为/情报/IP真实性/历史信誉）
DIMENSIONS = [
    ("行为证据", "_score_behavior"),
    ("威胁情报", "_score_intel"),
    ("IP真实性", "_score_ip"),
    ("历史信誉", "_score_reputation"),
]
BENIGN_INFRA_KEYWORDS = (
    "cloudflare", "google", "amazon", "aws", "azure", "microsoft",
    "cloudfront", "akamai", "fastly", "cdn", "cloud", "dns",
)
ANON_PROXY_KEYWORDS = (
    "proxy", "vpn", "tor", "anonym", "dynamic", "hosting", "nat",
)


class LegacyRiskScorer:
    """旧版规则加法评分器（fallback）— 完整保留 v2.4 逻辑。"""

    # 规则表常量（与 v2.4 一致）
    RISK_LEVEL_HIGH = 60
    RISK_LEVEL_MID = 20
    BENIGN_INFRA_KEYWORDS = (
        "cloudflare", "google", "amazon", "aws", "azure", "microsoft",
        "cloudfront", "akamai", "fastly", "cdn", "cloud", "dns",
    )
    ANON_PROXY_KEYWORDS = (
        "proxy", "vpn", "tor", "anonym", "dynamic", "hosting", "nat",
    )

    DIMENSIONS = [
        ("行为证据", "_score_behavior"),
        ("威胁情报", "_score_intel"),
        ("IP真实性", "_score_ip"),
        ("历史信誉", "_score_reputation"),
    ]

    @staticmethod
    def _is_private_or_reserved(ip: str) -> bool:
        try:
            from ipaddress import ip_address
            addr = ip_address(ip)
            return (
                addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified
            )
        except ValueError:
            return False

    @staticmethod
    def _get_fusion(ctx: dict) -> Optional[dict]:
        return ctx.get("fusion_result") or None

    @staticmethod
    def _find_package(ctx: dict, agent_id: str) -> Optional[dict]:
        for p in ctx.get("evidence_packages", []) or []:
            if p.get("agent_id") == agent_id:
                return p
        for r in ctx.get("agent_results", []) or []:
            if r.get("agent_id") == agent_id:
                return r
        return None

    def _score_behavior(self, ctx: dict) -> dict:
        fusion = self._get_fusion(ctx)
        if fusion is None:
            for r in ctx.get("agent_results", []):
                if r.get("agent_id") != "analyst-001":
                    continue
                if r.get("failed"):
                    return {"delta": 0, "rule_id": "RULE-BEH-06",
                            "reason": "分析师分析失败，行为维度无法评分", "tag": "unknown"}
                verdict = r.get("verdict")
                conf = r.get("confidence")
                if verdict == "malicious" and conf is not None and conf >= 0.7:
                    return {"delta": 35, "rule_id": "RULE-BEH-01",
                            "reason": f"分析师确认恶意行为（置信度 {conf:.0%}）", "tag": "pos"}
                if verdict == "malicious":
                    return {"delta": 20, "rule_id": "RULE-BEH-02",
                            "reason": f"分析师倾向恶意（置信度 {conf:.0%}）", "tag": "pos"}
                if verdict == "suspicious":
                    return {"delta": 15, "rule_id": "RULE-BEH-03",
                            "reason": "行为可疑，存在部分恶意特征", "tag": "pos"}
                if verdict == "benign":
                    return {"delta": -40, "rule_id": "RULE-BEH-04",
                            "reason": "分析师判定为良性/误报", "tag": "neg"}
                return {"delta": 0, "rule_id": "RULE-BEH-05",
                        "reason": "行为证据不足，按未知处理（不视为干净）", "tag": "unknown"}
            return {"delta": 0, "rule_id": "RULE-BEH-05",
                    "reason": "未获取行为分析结果，按未知处理", "tag": "unknown"}

        fv = fusion.get("verdict") or {}
        b_mal = fv.get("belief_malicious") or 0.0
        b_ben = fv.get("belief_benign") or 0.0
        b_unk = fv.get("belief_unknown") or 1.0
        verdict = fv.get("verdict", "unknown")
        conf = fv.get("confidence", 0.0)

        if verdict == "malicious" and conf >= 0.7:
            return {"delta": 35, "rule_id": "RULE-BEH-01",
                    "reason": f"融合裁决恶意行为（信念 {b_mal:.0%}）", "tag": "pos"}
        if verdict == "malicious":
            return {"delta": 20, "rule_id": "RULE-BEH-02",
                    "reason": f"融合倾向恶意（信念 {b_mal:.0%}）", "tag": "pos"}
        if verdict == "suspicious":
            return {"delta": 15, "rule_id": "RULE-BEH-03",
                    "reason": f"行为可疑（恶意信念 {b_mal:.0%}）", "tag": "pos"}
        if verdict == "benign":
            return {"delta": -40, "rule_id": "RULE-BEH-04",
                    "reason": f"融合判定良性（良性信念 {b_ben:.0%}）", "tag": "neg"}
        return {"delta": 0, "rule_id": "RULE-BEH-05",
                "reason": f"证据不足（未知 {b_unk:.0%}），按未知处理", "tag": "unknown"}

    def _score_intel(self, ctx: dict) -> dict:
        fusion = self._get_fusion(ctx)
        intel = self._find_package(ctx, "intel-001")
        coverage = None
        missing = []
        if intel is not None:
            coverage = intel.get("coverage")
            missing = intel.get("missing_sources") or []

        if fusion is None:
            if intel is None:
                return {"delta": 0, "rule_id": "RULE-INTEL-05",
                        "reason": "未获取威胁情报，按未知处理", "tag": "unknown"}
            if intel.get("failed"):
                return {"delta": 0, "rule_id": "RULE-INTEL-06",
                        "reason": "情报查询失败，按未知处理", "tag": "unknown"}
            verdict = intel.get("verdict")
            conf = intel.get("confidence")
            if verdict == "malicious" and conf is not None and conf >= 0.7:
                return {"delta": 40, "rule_id": "RULE-INTEL-01",
                        "reason": "威胁情报确认恶意（多源交叉验证）", "tag": "pos"}
            if verdict == "malicious":
                return {"delta": 25, "rule_id": "RULE-INTEL-02",
                        "reason": f"威胁情报显示恶意（置信度 {conf:.0%}）", "tag": "pos"}
            if verdict == "suspicious":
                return {"delta": 10, "rule_id": "RULE-INTEL-03",
                        "reason": "威胁情报显示可疑", "tag": "pos"}
            if verdict == "benign" and (coverage is None or coverage >= 1.0):
                return {"delta": -20, "rule_id": "RULE-INTEL-04",
                        "reason": "多源情报确认无恶意（降低误报风险）", "tag": "neg"}
            if coverage is not None and coverage < 1.0:
                return {"delta": 0, "rule_id": "RULE-INTEL-07",
                        "reason": f"情报源部分缺失（{len(missing)} 个源不可用），按未知处理", "tag": "unknown"}
            return {"delta": 0, "rule_id": "RULE-INTEL-05",
                    "reason": "情报未形成明确结论，按未知处理", "tag": "unknown"}

        fv = fusion.get("verdict") or {}
        verdict = fv.get("verdict", "unknown")
        conf = fv.get("confidence", 0.0)
        if intel is None or intel.get("failed"):
            return {"delta": 0, "rule_id": "RULE-INTEL-06",
                    "reason": "情报未参与融合或查询失败，按未知处理", "tag": "unknown"}

        if verdict == "malicious" and conf >= 0.7:
            return {"delta": 40, "rule_id": "RULE-INTEL-01",
                    "reason": "融合确认恶意（含情报多源交叉验证）", "tag": "pos"}
        if verdict == "malicious":
            return {"delta": 25, "rule_id": "RULE-INTEL-02",
                    "reason": f"融合显示恶意（置信度 {conf:.0%}）", "tag": "pos"}
        if verdict == "suspicious":
            return {"delta": 10, "rule_id": "RULE-INTEL-03",
                    "reason": "融合显示可疑", "tag": "pos"}
        if verdict == "benign" and (coverage is None or coverage >= 1.0):
            return {"delta": -20, "rule_id": "RULE-INTEL-04",
                    "reason": "多源情报确认无恶意（降低误报风险）", "tag": "neg"}
        if coverage is not None and coverage < 1.0:
            return {"delta": 0, "rule_id": "RULE-INTEL-07",
                    "reason": f"情报源部分缺失（{len(missing)} 个源不可用），按未知处理", "tag": "unknown"}
        return {"delta": 0, "rule_id": "RULE-INTEL-05",
                "reason": "情报未形成明确结论，按未知处理", "tag": "unknown"}

    def _score_ip(self, ctx: dict) -> dict:
        ip = ctx.get("ip")
        if not ip:
            return {"delta": 0, "rule_id": "RULE-IP-01",
                    "reason": "本次分析未涉及具体 IP，跳过真实性判断", "tag": "unknown"}
        if self._is_private_or_reserved(ip):
            return {"delta": -50, "rule_id": "RULE-IP-02",
                    "reason": f"源IP {ip} 为私有/保留地址，公网告警真实性存疑", "tag": "neg"}
        ip_info = ctx.get("ip_info") or {}
        org_text = " ".join(str(ip_info.get(k, "")) for k in ("org", "isp", "as", "note"))
        low = org_text.lower()
        if any(k in low for k in self.ANON_PROXY_KEYWORDS):
            return {"delta": 25, "rule_id": "RULE-IP-04",
                    "reason": "IP 归属匿名代理/动态通道，规避检测可能性高", "tag": "pos"}
        if any(k in low for k in self.BENIGN_INFRA_KEYWORDS):
            return {"delta": -30, "rule_id": "RULE-IP-03",
                    "reason": "IP 归属良性基础设施，公网告警真实性存疑", "tag": "neg"}
        return {"delta": 0, "rule_id": "RULE-IP-05",
                "reason": "IP 为正常公网地址", "tag": "neutral"}

    def _score_reputation(self, ctx: dict) -> dict:
        history = ctx.get("event_history")
        ip = ctx.get("ip")
        if history is None:
            return {"delta": 0, "rule_id": "RULE-REP-01",
                    "reason": "历史信誉查询未启用/不可用", "tag": "unknown"}
        if not ip:
            return {"delta": 0, "rule_id": "RULE-REP-01",
                    "reason": "无目标 IP，跳过历史信誉", "tag": "unknown"}
        if not history:
            return {"delta": -5, "rule_id": "RULE-REP-04",
                    "reason": f"{ip} 无历史记录，缺乏信任积累", "tag": "neg"}
        high = [e for e in history if (e.get("severity") or "") in ("高危", "紧急")]
        if high:
            return {"delta": 30, "rule_id": "RULE-REP-02",
                    "reason": f"{ip} 历史有 {len(high)} 条高危/紧急事件", "tag": "pos"}
        if all(e.get("status") == "resolved" for e in history):
            return {"delta": -10, "rule_id": "RULE-REP-03",
                    "reason": f"{ip} 历史 {len(history)} 条事件均正常处置", "tag": "neg"}
        return {"delta": -5, "rule_id": "RULE-REP-05",
                "reason": f"{ip} 历史 {len(history)} 条事件无高危记录", "tag": "neg"}

    @classmethod
    def score(cls, ctx: Optional[dict] = None) -> dict:
        """旧版评分（无界加法）— 与 v2.4 行为完全一致。"""
        ctx = ctx or {}
        dimensions = []
        rules_hit = []
        total = 0
        scorer = cls()
        for name, fn_name in cls.DIMENSIONS:
            try:
                res = getattr(scorer, fn_name)(ctx)
            except Exception as e:
                logger.warning("风险评分维度 %s 计算异常: %s", name, e)
                res = {"delta": 0, "rule_id": "RULE-ERR",
                       "reason": f"{name} 评分异常，按未知处理", "tag": "unknown"}
            delta = int(res["delta"])
            total += delta
            dimensions.append({
                "name": name,
                "delta": delta,
                "reason": res["reason"],
                "rule_id": res["rule_id"],
                "tag": res.get("tag", "neutral"),
            })
            rules_hit.append(res["rule_id"])

        level = cls._map_level(total)
        needs_human = cls._needs_human(total, dimensions)
        return {
            "risk_score": total,
            "risk_level": level,
            "dimensions": dimensions,
            "rules_hit": rules_hit,
            "needs_human": needs_human,
            "summarized": cls._summarize(dimensions, total, level),
            "model": "legacy",
        }

    @staticmethod
    def _map_level(score: int) -> str:
        if score >= LegacyRiskScorer.RISK_LEVEL_HIGH:
            return "高危"
        if score >= LegacyRiskScorer.RISK_LEVEL_MID:
            return "中危"
        return "低危"

    @staticmethod
    def _needs_human(total: int, dimensions: list) -> bool:
        if total >= LegacyRiskScorer.RISK_LEVEL_MID:
            return False
        unknown_rules = {
            "RULE-BEH-05", "RULE-BEH-06",
            "RULE-INTEL-05", "RULE-INTEL-06", "RULE-INTEL-07",
        }
        return any(d["rule_id"] in unknown_rules for d in dimensions)

    @staticmethod
    def _summarize(dimensions: list, total: int, level: str) -> str:
        parts = "，".join(
            f"{d['name']} {'+' if d['delta'] >= 0 else ''}{d['delta']}"
            for d in dimensions
        )
        return f"{parts}，最终 {total}（{level}）"


# ═══════════════════════ 门面（Facade） ═══════════════════════

def _load_config() -> dict:
    """惰性加载 config.yaml（失败返回 {}）。"""
    try:
        from backend.main import load_config
        return load_config() or {}
    except Exception as e:
        logger.debug("风险模型配置加载失败，使用默认加权模型: %s", e)
        return {}


class RiskScorer:
    """
    风险评分器统一门面（v3.0 双引擎）。

    - 默认使用新加权模型（WeightedRiskScorer，0~100）
    - config.risk_model.enabled=false → 回退旧加法模型（LegacyRiskScorer）
    - 权重/阈值从 config.yaml risk_model 段读取（参数化）
    """

    @classmethod
    def score(cls, ctx: Optional[dict] = None,
              config: Optional[dict] = None,
              weights: Optional[dict] = None) -> dict:
        """
        计算风险评分。

        参数:
          ctx:     评分上下文（见 risk_model.py docstring）
          config:  配置 dict（可选）；未提供时惰性加载 config.yaml
          weights: 权重覆盖 dict（可选，仅加权模型生效）
        """
        ctx = ctx or {}
        cfg = config if config is not None else _load_config()
        risk_cfg = (cfg or {}).get("risk_model", {}) or {}
        enabled = risk_cfg.get("enabled", True)
        if not enabled:
            return LegacyRiskScorer.score(ctx)

        # 权重参数化：config.risk_model.weights 优先，显式 weights 参数再次覆盖
        w = dict(risk_cfg.get("weights") or {})
        if weights:
            w.update(weights)
        return WeightedRiskScorer.score(ctx, weights=w)


__all__ = ["RiskScorer", "LegacyRiskScorer", "WeightedRiskScorer"]
