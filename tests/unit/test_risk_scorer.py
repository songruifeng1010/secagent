"""
可解释风险评分卡（Risk Scorecard）单元测试

覆盖:
  - 用户示例场景: 行为+35 / 情报+10 / IP-50 / 信誉-5 → 最终 -10 低危
  - 各维度规则命中/未命中
  - 缺失≠干净: 情报源缺失/Agent 未裁决 → 0 分并按"未知"处理
  - 危级映射与 needs_human 兜底
  - 确定性: 同输入多次评分结果一致
  - 空上下文安全
"""
import pytest

from backend.orchestrator.risk_scorer import (
    RiskScorer, DIMENSIONS,
    BENIGN_INFRA_KEYWORDS, ANON_PROXY_KEYWORDS,
)


def _analyst(verdict="malicious", confidence=0.85, failed=False):
    return {
        "agent_id": "analyst-001",
        "verdict": verdict,
        "confidence": confidence,
        "failed": failed,
        "degraded": False,
    }


def _intel(verdict=None, confidence=None, coverage=None, missing=None, failed=False):
    return {
        "agent_id": "intel-001",
        "verdict": verdict,
        "confidence": confidence,
        "coverage": coverage,
        "missing_sources": missing or [],
        "failed": failed,
        "degraded": False,
    }


def _ctx(agents=None, ip=None, ip_info=None, event_history=None):
    return {
        "agent_results": agents or [],
        "ip": ip,
        "ip_info": ip_info,
        "event_history": event_history,
    }


def _legacy_score(ctx):
    """旧模型评分入口（v2.4 回归基线）：显式走 LegacyRiskScorer。"""
    return RiskScorer.score(ctx, config={"risk_model": {"enabled": False}})




# ═══════════════════ 用户示例场景 ═══════════════════

class TestUserExample:
    def test_example_layout_and_score(self):
        """用户示例: 行为+35 / 情报+10 / IP-50 / 信誉-5 → 最终 -10 低危"""
        ctx = _ctx(
            agents=[_analyst(verdict="malicious", confidence=0.85), _intel(verdict="suspicious")],
            ip="10.0.0.5",
            event_history=[],
        )
        s = _legacy_score(ctx)
        assert s["risk_score"] == -10
        assert s["risk_level"] == "低危"
        assert s["summarized"] == "行为证据 +35，威胁情报 +10，IP真实性 -50，历史信誉 -5，最终 -10（低危）"
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["delta"] == 35
        assert dims["威胁情报"]["delta"] == 10
        assert dims["IP真实性"]["delta"] == -50
        assert dims["历史信誉"]["delta"] == -5


# ═══════════════════ 行为证据维度 ═══════════════════

class TestBehaviorDimension:
    def test_malicious_high_confidence_plus35(self):
        s = _legacy_score(_ctx(agents=[_analyst("malicious", 0.9)]))
        d = s["dimensions"][0]
        assert d["delta"] == 35 and d["rule_id"] == "RULE-BEH-01"

    def test_malicious_low_confidence_plus20(self):
        s = _legacy_score(_ctx(agents=[_analyst("malicious", 0.5)]))
        d = s["dimensions"][0]
        assert d["delta"] == 20 and d["rule_id"] == "RULE-BEH-02"

    def test_suspicious_plus15(self):
        s = _legacy_score(_ctx(agents=[_analyst("suspicious", 0.6)]))
        d = s["dimensions"][0]
        assert d["delta"] == 15 and d["rule_id"] == "RULE-BEH-03"

    def test_benign_minus40(self):
        s = _legacy_score(_ctx(agents=[_analyst("benign", 0.9)]))
        d = s["dimensions"][0]
        assert d["delta"] == -40 and d["rule_id"] == "RULE-BEH-04"

    def test_unknown_zero_not_clean(self):
        """行为证据不足 → 0 分（不视为干净），且标记 needs_human"""
        s = _legacy_score(_ctx(agents=[_analyst("unknown", None)]))
        d = s["dimensions"][0]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-BEH-05"
        assert s["needs_human"] is True

    def test_analyst_failed_zero(self):
        s = _legacy_score(_ctx(agents=[_analyst(failed=True)]))
        d = s["dimensions"][0]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-BEH-06"

    def test_no_analyst_zero(self):
        s = _legacy_score(_ctx(agents=[]))
        d = s["dimensions"][0]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-BEH-05"


# ═══════════════════ 威胁情报维度 ═══════════════════

class TestIntelDimension:
    def test_malicious_high_conf_plus40(self):
        s = _legacy_score(_ctx(agents=[_intel("malicious", 0.9, coverage=1.0)]))
        d = s["dimensions"][1]
        assert d["delta"] == 40 and d["rule_id"] == "RULE-INTEL-01"

    def test_malicious_low_conf_plus25(self):
        s = _legacy_score(_ctx(agents=[_intel("malicious", 0.5, coverage=1.0)]))
        d = s["dimensions"][1]
        assert d["delta"] == 25 and d["rule_id"] == "RULE-INTEL-02"

    def test_suspicious_plus10(self):
        s = _legacy_score(_ctx(agents=[_intel("suspicious", 0.6)]))
        d = s["dimensions"][1]
        assert d["delta"] == 10 and d["rule_id"] == "RULE-INTEL-03"

    def test_benign_full_coverage_minus20(self):
        """情报全覆盖且确认无恶意 → 可信的干净证据，可减分"""
        s = _legacy_score(_ctx(agents=[_intel("benign", 0.9, coverage=1.0)]))
        d = s["dimensions"][1]
        assert d["delta"] == -20 and d["rule_id"] == "RULE-INTEL-04"

    def test_missing_sources_zero_not_clean(self):
        """情报源部分缺失 → 0 分（缺失≠干净），且 needs_human"""
        s = _legacy_score(_ctx(agents=[_intel("benign", 0.9, coverage=0.5, missing=["otx", "vt"])]))
        d = s["dimensions"][1]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-INTEL-07"
        assert s["needs_human"] is True

    def test_no_intel_zero(self):
        s = _legacy_score(_ctx(agents=[]))
        d = s["dimensions"][1]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-INTEL-05"

    def test_intel_failed_zero(self):
        s = _legacy_score(_ctx(agents=[_intel(failed=True)]))
        d = s["dimensions"][1]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-INTEL-06"


# ═══════════════════ IP 真实性维度 ═══════════════════

class TestIpDimension:
    def test_no_ip_zero(self):
        s = _legacy_score(_ctx(ip=None))
        d = s["dimensions"][2]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-IP-01"

    @pytest.mark.parametrize("ip", [
        "10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1",
        "169.254.1.1", "0.0.0.0",
    ])
    def test_private_reserved_minus50(self, ip):
        s = _legacy_score(_ctx(ip=ip))
        d = s["dimensions"][2]
        assert d["delta"] == -50 and d["rule_id"] == "RULE-IP-02"

    def test_public_ip_zero(self):
        s = _legacy_score(_ctx(ip="45.33.32.156"))
        d = s["dimensions"][2]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-IP-05"

    def test_anon_proxy_plus25(self):
        s = _legacy_score(_ctx(ip="1.2.3.4", ip_info={"org": "VPN Proxy Service"}))
        d = s["dimensions"][2]
        assert d["delta"] == 25 and d["rule_id"] == "RULE-IP-04"

    def test_benign_infra_minus30(self):
        s = _legacy_score(_ctx(ip="1.2.3.4", ip_info={"org": "Cloudflare, Inc."}))
        d = s["dimensions"][2]
        assert d["delta"] == -30 and d["rule_id"] == "RULE-IP-03"


# ═══════════════════ 历史信誉维度 ═══════════════════

class TestReputationDimension:
    def test_no_query_zero(self):
        s = _legacy_score(_ctx(ip="1.2.3.4", event_history=None))
        d = s["dimensions"][3]
        assert d["delta"] == 0 and d["rule_id"] == "RULE-REP-01"

    def test_high_history_plus30(self):
        s = _legacy_score(_ctx(
            ip="1.2.3.4",
            event_history=[{"severity": "高危", "status": "open"}, {"severity": "中危", "status": "resolved"}],
        ))
        d = s["dimensions"][3]
        assert d["delta"] == 30 and d["rule_id"] == "RULE-REP-02"

    def test_resolved_all_minus10(self):
        s = _legacy_score(_ctx(
            ip="1.2.3.4",
            event_history=[{"severity": "低危", "status": "resolved"}, {"severity": "中危", "status": "resolved"}],
        ))
        d = s["dimensions"][3]
        assert d["delta"] == -10 and d["rule_id"] == "RULE-REP-03"

    def test_no_history_minus5(self):
        s = _legacy_score(_ctx(ip="1.2.3.4", event_history=[]))
        d = s["dimensions"][3]
        assert d["delta"] == -5 and d["rule_id"] == "RULE-REP-04"

    def test_low_history_minus5(self):
        s = _legacy_score(_ctx(
            ip="1.2.3.4",
            event_history=[{"severity": "低危", "status": "open"}],
        ))
        d = s["dimensions"][3]
        assert d["delta"] == -5 and d["rule_id"] == "RULE-REP-05"


# ═══════════════════ 危级映射 / 兜底 / 确定性 ═══════════════════

class TestLevelAndGuarantees:
    def test_level_high(self):
        """行为+35 + 情报+40 + 信誉+30 → 105 高危"""
        s = _legacy_score(_ctx(
            agents=[_analyst("malicious", 0.9), _intel("malicious", 0.9, coverage=1.0)],
            ip="45.33.32.156",
            event_history=[{"severity": "高危", "status": "open"}],
        ))
        assert s["risk_level"] == "高危"

    def test_level_mid(self):
        """行为+35 + 情报-20 → 15 中危（<20 则低危，验证边界）"""
        s = _legacy_score(_ctx(
            agents=[_analyst("malicious", 0.9), _intel("benign", 0.9, coverage=1.0)],
        ))
        assert s["risk_score"] == 15
        assert s["risk_level"] == "低危"

    def test_empty_ctx_safe(self):
        s = _legacy_score({})
        assert s["risk_score"] == 0
        assert s["risk_level"] == "低危"
        assert s["needs_human"] is True
        assert len(s["dimensions"]) == 4
        assert s["rules_hit"] == ["RULE-BEH-05", "RULE-INTEL-05", "RULE-IP-01", "RULE-REP-01"]

    def test_deterministic(self):
        ctx = _ctx(
            agents=[_analyst("malicious", 0.9), _intel("suspicious")],
            ip="10.0.0.5", event_history=[],
        )
        results = {_legacy_score(ctx)["risk_score"] for _ in range(5)}
        assert len(results) == 1  # 同输入 → 同分数

    def test_rules_hit_tracked(self):
        s = _legacy_score(_ctx(
            agents=[_analyst("malicious", 0.9), _intel("suspicious")],
            ip="10.0.0.5", event_history=[],
        ))
        assert set(s["rules_hit"]) == {"RULE-BEH-01", "RULE-INTEL-03", "RULE-IP-02", "RULE-REP-04"}

    def test_dimensions_order(self):
        names = [n for n, _ in DIMENSIONS]
        assert names == ["行为证据", "威胁情报", "IP真实性", "历史信誉"]


class TestRiskScorerFusion:
    """v2.4: RiskScorer 消费 Fusion 结果（不再读单个 Agent verdict）"""

    @staticmethod
    def _fusion_ctx(belief_mal=0.0, belief_ben=0.0, belief_unk=1.0,
                     verdict="unknown", confidence=0.0, intel_coverage=None,
                     ip="8.8.8.8"):
        fusion_result = {
            "engine": "dempster_shafer",
            "verdict": {
                "verdict": verdict,
                "belief_malicious": belief_mal,
                "belief_benign": belief_ben,
                "belief_unknown": belief_unk,
                "confidence": confidence,
            },
        }
        ctx = {
            "fusion_result": fusion_result,
            "evidence_packages": [],
            "agent_results": [],  # 故意为空：验证 fusion 路径不依赖 agent_results
            "ip": ip,
            "event_history": None,
        }
        if intel_coverage is not None:
            ctx["evidence_packages"] = [{
                "agent_id": "intel-001", "coverage": intel_coverage,
                "missing_sources": [] if intel_coverage >= 1.0 else ["VT"],
            }]
        return _legacy_score(ctx)

    def test_fusion_malicious_high(self):
        """fusion 裁决恶意(高信念) → 行为+35, 情报+40"""
        s = self._fusion_ctx(belief_mal=0.93, belief_unk=0.07,
                             verdict="malicious", confidence=0.93,
                             intel_coverage=1.0)
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["delta"] == 35
        assert dims["行为证据"]["rule_id"] == "RULE-BEH-01"
        assert dims["威胁情报"]["delta"] == 40
        assert dims["威胁情报"]["rule_id"] == "RULE-INTEL-01"

    def test_fusion_suspicious(self):
        s = self._fusion_ctx(belief_mal=0.55, belief_unk=0.45,
                             verdict="suspicious", confidence=0.55,
                             intel_coverage=0.5)
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["delta"] == 15
        assert dims["行为证据"]["rule_id"] == "RULE-BEH-03"
        # fusion 已综合裁决 suspicious → 情报维度同样 +10（覆盖不足不再单独扣）
        assert dims["威胁情报"]["delta"] == 10
        assert dims["威胁情报"]["rule_id"] == "RULE-INTEL-03"

    def test_fusion_benign_full_coverage(self):
        """fusion 裁决良性 + 情报全覆盖 → 行为-40, 情报-20"""
        s = self._fusion_ctx(belief_ben=0.92, belief_unk=0.08,
                             verdict="benign", confidence=0.08,
                             intel_coverage=1.0)
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["delta"] == -40
        assert dims["威胁情报"]["delta"] == -20

    def test_fusion_unknown(self):
        """fusion 未知 → 行为/情报均 0 分 + needs_human"""
        s = self._fusion_ctx(belief_unk=1.0, verdict="unknown", confidence=0.3)
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["delta"] == 0
        assert dims["行为证据"]["rule_id"] == "RULE-BEH-05"
        assert dims["威胁情报"]["rule_id"] == "RULE-INTEL-06"
        assert s["needs_human"] is True

    def test_fusion_overrides_single_agent(self):
        """关键：fusion 存在时，即使 agent_results 里有相反 verdict，也以 fusion 为准"""
        fusion_result = {
            "engine": "dempster_shafer",
            "verdict": {"verdict": "malicious", "belief_malicious": 0.93,
                        "belief_benign": 0.0, "belief_unknown": 0.07,
                        "confidence": 0.93},
        }
        ctx = {
            "fusion_result": fusion_result,
            # 故意放一个 benign 的 analyst —— 验证 fusion 不被单个 Agent 撬动
            "agent_results": [_analyst(verdict="benign", confidence=0.95)],
            "evidence_packages": [{
                "agent_id": "intel-001", "coverage": 1.0,
                "missing_sources": [],
            }],
            "ip": "8.8.8.8", "event_history": None,
        }
        s = _legacy_score(ctx)
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["delta"] == 35  # 按 fusion 恶意，而非 analyst benign
        assert dims["行为证据"]["rule_id"] == "RULE-BEH-01"


# ═══════════════════════ v3.0 双引擎门面（Facade）测试 ═══════════════════════

class TestRiskScorerFacade:
    """v3.0: RiskScorer 门面按配置分发加权/旧模型"""

    def test_default_uses_weighted_model(self):
        """默认（无 config）→ 加权模型（model=weighted）。"""
        s = RiskScorer.score({})
        assert s["model"] == "weighted"
        assert s["risk_score"] == 50  # 全未知 → 中性基线 50
        assert 0 <= s["risk_score"] <= 100
        assert len(s["dimensions"]) == 4

    def test_explicit_enabled_uses_weighted(self):
        cfg = {"risk_model": {"enabled": True}}
        s = RiskScorer.score({}, config=cfg)
        assert s["model"] == "weighted"

    def test_disabled_falls_back_to_legacy(self):
        """enabled=false → 旧加法模型（model=legacy）。"""
        cfg = {"risk_model": {"enabled": False}}
        s = RiskScorer.score({}, config=cfg)
        assert s["model"] == "legacy"
        assert s["risk_score"] == 0  # 旧模型空 ctx → 0
        assert len(s["dimensions"]) == 4

    def test_legacy_preserves_v24_behaviors(self):
        """旧模型用户示例场景仍为 -10 低危（回归）。"""
        ctx = _ctx(
            agents=[_analyst(verdict="malicious", confidence=0.85), _intel(verdict="suspicious")],
            ip="10.0.0.5",
            event_history=[],
        )
        s = RiskScorer.score(ctx, config={"risk_model": {"enabled": False}})
        assert s["risk_score"] == -10
        assert s["risk_level"] == "低危"

    def test_legacy_level_high(self):
        """旧模型：行为+35 + 情报+40 + 信誉+30 → 105 高危（可超 100，无界语义）。"""
        ctx = _ctx(
            agents=[_analyst("malicious", 0.9), _intel("malicious", 0.9, coverage=1.0)],
            ip="45.33.32.156",
            event_history=[{"severity": "高危", "status": "open"}],
        )
        s = RiskScorer.score(ctx, config={"risk_model": {"enabled": False}})
        assert s["risk_score"] == 105
        assert s["risk_level"] == "高危"

    def test_weights_param_passed_through(self):
        """门面支持显式 weights 覆盖（仅加权模型生效）。"""
        ctx = {
            "fusion_result": {
                "engine": "dempster_shafer",
                "verdict": {"verdict": "malicious", "belief_malicious": 0.93,
                            "belief_benign": 0.0, "belief_unknown": 0.07,
                            "confidence": 0.93},
            },
            "evidence_packages": [{
                "agent_id": "intel-001", "coverage": 1.0, "missing_sources": [],
            }],
            "agent_results": [], "ip": "45.33.32.156", "event_history": None,
        }
        base = RiskScorer.score(ctx)
        boosted = RiskScorer.score(ctx, weights={
            "behavior": 0.20, "intel": 0.50, "asset": 0.20, "context": 0.10,
        })
        assert boosted["risk_score"] >= base["risk_score"]

    def test_facade_legacy_rules_hit(self):
        cfg = {"risk_model": {"enabled": False}}
        s = RiskScorer.score(_ctx(
            agents=[_analyst("malicious", 0.9), _intel("suspicious")],
            ip="10.0.0.5", event_history=[],
        ), config=cfg)
        assert set(s["rules_hit"]) == {"RULE-BEH-01", "RULE-INTEL-03", "RULE-IP-02", "RULE-REP-04"}
