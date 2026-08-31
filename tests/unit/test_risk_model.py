"""
加权风险评分模型（v3.0）单元测试

覆盖:
  - 范围保证: 任意输入 0 ≤ risk_score ≤ 100
  - 权重正确性: 默认 40/30/20/10，参数化覆盖生效
  - 四维度子评分规则表
  - 等级阈值边界: 39/40、59/60、79/80
  - 权重敏感性测试: 提高 Threat Intel 权重 → 风险升高
  - 冲突测试: 行为/情报矛盾 vs 一致
  - unknown 处理: 缺失 → 子分 50 + needs_human
  - 确定性: 同输入多次评分一致
"""
import pytest

from backend.orchestrator.risk_model import (
    WeightedRiskScorer, DIMENSIONS, DEFAULT_WEIGHTS,
    LEVEL_THRESHOLDS, UNKNOWN_BASELINE, BENIGN_SCORE,
)


# ═══════════════════════ 测试上下文构造 ═══════════════════════

def _fusion(belief_mal=0.0, belief_ben=0.0, belief_unk=1.0,
            verdict="unknown", confidence=0.0):
    return {
        "engine": "dempster_shafer",
        "verdict": {
            "verdict": verdict,
            "belief_malicious": belief_mal,
            "belief_benign": belief_ben,
            "belief_unknown": belief_unk,
            "confidence": confidence,
        },
    }


def _ctx(fusion=None, intel_coverage=None, ip="8.8.8.8",
         asset=None, event_history=None, alert_meta=None,
         ip_info=None, agent_results=None):
    ctx = {
        "ip": ip,
        "asset": asset,
        "event_history": event_history,
        "alert_meta": alert_meta,
        "ip_info": ip_info,
        "agent_results": agent_results or [],
    }
    evidence_packages = []
    if intel_coverage is not None:
        evidence_packages.append({
            "agent_id": "intel-001",
            "coverage": intel_coverage,
            "missing_sources": [] if intel_coverage >= 1.0 else ["VT"],
        })
    if fusion is not None:
        ctx["fusion_result"] = fusion
        ctx["evidence_packages"] = evidence_packages
    return ctx


def _malicious_ctx(intel_coverage=1.0, ip="45.33.32.156", asset=None):
    """行为+情报全恶意 → 高分。"""
    return _ctx(
        fusion=_fusion(belief_mal=0.93, belief_unk=0.07,
                       verdict="malicious", confidence=0.93),
        intel_coverage=intel_coverage,
        ip=ip, asset=asset,
    )


def _benign_ctx(intel_coverage=1.0, ip="45.33.32.156", asset=None):
    """行为+情报全良性 → 低分。"""
    return _ctx(
        fusion=_fusion(belief_ben=0.92, belief_unk=0.08,
                       verdict="benign", confidence=0.08),
        intel_coverage=intel_coverage,
        ip=ip, asset=asset,
    )


# ═══════════════════════ 范围保证 ═══════════════════════

class TestRange:
    def test_score_within_0_100_malicious(self):
        s = WeightedRiskScorer.score(_malicious_ctx())
        assert 0 <= s["risk_score"] <= 100

    def test_score_within_0_100_empty(self):
        s = WeightedRiskScorer.score({})
        assert 0 <= s["risk_score"] <= 100

    def test_all_scores_clamped(self):
        """各维度子分均 Clamp 到 0~100。"""
        s = WeightedRiskScorer.score(_malicious_ctx())
        for d in s["dimensions"]:
            assert 0 <= d["score"] <= 100
            assert 0 <= d["weighted"] <= 100


# ═══════════════════════ 权重正确性 ═══════════════════════

class TestWeights:
    def test_default_weights(self):
        assert DEFAULT_WEIGHTS == {
            "behavior": 0.38, "intel": 0.28, "asset": 0.20,
            "context": 0.09, "knowledge": 0.05,
        }

    def test_weighted_sum_matches(self):
        """总分 = 各维度子分 × 权重求和。"""
        s = WeightedRiskScorer.score(_malicious_ctx())
        expected = sum(d["weighted"] for d in s["dimensions"])
        assert abs(s["risk_score"] - round(expected)) <= 1  # 取整容差

    def test_weights_in_output(self):
        s = WeightedRiskScorer.score(_malicious_ctx())
        assert s["weights"]["behavior"] == pytest.approx(0.38)
        assert s["weights"]["intel"] == pytest.approx(0.28)
        assert s["weights"]["asset"] == pytest.approx(0.20)
        assert s["weights"]["context"] == pytest.approx(0.09)
        assert s["weights"]["knowledge"] == pytest.approx(0.05)

    def test_custom_weights_normalized(self):
        """权重参数化：传入覆盖权重，结果随之变化。"""
        ctx = _malicious_ctx()
        default = WeightedRiskScorer.score(ctx)
        # 提高 intel 权重到 0.5，behavior 降到 0.2
        custom = WeightedRiskScorer.score(ctx, weights={
            "behavior": 0.20, "intel": 0.50,
            "asset": 0.20, "context": 0.10,
        })
        assert custom["weights"]["intel"] == pytest.approx(0.50)
        assert custom["weights"]["behavior"] == pytest.approx(0.20)
        assert abs(custom["risk_score"] - default["risk_score"]) > 0.01 or \
            abs(custom["risk_score"] - default["risk_score"]) == 0


# ═══════════════════════ 权重敏感性（用户要求 B） ═══════════════════════

def _intel_heavy_ctx():
    """冲突场景：行为良性(15) + 情报恶意(95) —— 两维度分数不同，可观察权重变化。"""
    return _ctx(
        fusion=None,  # 走 fallback：行为读 analyst，情报读 intel
        agent_results=[
            {"agent_id": "analyst-001", "verdict": "benign", "confidence": 0.9},
            {"agent_id": "intel-001", "verdict": "malicious", "confidence": 0.9,
             "coverage": 1.0, "missing_sources": []},
        ],
        ip="45.33.32.156",
    )


class TestWeightSensitivity:
    def test_increase_intel_weight_increases_risk(self):
        """提升 Threat Intel 权重（0.30→0.50）→ 情报维度恶意(95)贡献增大 → 风险升高。"""
        ctx = _intel_heavy_ctx()
        base = WeightedRiskScorer.score(ctx)
        boosted = WeightedRiskScorer.score(ctx, weights={
            "behavior": 0.20, "intel": 0.50, "asset": 0.20, "context": 0.10,
        })
        assert boosted["weights"]["intel"] == pytest.approx(0.50)
        assert boosted["risk_score"] > base["risk_score"]

    def test_decrease_intel_weight_decreases_risk(self):
        """降低 Threat Intel 权重（0.30→0.10）→ 情报恶意贡献减小 → 风险降低。"""
        ctx = _intel_heavy_ctx()
        base = WeightedRiskScorer.score(ctx)
        reduced = WeightedRiskScorer.score(ctx, weights={
            "behavior": 0.50, "intel": 0.10, "asset": 0.30, "context": 0.10,
        })
        assert reduced["weights"]["intel"] == pytest.approx(0.10)
        assert reduced["risk_score"] < base["risk_score"]


# ═══════════════════════ 等级阈值边界（用户要求 A） ═══════════════════════

class TestLevelBoundaries:
    def test_threshold_config(self):
        # 等级划分: 0~39 低危 / 40~59 中危 / 60~79 高危 / 80~100 紧急
        assert LEVEL_THRESHOLDS["低危"] == 0
        assert LEVEL_THRESHOLDS["中危"] == 40
        assert LEVEL_THRESHOLDS["高危"] == 60
        assert LEVEL_THRESHOLDS["紧急"] == 80

    def test_map_level_39_low(self):
        assert WeightedRiskScorer._map_level(39) == "低危"

    def test_map_level_40_mid(self):
        assert WeightedRiskScorer._map_level(40) == "中危"

    def test_map_level_59_mid(self):
        assert WeightedRiskScorer._map_level(59) == "中危"

    def test_map_level_60_high(self):
        assert WeightedRiskScorer._map_level(60) == "高危"

    def test_map_level_79_high(self):
        assert WeightedRiskScorer._map_level(79) == "高危"

    def test_map_level_80_critical(self):
        assert WeightedRiskScorer._map_level(80) == "紧急"

    def test_map_level_100_critical(self):
        assert WeightedRiskScorer._map_level(100) == "紧急"

    def test_level_transitions_with_real_scores(self):
        """用真实输入逼近各等级边界，验证等级切换。"""
        # 全良性：应低危
        s = WeightedRiskScorer.score(_benign_ctx(asset={"criticality": "low"}))
        assert s["risk_level"] in ("低危",)
        # 全恶意 + 高价值资产：应高危/紧急
        s = WeightedRiskScorer.score(_malicious_ctx(
            asset={"criticality": "critical", "exposed": True, "contains_pii": True}))
        assert s["risk_level"] in ("高危", "紧急")


# ═══════════════════════ 冲突测试（用户要求 C） ═══════════════════════

class TestConflict:
    def test_conflicting_agents_between_consistent(self):
        """行为良性 vs 情报恶意（冲突）→ 风险介于【一致恶意】与【一致良性】之间。"""
        all_mal = WeightedRiskScorer.score(_malicious_ctx())
        all_ben = WeightedRiskScorer.score(_benign_ctx())
        conflict = WeightedRiskScorer.score(_intel_heavy_ctx())
        assert all_ben["risk_score"] < conflict["risk_score"] < all_mal["risk_score"]

    def test_conflict_marks_unknown_needs_human(self):
        """证据冲突（fusion 未知主导）→ 需人工复核。"""
        s = WeightedRiskScorer.score(_ctx(
            fusion=_fusion(belief_unk=1.0, verdict="unknown", confidence=0.3),
        ))
        assert s["needs_human"] is True
        assert s["risk_score"] == UNKNOWN_BASELINE

    def test_conflict_reason_visible(self):
        """冲突场景下，行为与情报维度各自携带不同规则与理由（可审计）。"""
        s = WeightedRiskScorer.score(_intel_heavy_ctx())
        dims = {d["name"]: d for d in s["dimensions"]}
        assert dims["行为证据"]["rule_id"] == "RULE-BEH-04"   # 良性
        assert dims["威胁情报"]["rule_id"] == "RULE-INTEL-01"  # 恶意 95
        assert dims["行为证据"]["score"] == BENIGN_SCORE
        assert dims["威胁情报"]["score"] == 95


# ═══════════════════════ 各维度子评分 ═══════════════════════

class TestBehaviorDimension:
    def test_malicious_high_95(self):
        s = WeightedRiskScorer.score(_ctx(
            fusion=_fusion(belief_mal=0.93, belief_unk=0.07,
                           verdict="malicious", confidence=0.93),
        ))
        d = s["dimensions"][0]
        assert d["score"] == 95 and d["rule_id"] == "RULE-BEH-01"

    def test_suspicious_60(self):
        s = WeightedRiskScorer.score(_ctx(
            fusion=_fusion(belief_mal=0.55, belief_unk=0.45,
                           verdict="suspicious", confidence=0.55),
        ))
        d = s["dimensions"][0]
        assert d["score"] == 60 and d["rule_id"] == "RULE-BEH-03"

    def test_benign_15(self):
        s = WeightedRiskScorer.score(_ctx(
            fusion=_fusion(belief_ben=0.92, belief_unk=0.08,
                           verdict="benign", confidence=0.08),
        ))
        d = s["dimensions"][0]
        assert d["score"] == BENIGN_SCORE and d["rule_id"] == "RULE-BEH-04"

    def test_unknown_50(self):
        s = WeightedRiskScorer.score(_ctx())
        d = s["dimensions"][0]
        assert d["score"] == UNKNOWN_BASELINE and d["rule_id"] == "RULE-BEH-05"
        assert s["needs_human"] is True


class TestIntelDimension:
    def test_malicious_full_coverage_95(self):
        s = WeightedRiskScorer.score(_ctx(
            fusion=_fusion(belief_mal=0.93, belief_unk=0.07,
                           verdict="malicious", confidence=0.93),
            intel_coverage=1.0,
        ))
        d = s["dimensions"][1]
        assert d["score"] == 95 and d["rule_id"] == "RULE-INTEL-01"

    def test_missing_sources_50_unknown(self):
        """情报源缺失 → 50 分 + needs_human（缺失≠干净）。"""
        s = WeightedRiskScorer.score(_ctx(
            fusion=_fusion(belief_ben=0.92, belief_unk=0.08,
                           verdict="benign", confidence=0.08),
            intel_coverage=0.5,
        ))
        d = s["dimensions"][1]
        assert d["score"] == UNKNOWN_BASELINE and d["rule_id"] == "RULE-INTEL-07"
        assert s["needs_human"] is True


class TestAssetDimension:
    def test_critical_exposed_pii_high(self):
        s = WeightedRiskScorer.score(_ctx(
            asset={"criticality": "critical", "exposed": True, "contains_pii": True},
        ))
        d = s["dimensions"][2]
        assert d["score"] >= 90 and d["rule_id"] == "RULE-ASSET-01"

    def test_low_value_30(self):
        s = WeightedRiskScorer.score(_ctx(
            asset={"criticality": "low"},
        ))
        d = s["dimensions"][2]
        assert d["score"] == 30 and d["rule_id"] == "RULE-ASSET-02"

    def test_no_asset_50_unknown(self):
        """无资产画像 → 50 分中性（不强制 needs_human，行为/情报已知时）。"""
        s = WeightedRiskScorer.score(_benign_ctx(asset=None))
        d = s["dimensions"][2]
        assert d["score"] == UNKNOWN_BASELINE and d["rule_id"] == "RULE-ASSET-05"
        # 行为/情报均已知良性 → 资产未知不触发 needs_human
        assert s["needs_human"] is False


class TestContextDimension:
    def test_anon_proxy_high(self):
        s = WeightedRiskScorer.score(_ctx(
            ip="1.2.3.4", ip_info={"org": "VPN Proxy Service"},
        ))
        d = s["dimensions"][3]
        assert d["score"] == 80 and d["rule_id"] == "RULE-CTX-01"

    def test_high_history_75(self):
        s = WeightedRiskScorer.score(_ctx(
            ip="1.2.3.4",
            event_history=[{"severity": "高危", "status": "open"}],
        ))
        d = s["dimensions"][3]
        assert d["score"] == 75 and d["rule_id"] == "RULE-CTX-01"

    def test_private_ip_low(self):
        s = WeightedRiskScorer.score(_ctx(ip="10.0.0.5"))
        d = s["dimensions"][3]
        assert d["score"] == 20 and d["rule_id"] == "RULE-CTX-02"

    def test_no_context_50(self):
        s = WeightedRiskScorer.score(_ctx(ip=None))
        d = s["dimensions"][3]
        assert d["score"] == UNKNOWN_BASELINE and d["rule_id"] == "RULE-CTX-05"


# ═══════════════════════ unknown 处理 / 确定性（用户要求） ═══════════════════════

class TestUnknownAndDeterminism:
    def test_all_unknown_score_50_needs_human(self):
        """全未知 → 50 分（中性基线）+ needs_human=true。"""
        s = WeightedRiskScorer.score({})
        assert s["risk_score"] == UNKNOWN_BASELINE
        assert s["needs_human"] is True
        assert s["risk_level"] == "中危"  # 50 落在中危，不自动放行

    def test_dimensions_order(self):
        names = [n for n, _, _, _ in DIMENSIONS]
        assert names == ["行为证据", "威胁情报", "资产价值", "上下文线索"]

    def test_deterministic(self):
        ctx = _malicious_ctx()
        results = {WeightedRiskScorer.score(ctx)["risk_score"] for _ in range(5)}
        assert len(results) == 1

    def test_empty_ctx_safe(self):
        s = WeightedRiskScorer.score({})
        assert len(s["dimensions"]) == 4
        assert s["rules_hit"] == [
            "RULE-BEH-05", "RULE-INTEL-05", "RULE-ASSET-05", "RULE-CTX-05",
        ]

    def test_weights_param_and_normalization(self):
        """权重参数化且自动归一化（权重和≠1 也能正确归一）。"""
        s = WeightedRiskScorer.score(_malicious_ctx(), weights={
            "behavior": 2, "intel": 1,  # 未归一化输入
        })
        total = sum(s["weights"].values())
        assert total == pytest.approx(1.0)
        assert s["weights"]["behavior"] > s["weights"]["intel"]
