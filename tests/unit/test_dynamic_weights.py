"""
动态权重引擎（v3.1 / M1）单元测试

覆盖:
  - 默认权重不变（未开启动态时 40/30/20/10）
  - 动态权重开关生效（weights_dynamic 标记 + weight_adjustments 审计明细）
  - 情报覆盖度调节: 覆盖不足 → 情报降权、行为升权（证据转移）
  - 独立情报源≥3 → 情报升权
  - 情报失败 → 大幅降权
  - 资产画像完整度调节
  - 上下文线索丰富度调节
  - 范围保护 clamp + 归一化 ΣW=1
  - 确定性: 同输入多次一致
  - 兼容: 显式 weights 参数 + dynamic 同时使用
"""

import pytest

from backend.orchestrator.risk_model import (
    WeightedRiskScorer, DEFAULT_WEIGHTS,
)
from backend.orchestrator.dynamic_weights import (
    DynamicWeightEngine, RULES,
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
         ip_info=None, agent_results=None, independent_sources=0):
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
            "independent_sources": independent_sources,
        })
    if fusion is not None:
        ctx["fusion_result"] = fusion
    ctx["evidence_packages"] = evidence_packages
    return ctx


def _malicious_ctx(intel_coverage=1.0, asset=None, independent_sources=0):
    """行为+情报全恶意 -> 高分。"""
    return _ctx(
        fusion=_fusion(belief_mal=0.93, belief_unk=0.07,
                       verdict="malicious", confidence=0.93),
        intel_coverage=intel_coverage,
        asset=asset, independent_sources=independent_sources,
    )


# ═══════════════════════ 默认行为（不破坏兼容） ═══════════════════════

class TestBackwardCompat:
    def test_default_weights_unchanged_when_dynamic_off(self):
        """未开启动态权重 -> 权重保持 38/28/20/9/5（v2.7 P2-2 含 knowledge 维度）。"""
        s = WeightedRiskScorer.score(_malicious_ctx())
        assert "weights_dynamic" not in s or s["weights_dynamic"] is False
        assert s["weights"]["behavior"] == pytest.approx(0.38)
        assert s["weights"]["intel"] == pytest.approx(0.28)
        assert s["weights"]["asset"] == pytest.approx(0.20)
        assert s["weights"]["context"] == pytest.approx(0.09)
        assert s["weights"]["knowledge"] == pytest.approx(0.05)

    def test_dynamic_flag_marks_output(self):
        """开启动态权重 -> weights_dynamic=True + weight_adjustments 存在。"""
        s = WeightedRiskScorer.score(_malicious_ctx(), dynamic_weights=True)
        assert s["weights_dynamic"] is True
        # 全覆盖且独立源<3 的情报维度无调节记录；其余三维各至少一条
        assert len(s["weight_adjustments"]) >= 3


# ═══════════════════════ 确定性 & 归一化 ═══════════════════════

class TestDeterminismAndNormalization:
    def test_weights_sum_to_one(self):
        s = WeightedRiskScorer.score(_malicious_ctx(), dynamic_weights=True)
        total = sum(s["weights"].values())
        assert total == pytest.approx(1.0)

    def test_deterministic(self):
        ctx = _malicious_ctx()
        w1 = WeightedRiskScorer.score(ctx, dynamic_weights=True)["weights"]
        w2 = WeightedRiskScorer.score(ctx, dynamic_weights=True)["weights"]
        assert w1 == w2

    def test_all_dimensions_present(self):
        s = WeightedRiskScorer.score(_malicious_ctx(), dynamic_weights=True)
        assert set(s["weights"].keys()) == set(DEFAULT_WEIGHTS.keys())


# ═══════════════════════ 情报覆盖度调节 ═══════════════════════

class TestIntelCoverageAdjustment:
    def test_full_coverage_intel_kept(self):
        """全覆盖 + 独立源<3 -> 情报权重不升不降（无 RULE-DYN-INTEL-0x 降权记录）。"""
        s = WeightedRiskScorer.score(
            _malicious_ctx(intel_coverage=1.0, independent_sources=0),
            dynamic_weights=True,
        )
        intel_rules = [a["rule_id"] for a in s["weight_adjustments"]
                       if a["dimension"] == "intel"]
        # 全覆盖场景下情报维度不应出现"覆盖不足"类降权
        assert not any(r in intel_rules for r in (
            "RULE-DYN-INTEL-01", "RULE-DYN-INTEL-02", "RULE-DYN-INTEL-03",
            "RULE-DYN-INTEL-04", "RULE-DYN-INTEL-05",
        ))

    def test_low_coverage_reduces_intel_weight(self):
        """覆盖严重不足(<33%) -> 情报权重低于静态 30%，且行为升权（证据转移）。"""
        s = WeightedRiskScorer.score(
            _malicious_ctx(intel_coverage=0.2),
            dynamic_weights=True,
        )
        assert s["weights"]["intel"] < 0.30
        assert s["weights"]["behavior"] > 0.40
        # 审计: 存在覆盖不足降权记录
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-INTEL-01" in rules
        assert "RULE-DYN-BEH-04" in rules  # 证据转移

    def test_mid_coverage_reduces_intel(self):
        """覆盖不足(33%~50%) -> 情报降权。"""
        s = WeightedRiskScorer.score(
            _malicious_ctx(intel_coverage=0.4),
            dynamic_weights=True,
        )
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-INTEL-02" in rules

    def test_missing_coverage_reduces_intel(self):
        """情报未查询（coverage=None）-> 按未知降权（缺失≠干净）。"""
        ctx = _malicious_ctx()
        ctx.pop("evidence_packages", None)
        s = WeightedRiskScorer.score(ctx, dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-INTEL-04" in rules
        assert s["weights"]["intel"] < 0.30

    def test_independent_sources_boost(self):
        """独立情报源≥3 -> 情报升权（交叉验证增强）。"""
        low = WeightedRiskScorer.score(
            _malicious_ctx(intel_coverage=1.0, independent_sources=0),
            dynamic_weights=True,
        )
        high = WeightedRiskScorer.score(
            _malicious_ctx(intel_coverage=1.0, independent_sources=3),
            dynamic_weights=True,
        )
        assert high["weights"]["intel"] > low["weights"]["intel"]
        rules = [a["rule_id"] for a in high["weight_adjustments"]]
        assert "RULE-DYN-INTEL-06" in rules

    def test_intel_failed_reduces_heavily(self):
        """情报查询失败 -> 大幅降权。"""
        ctx = _ctx(
            fusion=_fusion(belief_mal=0.93, belief_unk=0.07,
                           verdict="malicious", confidence=0.93),
            agent_results=[
                {"agent_id": "intel-001", "failed": True,
                 "coverage": None, "missing_sources": [], "independent_sources": 0},
            ],
        )
        s = WeightedRiskScorer.score(ctx, dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-INTEL-05" in rules
        assert s["weights"]["intel"] < 0.30


# ═══════════════════════ 行为/资产/上下文调节 ═══════════════════════

class TestOtherDimensions:
    def test_behavior_unknown_reduced(self):
        """行为证据未知 -> 行为降权。"""
        s = WeightedRiskScorer.score({}, dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-BEH-02" in rules

    def test_behavior_clear_boosted(self):
        """行为证据明确 -> 轻微升权。"""
        s = WeightedRiskScorer.score(_malicious_ctx(), dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-BEH-01" in rules

    def test_behavior_failed_reduced(self):
        """行为分析失败 -> 大幅降权。"""
        ctx = _ctx(
            agent_results=[
                {"agent_id": "analyst-001", "failed": True,
                 "verdict": None, "confidence": None},
            ],
        )
        s = WeightedRiskScorer.score(ctx, dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-BEH-03" in rules
        assert s["weights"]["behavior"] < 0.40

    def test_asset_complete_boosted(self):
        """资产画像完整（价值+暴露+敏感数据）-> 资产升权。"""
        complete = WeightedRiskScorer.score(
            _malicious_ctx(asset={"criticality": "critical", "exposed": True,
                                  "contains_pii": True}),
            dynamic_weights=True,
        )
        rules = [a["rule_id"] for a in complete["weight_adjustments"]]
        assert "RULE-DYN-ASSET-01" in rules
        assert complete["weights"]["asset"] > 0.20

    def test_asset_missing_reduced(self):
        """无资产画像 -> 资产降权（未知不当作高价值）。"""
        s = WeightedRiskScorer.score(_malicious_ctx(asset=None), dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-ASSET-03" in rules
        assert s["weights"]["asset"] < 0.20

    def test_context_rich_boosted(self):
        """上下文线索≥3 -> 上下文升权。"""
        ctx = _ctx(
            fusion=_fusion(belief_mal=0.93, verdict="malicious", confidence=0.93),
            intel_coverage=1.0,
            event_history=[{"severity": "高危", "status": "open"}],
            alert_meta={"severity": "高危", "mitre_tactic": "T1566"},
            ip_info={"org": "VPN Proxy Service"},
        )
        s = WeightedRiskScorer.score(ctx, dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-CTX-01" in rules

    def test_context_missing_reduced(self):
        """无上下文线索 -> 上下文降权。"""
        s = WeightedRiskScorer.score(_malicious_ctx(), dynamic_weights=True)
        rules = [a["rule_id"] for a in s["weight_adjustments"]]
        assert "RULE-DYN-CTX-03" in rules
        assert s["weights"]["context"] < 0.10


# ═══════════════════════ 范围保护 & 组合 ═══════════════════════

class TestRangeProtection:
    def test_weights_within_bounds(self):
        """极端场景下权重仍在 [min, max] 内。"""
        # 全未知 + 情报失败 + 行为失败 -> 权重剧烈变化
        ctx = _ctx(
            agent_results=[
                {"agent_id": "analyst-001", "failed": True},
                {"agent_id": "intel-001", "failed": True},
            ],
        )
        s = WeightedRiskScorer.score(ctx, dynamic_weights=True)
        for v in s["weights"].values():
            assert 0.05 <= v <= 0.70

    def test_custom_weights_with_dynamic(self):
        """显式 weights + 动态权重同时使用：自定义权重为基线。"""
        s = WeightedRiskScorer.score(
            _malicious_ctx(intel_coverage=0.2),
            weights={"behavior": 0.5, "intel": 0.2, "asset": 0.2, "context": 0.1},
            dynamic_weights=True,
        )
        # 情报覆盖不足 -> intel 应低于其基线 0.20
        assert s["weights"]["intel"] < 0.20

    def test_each_adjustment_has_audit_fields(self):
        """每条调节记录含完整审计字段（dimension/base_weight/factor/rule_id/reason）。"""
        s = WeightedRiskScorer.score(_malicious_ctx(intel_coverage=0.2), dynamic_weights=True)
        for a in s["weight_adjustments"]:
            assert a["dimension"]
            assert isinstance(a["base_weight"], (int, float))
            assert isinstance(a["factor"], (int, float))
            assert a["rule_id"].startswith("RULE-DYN-")
            assert a["reason"]
            assert isinstance(a["adjusted_weight"], (int, float))


# ═══════════════════════ 引擎直接单测 ═══════════════════════

class TestEngineDirect:
    def test_engine_compute_structure(self):
        result = DynamicWeightEngine.compute(_malicious_ctx(), config={
            "min_weight": 0.05, "max_weight": 0.70,
        })
        assert set(result["weights"].keys()) == set(DEFAULT_WEIGHTS.keys())
        assert sum(result["weights"].values()) == pytest.approx(1.0)
        assert isinstance(result["adjustments"], list)
        assert result["enabled"] is True

    def test_rule_table_sanity(self):
        """规则表 16 条，维度均在四维内，因子在合理范围。"""
        assert len(RULES) == 16
        for rule_id, (dim, factor, reason) in RULES.items():
            assert dim in DEFAULT_WEIGHTS
            assert 0.3 <= factor <= 1.2
            assert reason
            assert rule_id.startswith("RULE-DYN-")
