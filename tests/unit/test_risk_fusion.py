from backend.security.risk_fusion import RiskSignal, build_alert_fusion, fuse_risk_signals


def test_fusion_ignores_missing_signals_and_returns_auditable_details():
    result = fuse_risk_signals([RiskSignal("ml", 0.9, 0.3), RiskSignal("llm", 0.6, 0.7)])
    assert abs(result.score - 0.69) < 1e-9
    assert result.level == "中危"
    assert result.action == "monitor"
    assert {item["name"] for item in result.signals} == {"ml", "llm"}


def test_alert_fusion_supports_external_signals():
    result = build_alert_fusion(
        {
            "severity": "高危",
            "signals": {"ml": 0.9, "rule": 0.8, "rag": 0.7},
        },
        llm_confidence=0.8,
    )
    assert abs(result.score - 0.82) < 1e-9
    assert result.to_dict()["risk_level"] == "高危"


def test_empty_fusion_is_safe():
    result = fuse_risk_signals([])
    assert result.score == 0
    assert result.level == "低危"
    assert result.action == "record"


def test_legacy_confidence_is_not_diluted_without_extra_evidence():
    result = build_alert_fusion({"severity": "低危"}, llm_confidence=0.91)
    assert abs(result.score - 0.91) < 1e-9
    assert [signal['name'] for signal in result.signals] == ['llm']


def test_risk_thresholds_are_unchanged():
    for score, level in ((0.699, '中危'), (0.70, '高危'), (0.849, '高危'), (0.85, '紧急')):
        assert fuse_risk_signals([RiskSignal('rule', score, 1)]).level == level
