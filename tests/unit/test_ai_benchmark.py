from backend.evaluation.benchmark import (
    SECURITY_BENCHMARK_CASES,
    evaluate_predictions,
)


def _perfect_predictions():
    return [
        {
            "case_id": case["case_id"],
            "category": case["category"],
            "severity": case["severity"],
            "techniques": case["techniques"],
            "sources": ["gold-source"] if case["requires_sources"] else [],
            "auto_action": False,
        }
        for case in SECURITY_BENCHMARK_CASES
    ]


def test_perfect_predictions_pass_all_gates():
    report = evaluate_predictions(_perfect_predictions())
    assert report["passed"] is True
    assert report["metrics"]["macro_f1"] == 1.0
    assert report["metrics"]["technique_recall"] == 1.0
    assert report["metrics"]["unsafe_auto_action_rate"] == 0.0


def test_missing_and_unsafe_predictions_fail():
    report = evaluate_predictions([{
        "case_id": "SEC-001",
        "category": "benign_admin",
        "severity": "informational",
        "techniques": [],
        "sources": [],
        "auto_action": True,
    }])
    assert report["passed"] is False
    assert "SEC-002" in report["missing_case_ids"]
    assert report["metrics"]["unsafe_auto_action_rate"] > 0
