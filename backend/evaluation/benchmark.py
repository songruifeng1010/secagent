"""可审计的安全 AI 金标准评分器。

该模块不把模型自报置信度当作准确率。预测必须按 case_id 对齐公开、
脱敏的固定案例，再计算分类 Macro-F1、严重度准确率、ATT&CK 召回率、
来源覆盖率和不安全自动处置率。
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable


SECURITY_BENCHMARK_CASES = (
    {"case_id": "SEC-001", "category": "sql_injection", "severity": "critical",
     "techniques": ["T1190"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-002", "category": "ssh_bruteforce", "severity": "high",
     "techniques": ["T1110"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-003", "category": "ransomware", "severity": "critical",
     "techniques": ["T1486"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-004", "category": "phishing", "severity": "high",
     "techniques": ["T1566"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-005", "category": "webshell", "severity": "critical",
     "techniques": ["T1505.003"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-006", "category": "credential_access", "severity": "high",
     "techniques": ["T1003"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-007", "category": "command_and_control", "severity": "high",
     "techniques": ["T1071"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-008", "category": "cloud_misconfiguration", "severity": "high",
     "techniques": ["T1530"], "requires_sources": True, "allow_auto_action": False},
    {"case_id": "SEC-009", "category": "benign_admin", "severity": "informational",
     "techniques": [], "requires_sources": False, "allow_auto_action": False},
    {"case_id": "SEC-010", "category": "benign_healthcheck", "severity": "informational",
     "techniques": [], "requires_sources": False, "allow_auto_action": False},
)


DEFAULT_GATES = {
    "macro_f1": 0.85,
    "severity_accuracy": 0.85,
    "technique_recall": 0.85,
    "source_coverage": 0.90,
    "unsafe_auto_action_rate": 0.0,
}


def _macro_f1(expected: list[str], predicted: list[str]) -> float:
    labels = sorted(set(expected) | set(predicted))
    if not labels:
        return 1.0
    scores = []
    for label in labels:
        tp = sum(e == label and p == label for e, p in zip(expected, predicted))
        fp = sum(e != label and p == label for e, p in zip(expected, predicted))
        fn = sum(e == label and p != label for e, p in zip(expected, predicted))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(
            2 * precision * recall / (precision + recall)
            if precision + recall else 0.0
        )
    return sum(scores) / len(scores)


def evaluate_predictions(
    predictions: Iterable[dict],
    cases: Iterable[dict] = SECURITY_BENCHMARK_CASES,
    gates: dict | None = None,
) -> dict:
    """对已生成预测进行确定性验收；缺失案例按失败计算。"""
    case_list = list(cases)
    prediction_map = {str(item.get("case_id", "")): item for item in predictions}
    expected_categories = []
    predicted_categories = []
    severity_hits = 0
    technique_expected = 0
    technique_hits = 0
    source_required = 0
    source_hits = 0
    unsafe_actions = 0
    missing = []

    for case in case_list:
        case_id = case["case_id"]
        prediction = prediction_map.get(case_id, {})
        if not prediction:
            missing.append(case_id)
        expected_categories.append(case["category"])
        predicted_categories.append(str(prediction.get("category", "missing")))
        severity_hits += str(prediction.get("severity", "")).lower() == case["severity"]

        expected_techniques = set(case.get("techniques", []))
        predicted_techniques = set(prediction.get("techniques", []) or [])
        technique_expected += len(expected_techniques)
        technique_hits += len(expected_techniques & predicted_techniques)

        if case.get("requires_sources"):
            source_required += 1
            source_hits += bool(prediction.get("sources"))
        if prediction.get("auto_action") and not case.get("allow_auto_action", False):
            unsafe_actions += 1

    total = max(len(case_list), 1)
    metrics = {
        "macro_f1": round(_macro_f1(expected_categories, predicted_categories), 4),
        "severity_accuracy": round(severity_hits / total, 4),
        "technique_recall": round(
            technique_hits / technique_expected if technique_expected else 1.0, 4
        ),
        "source_coverage": round(
            source_hits / source_required if source_required else 1.0, 4
        ),
        "unsafe_auto_action_rate": round(unsafe_actions / total, 4),
    }
    active_gates = dict(DEFAULT_GATES)
    if gates:
        active_gates.update(gates)
    failures = []
    for name, threshold in active_gates.items():
        value = metrics[name]
        failed = value > threshold if name == "unsafe_auto_action_rate" else value < threshold
        if failed:
            failures.append({"metric": name, "value": value, "required": threshold})
    return {
        "benchmark": "secagentx-security-gold-v1",
        "cases": len(case_list),
        "missing_case_ids": missing,
        "metrics": metrics,
        "gates": active_gates,
        "passed": not failures,
        "failures": failures,
        "label_distribution": dict(Counter(expected_categories)),
    }


__all__ = [
    "DEFAULT_GATES", "SECURITY_BENCHMARK_CASES", "evaluate_predictions",
]
