"""多信号风险融合。

统一把规则、机器学习、RAG/情报和 LLM 裁决转换为 0~1 风险分数。
该模块只负责确定性计算，不执行封禁等副作用操作；处置仍由
``AutoIngestor`` 的阈值和人工确认策略控制。
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable


@dataclass(frozen=True)
class RiskSignal:
    """一个可审计的风险信号。"""

    name: str
    score: float
    weight: float
    source: str = ""

    def normalized(self) -> "RiskSignal":
        return RiskSignal(
            name=self.name,
            score=min(1.0, max(0.0, float(self.score))),
            weight=max(0.0, float(self.weight)),
            source=self.source,
        )


@dataclass(frozen=True)
class FusionResult:
    score: float
    level: str
    action: str
    signals: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": round(self.score, 4),
            "risk_level": self.level,
            "recommended_action": self.action,
            "signals": list(self.signals),
        }


def _level(score: float) -> str:
    if score >= 0.85:
        return "紧急"
    if score >= 0.70:
        return "高危"
    if score >= 0.40:
        return "中危"
    return "低危"


def _action(score: float) -> str:
    if score >= 0.85:
        return "block_review"
    if score >= 0.70:
        return "manual_confirm"
    if score >= 0.40:
        return "monitor"
    return "record"


def fuse_risk_signals(signals: Iterable[RiskSignal]) -> FusionResult:
    """按有效权重计算加权风险分数。

    缺失信号不参与分母；因此只提供 LLM 或只提供 ML 时不会被默认的
    0 分信号稀释。没有任何有效信号时返回 0 分并建议记录。
    """
    normalized = [signal.normalized() for signal in signals]
    usable = [signal for signal in normalized if signal.weight > 0]
    weight_sum = sum(signal.weight for signal in usable)
    score = (
        sum(signal.score * signal.weight for signal in usable) / weight_sum
        if weight_sum
        else 0.0
    )
    return FusionResult(
        score=min(1.0, max(0.0, score)),
        level=_level(score),
        action=_action(score),
        signals=tuple(asdict(signal) for signal in usable),
    )


def build_alert_fusion(alert: dict, llm_confidence: float | None) -> FusionResult:
    """从标准化告警构建融合结果。

    Webhook 可通过 ``signals`` 提供 ``ml``、``rule``、``rag``、``llm`` 四类
    信号；未提供时仅使用 LLM 置信度和告警严重度，保持向后兼容。
    """
    raw_signals = alert.get("signals") or {}
    if not isinstance(raw_signals, dict):
        raw_signals = {}
    signals: list[RiskSignal] = []
    weights = {"llm": 0.40, "ml": 0.30, "rule": 0.20, "rag": 0.10}
    for name, weight in weights.items():
        value = raw_signals.get(name)
        if name == "llm" and value is None:
            value = llm_confidence
        if isinstance(value, (int, float)):
            signals.append(RiskSignal(name=name, score=float(value), weight=weight, source="alert"))

    if not signals:
        return fuse_risk_signals([])

    # 未提供额外证据时保留旧版 LLM 置信度，不用默认低危等级稀释它。
    if all(signal.name == "llm" for signal in signals):
        return fuse_risk_signals(signals)

    if not any(signal.name == "rule" for signal in signals):
        severity_map = {"低危": 0.20, "中危": 0.45, "高危": 0.70, "紧急": 0.90}
        severity = str(alert.get("severity") or "低危").strip()
        signals.append(RiskSignal(name="severity", score=severity_map.get(severity, 0.30), weight=0.10, source="severity"))

    return fuse_risk_signals(signals)
