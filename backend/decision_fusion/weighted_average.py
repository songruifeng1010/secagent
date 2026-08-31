"""
WeightedAverageEngine — 加权平均融合引擎（可替换模块的参考实现 / 兜底）

与 Dempster-Shafer 的差异：
  - 不显式建模"未知"：直接对 leaning 数值加权平均
  - 适用场景：作为 DS 引擎异常时的降级，或对照实验
  - 输出结构完全一致（FusionResult），上层无需改动
"""
import logging
from typing import Optional

from ..models.output import (
    EvidencePackage, FusionResult, FusionVerdict, EvidenceMass,
    FusionConflict, build_fusion_result,
)
from .base import DecisionFusionEngine, FusionEngineFactory

logger = logging.getLogger("secagentx.decision_fusion")

VERDICT_WEIGHTS = {"malicious": 1.0, "suspicious": 0.6, "unknown": 0.4, "benign": 0.0}
HIGH = 0.7
MID = 0.4


class WeightedAverageEngine(DecisionFusionEngine):
    """加权平均融合引擎 — 参考实现。"""

    name = "weighted_average"

    def fuse(self, evidence_packages: list[EvidencePackage]) -> FusionResult:
        if not evidence_packages:
            return self._empty_result()

        scored = self._normalize_weights(evidence_packages)
        active = [(p, w) for p, w in scored if w > 0]
        if not active:
            return self._empty_result()

        weighted = 0.0
        total_w = 0.0
        mass_list = []
        for p, w in active:
            try:
                lean_str = str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning)
            except Exception:
                lean_str = "unknown"
            val = VERDICT_WEIGHTS.get(lean_str, 0.4)
            weighted += val * w
            total_w += w
            mass_list.append({
                "agent_id": p.agent_id, "weight": w,
                "m_mal": (val * w), "m_ben": (1 - val) * w * 0, "m_unknown": (1 - val) * w,
            })

        avg = weighted / total_w if total_w else 0.0
        if avg >= HIGH:
            verdict, risk, action = "malicious", "高危", "block"
        elif avg <= 1 - HIGH:
            verdict, risk, action = "benign", "低危", "none"
        elif avg >= MID:
            verdict, risk, action = "suspicious", "中危", "escalate"
        else:
            verdict, risk, action = "unknown", "低危", "escalate"

        # 检测冲突（leaning 矛盾）
        conflicts = []
        leans = [str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning)
                 for p, _ in active]
        mal = [i for i, l in enumerate(leans) if l == "malicious"]
        ben = [i for i, l in enumerate(leans) if l == "benign"]
        if mal and ben:
            conflicts.append(FusionConflict(
                between=f"{active[mal[0]][0].agent_id} vs {active[ben[0]][0].agent_id}",
                coefficient=0.8,
                leaning_a="malicious", leaning_b="benign",
                resolution="malicious 与 benign 冲突，需人工复核",
            ))

        evidence_masses = [
            EvidenceMass(
                agent_id=p.agent_id, agent_name=p.agent_name,
                weight=round(w, 4),
                belief=round(VERDICT_WEIGHTS.get(
                    str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning),
                    0.4) * w, 4),
                plausibility=round(VERDICT_WEIGHTS.get(
                    str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning),
                    0.4) * w, 4),
                leaning=str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning),
                degraded=p.degraded, failed=p.failed,
            )
            for p, w in active
        ]

        path = [
            {"step": 1, "desc": f"加权平均融合 {len(active)} 个证据包", "tag": "evidence"},
            {"step": 2, "desc": f"加权得分 {avg:.0%} → 裁决 {verdict}", "tag": "fusion"},
        ]
        if conflicts:
            path.append({"step": 3, "desc": "检测到冲突，标记需人工", "tag": "conflict"})

        needs_human = bool(conflicts) or verdict == "unknown"
        return build_fusion_result(
            engine=self.name, method=self.name, status="completed",
            verdict=FusionVerdict(
                verdict=verdict, belief_malicious=round(avg, 4),
                belief_benign=round(1 - avg, 4), belief_unknown=0.0,
                risk_probability=round(avg, 4),   # 加权平均：概率=平均恶意得分
                confidence=round(avg, 4), risk_level=risk,
                recommended_action=action, needs_human=needs_human,
            ),
            conflict_coefficient=round(0.8 if conflicts else 0.0, 4),
            conflicts=conflicts,
            evidence_masses=evidence_masses,
            decision_path=path,
            risk_score=0,
            agent_count=len(active),
            evidence_count=sum(len(p.findings or []) for p, _ in active),
        )

    def _empty_result(self) -> FusionResult:
        verdict = FusionVerdict(
            verdict="unknown", belief_malicious=0.0, belief_benign=0.0,
            belief_unknown=1.0, risk_probability=0.0, confidence=0.3,
            risk_level="低危",
            recommended_action="escalate", needs_human=True,
        )
        return build_fusion_result(
            engine=self.name, method=self.name, status="completed",
            verdict=verdict, conflict_coefficient=0.0,
            conflicts=[], evidence_masses=[],
            decision_path=[{"step": 1, "desc": "无有效证据", "tag": "decision"}],
            risk_score=0, agent_count=0, evidence_count=0,
        )


FusionEngineFactory.register(WeightedAverageEngine.name, WeightedAverageEngine)


__all__ = ["WeightedAverageEngine"]

