"""
Decision Fusion 决策融合模块 — 统一决策框架（Sense-Decide 分离）

职责:
  - 各专业 Agent（感知层）只输出证据包 EvidencePackage
  - Decision Fusion（决策层）统一裁决 → 唯一 final verdict
  - 融合引擎为可替换模块（接口见 base.py）

用法:
    from backend.decision_fusion import FusionEngineFactory
    engine = FusionEngineFactory.get_engine("dempster_shafer", config={...})
    result = engine.fuse(evidence_packages)   # -> FusionResult

引擎注册表:
  - dempster_shafer   （默认，DS 证据理论，支持未知/冲突）
  - weighted_average  （参考实现 / 兜底）
"""
from .base import DecisionFusionEngine, FusionEngineFactory, DEFAULT_AGENT_WEIGHTS
from .dempster_shafer import DempsterShaferEngine
from .weighted_average import WeightedAverageEngine
from ..models.output import (
    EvidencePackage, EvidenceMass, FusionConflict, FusionResult,
    FusionVerdict, Finding, build_evidence_package, build_fusion_result,
)

__all__ = [
    "DecisionFusionEngine", "FusionEngineFactory", "DEFAULT_AGENT_WEIGHTS",
    "DempsterShaferEngine", "WeightedAverageEngine",
    "EvidencePackage", "EvidenceMass", "FusionConflict", "FusionResult",
    "FusionVerdict", "Finding", "build_evidence_package", "build_fusion_result",
]

