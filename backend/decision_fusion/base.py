"""
DecisionFusionEngine — 决策融合引擎抽象接口（可替换模块）

设计目标（Sense-Decide 分离）:
  1. 各专业 Agent 只输出证据包（EvidencePackage），不直接裁决风险
  2. Decision Fusion 统一裁决 → 唯一 final verdict
  3. 引擎是可替换模块：通过工厂按名称注册/切换，默认 Dempster-Shafer

接入新引擎步骤:
  1. 继承 DecisionFusionEngine，实现 fuse()
  2. 在 FusionEngineFactory._ENGINES 注册（或在运行时 register）
  3. 配置 config.yaml: decision_fusion.engine = "你的引擎名"

所有引擎输出统一 FusionResult（见 backend/models/output.py），
上层（react_loop / RiskScorer / 前端）不感知具体算法。
"""
from abc import ABC, abstractmethod
from typing import Optional

from ..models.output import (
    EvidencePackage, FusionResult, build_fusion_result,
)

# ── 各 Agent 的固定基础权重（与 react_loop.CONFIDENCE_WEIGHTS 对齐） ──
DEFAULT_AGENT_WEIGHTS = {
    "analyst-001": 0.35,
    "intel-001": 0.25,
    "responder-001": 0.20,
    "alert-filter-001": 0.10,
    "knowledge-001": 0.10,
}


class DecisionFusionEngine(ABC):
    """决策融合引擎抽象基类 — 可替换模块接口。

    子类只需实现 fuse()；其余辅助方法（权重归一化等）可直接复用。
    """

    #: 引擎唯一标识（config 中 decision_fusion.engine 引用此名称）
    name: str = "base"

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.agent_weights = dict(DEFAULT_AGENT_WEIGHTS)
        self.agent_weights.update(self.config.get("agent_weights", {}) or {})

    @abstractmethod
    def fuse(self, evidence_packages: list[EvidencePackage]) -> FusionResult:
        """融合所有证据包，产出唯一权威裁决。

        Args:
            evidence_packages: 各 Agent 证据包（已标准化）

        Returns:
            FusionResult（verdict/confidence/conflicts/decision_path ...）
        """
        ...

    # ── 共享辅助 ──

    def _weight_for(self, agent_id: str, degraded: bool = False) -> float:
        """获取 Agent 基础权重（降级折半，与既有纪律一致）。"""
        w = self.agent_weights.get(agent_id, 0.0)
        if degraded:
            w *= 0.5
        return w

    def _normalize_weights(self, packages: list[EvidencePackage]) -> list[tuple[EvidencePackage, float]]:
        """为每个证据包计算归一化权重（基础权重 × 证据可靠度）。

        规则:
          - failed 包权重 = 0（不参与融合，但记录）
          - 无结构化裁决（evidence_confidence 接近默认且无 findings）→ 权重打折
        """
        scored = []
        for p in packages:
            if p.failed:
                scored.append((p, 0.0))
                continue
            base = self._weight_for(p.agent_id, p.degraded)
            # 证据可靠度：findings 均值 / evidence_confidence
            ev_conf = p.evidence_confidence
            if ev_conf <= 0.0:
                ev_conf = 0.5
            scored.append((p, base * ev_conf))
        total = sum(w for _, w in scored)
        if total <= 0:
            return [(p, 0.0) for p in packages]
        return [(p, w / total) for p, w in scored]


# ═══════════════════════ 引擎工厂（可替换模块注册表） ═══════════════════════

class FusionEngineFactory:
    """决策融合引擎工厂 — 按名称获取引擎实例。

    默认注册 dempster_shafer；可调用 register() 注册自定义引擎。
    """

    _ENGINES: dict[str, type] = {}

    @classmethod
    def register(cls, name: str, engine_cls: type) -> None:
        cls._ENGINES[name] = engine_cls

    @classmethod
    def get_engine(cls, name: str = "dempster_shafer",
                   config: Optional[dict] = None) -> "DecisionFusionEngine":
        """获取引擎实例；未知名称抛 ValueError（配置错误要尽早暴露）。"""
        engine_cls = cls._ENGINES.get(name)
        if engine_cls is None:
            raise ValueError(
                f"未知决策融合引擎: {name!r}，可用: {sorted(cls._ENGINES.keys())}"
            )
        return engine_cls(config=config)

    @classmethod
    def available(cls) -> list[str]:
        return sorted(cls._ENGINES.keys())


__all__ = [
    "DecisionFusionEngine", "FusionEngineFactory",
    "DEFAULT_AGENT_WEIGHTS",
]

