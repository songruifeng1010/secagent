"""
DempsterShaferEngine — Dempster-Shafer 证据理论融合引擎（默认实现）

为什么选 DS 而非加权平均：
  - 显式建模"未知 (unknown)"：情报源缺失 / Agent 未裁决 → mass 进入 unknown，
    绝不因"没查到"而把信念分给恶意或良性（项目"缺失≠干净"纪律）
  - 显式量化"冲突"：Dempster 冲突系数 K 直接反映证据间打架程度，
    K 高 → 自动标记 needs_human + 输出冲突记录（可审计）

识别框架:
  Θ = { malicious, benign }
  幂集 2^Θ = { ∅, {malicious}, {benign}, Θ }  (Θ = unknown)

每个证据包 → mass function:
  m({malicious}) = w * lean_mal
  m({benign})    = w * lean_benign
  m(Θ)           = 1 - m(malicious) - m(benign)   （未知质量）
  其中 w 为归一化权重；lean 由 leaning / findings 推导

Dempster 组合规则（两两组合）:
  m12(A) = Σ_{B∩C=A} m1(B)·m2(C) / (1 - K)
  K = Σ_{B∩C=∅} m1(B)·m2(C)      （冲突系数）

决策映射:
  belief(malicious) ≥ 0.7 → malicious
  belief(benign)    ≥ 0.7 → benign
  belief(malicious) ≥ 0.4 → suspicious
  其余 → unknown + needs_human
"""
import logging
from typing import Optional

from ..models.output import (
    EvidencePackage, Finding, FusionResult, FusionVerdict, EvidenceMass,
    FusionConflict, build_fusion_result,
)
from .base import DecisionFusionEngine, FusionEngineFactory

logger = logging.getLogger("secagentx.decision_fusion")

# 决策阈值（与既有置信度口径对齐：0.7/0.4）
BELIEF_MALICIOUS_HIGH = 0.7
BELIEF_MALICIOUS_MID = 0.4
BELIEF_BENIGN_HIGH = 0.7
# 冲突系数阈值：K 超阈值 → 需人工介入
DEFAULT_CONFLICT_THRESHOLD = 0.6
# 证据可靠度下限：低于此值视为"证据薄弱"，置信度打折
MIN_EVIDENCE_CONF = 0.3
# 无任何 Agent 有效裁决时，最终置信度上限
MIN_CONF_NO_AGENT = 0.3
# 裁决为 unknown 时的置信度上限（语义一致性：未知 ≠ 高置信，防止 LLM 误读/前端误标）
UNKNOWN_VERDICT_CONF_CAP = 0.4


class DempsterShaferEngine(DecisionFusionEngine):
    """Dempster-Shafer 证据理论融合引擎。"""

    name = "dempster_shafer"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self.conflict_threshold = float(
            self.config.get("conflict_threshold", DEFAULT_CONFLICT_THRESHOLD)
        )

    # ═══════════════════════ 主入口 ═══════════════════════

    def fuse(self, evidence_packages: list[EvidencePackage]) -> FusionResult:
        if not evidence_packages:
            return self._empty_result()

        # 1. 权重归一化（基础权重 × 证据可靠度）
        scored = self._normalize_weights(evidence_packages)
        active = [(p, w) for p, w in scored if w > 0]
        if not active:
            # 全部失败/无权重 → 未知 + 需人工
            return self._empty_result(
                summary="所有 Agent 证据均无效，无法融合，需人工介入"
            )

        # 2. 为每个证据包构建 mass
        masses = []
        for p, w in active:
            masses.append(self._build_mass(p, w))

        # 3. 全局冲突系数 K（两两冲突之和 / 组合数）
        K_total, pairwise = self._conflict_coefficient(masses)

        # 4. Dempster 组合
        belief = self._combine(masses, K_total)

        # 5. 决策映射
        verdict = self._decide(belief, K_total)

        # 6. 组装结果 + 决策依据链
        evidence_masses = [
            EvidenceMass(
                agent_id=p.agent_id, agent_name=p.agent_name,
                weight=round(w, 4),
                belief=round(self._lean_belief(p), 4),
                plausibility=round(min(1.0, self._lean_belief(p) + 0.0), 4),
                leaning=p.leaning.value if hasattr(p.leaning, "value") else str(p.leaning),
                degraded=p.degraded, failed=p.failed,
            )
            for p, w in active
        ]
        conflicts = [
            FusionConflict(
                between=f"{a} vs {b}",
                coefficient=round(k, 4),
                leaning_a=la, leaning_b=lb,
                resolution=("冲突显著，建议人工复核" if k >= self.conflict_threshold
                            else "取信念较高者"),
            )
            for (a, b, k, la, lb) in pairwise
        ]

        path = self._build_decision_path(active, masses, belief, verdict)

        fr = build_fusion_result(
            engine=self.name,
            method=self.name,
            status="completed",
            verdict=verdict,
            conflict_coefficient=round(K_total, 4),
            conflicts=conflicts,
            evidence_masses=evidence_masses,
            decision_path=path,
            agent_count=len(active),
            evidence_count=sum(len(p.findings or []) for p, _ in active),
            risk_score=0,
        )
        return fr

    # ═══════════════════════ mass 构建 ═══════════════════════

    @staticmethod
    def _lean_belief(p: EvidencePackage) -> float:
        """从 evidence_package 推导"恶意"信念基线（供证据质量展示）。"""
        if p.failed:
            return 0.0
        # 优先用 leaning（含从 verdict 兜底）
        try:
            lean = str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning)
        except Exception:
            lean = "unknown"
        conf = p.leaning_confidence or p.evidence_confidence or 0.5
        if lean == "malicious":
            return conf
        if lean == "suspicious":
            return conf * 0.6
        if lean == "benign":
            return 0.0
        # unknown：从 findings 类型推断
        mal_findings = [f for f in (p.findings or [])
                        if "malicious" in str(f.type) or "intel_hit" in str(f.type)]
        if mal_findings:
            return max(f.evidence_confidence for f in mal_findings) * 0.5
        return 0.5 * conf * 0.3

    def _build_mass(self, p: EvidencePackage, w: float) -> dict:
        """
        构造单个证据包的 mass 分配（Shafer 折扣）。

        关键设计（修正：不把跨 Agent 归一化权重塞进 mass，避免稀释一致证据）:
          - 原始 mass 反映证据本身的信念强度：m_mal = leaning_confidence
          - Shafer 折扣 α = evidence_confidence × (降级?0.5:1) × 覆盖惩罚
          - mass'_mal = α × m_mal；未知质量吸收被折扣掉的信念
          - 归一化权重 w 只用于审计展示与 failed 过滤，不参与 mass 稀释
        """
        # 原始 mass（基于 leaning 信念强度）
        try:
            lean_str = str(p.leaning.value) if hasattr(p.leaning, "value") else str(p.leaning)
        except Exception:
            lean_str = "unknown"
        base_conf = p.leaning_confidence or p.evidence_confidence or 0.5
        if lean_str == "malicious":
            m_mal, m_ben = base_conf, 0.0
        elif lean_str == "benign":
            m_mal, m_ben = 0.0, base_conf
        elif lean_str == "suspicious":
            m_mal, m_ben = base_conf * 0.6, 0.0
        else:  # unknown / 其他：不给恶意/良性任何正质量，全部归入未知
            m_mal, m_ben = 0.0, 0.0

        # Shafer 折扣因子（不跨 Agent 归一化，避免稀释）
        discount = max(p.evidence_confidence, 0.0)
        if p.degraded:
            discount *= 0.5
        # 覆盖度惩罚：情报覆盖不足 → 打折扣（缺失≠干净）
        if p.agent_id == "intel-001" and p.coverage is not None:
            discount *= max(0.3, p.coverage)
        # 证据可靠度过低 → 额外衰减
        if p.evidence_confidence < MIN_EVIDENCE_CONF:
            discount *= 0.5

        m_mal = m_mal * discount
        m_ben = m_ben * discount
        m_unknown = max(0.0, 1.0 - m_mal - m_ben)
        return {
            "agent_id": p.agent_id,
            "weight": w,
            "m_mal": round(m_mal, 6),
            "m_ben": round(m_ben, 6),
            "m_unknown": round(m_unknown, 6),
        }

    # ═══════════════════════ 组合 ═══════════════════════

    def _combine(self, masses: list[dict], K_total: float) -> dict:
        """Dempster 组合：按顺序两两组合全部证据。"""
        if not masses:
            return {"malicious": 0.0, "benign": 0.0, "unknown": 1.0}
        acc = {"malicious": masses[0]["m_mal"],
               "benign": masses[0]["m_ben"],
               "unknown": masses[0]["m_unknown"]}
        for m in masses[1:]:
            # _build_mass 产出 m_mal/m_ben/m_unknown，统一成 internal keys
            m_norm = {
                "malicious": m["m_mal"],
                "benign": m["m_ben"],
                "unknown": m["m_unknown"],
            }
            acc = self._pairwise_combine(acc, m_norm)
            # 若冲突过大导致分母为 0，退化为归一化求和（防御）
            norm = acc["malicious"] + acc["benign"] + acc["unknown"]
            if norm <= 0:
                acc = {"malicious": 0.0, "benign": 0.0, "unknown": 1.0}
                break
        return {
            "malicious": round(acc["malicious"], 6),
            "benign": round(acc["benign"], 6),
            "unknown": round(acc["unknown"], 6),
        }

    @staticmethod
    def _pairwise_combine(m1: dict, m2: dict) -> dict:
        """两个 mass 的 Dempster 组合（含冲突归一）。"""
        # 联合质量
        mal_mal = m1["malicious"] * m2["malicious"]
        mal_unk = m1["malicious"] * m2["unknown"]
        unk_mal = m1["unknown"] * m2["malicious"]
        ben_ben = m1["benign"] * m2["benign"]
        ben_unk = m1["benign"] * m2["unknown"]
        unk_ben = m1["unknown"] * m2["benign"]
        unk_unk = m1["unknown"] * m2["unknown"]
        # 冲突（交集为空）
        conflict = (
            m1["malicious"] * m2["benign"]
            + m1["benign"] * m2["malicious"]
        )
        norm = 1.0 - conflict
        if norm <= 0:
            return {"malicious": 0.0, "benign": 0.0, "unknown": 1.0}
        return {
            "malicious": round((mal_mal + mal_unk + unk_mal) / norm, 6),
            "benign": round((ben_ben + ben_unk + unk_ben) / norm, 6),
            "unknown": round(unk_unk / norm, 6),
        }

    @staticmethod
    def _conflict_coefficient(masses: list[dict]) -> tuple[float, list]:
        """全局冲突系数 K 与两两冲突列表。"""
        if len(masses) < 2:
            return 0.0, []
        pairwise = []
        total_k = 0.0
        count = 0
        for i in range(len(masses)):
            for j in range(i + 1, len(masses)):
                a, b = masses[i], masses[j]
                k = a["m_mal"] * b["m_ben"] + a["m_ben"] * b["m_mal"]
                total_k += k
                count += 1
                pairwise.append((a["agent_id"], b["agent_id"], k,
                                 DempsterShaferEngine._lean_label(a),
                                 DempsterShaferEngine._lean_label(b)))
        avg_k = total_k / count if count else 0.0
        return avg_k, pairwise

    @staticmethod
    def _lean_label(m: dict) -> str:
        """mass 对应的倾向标签（供冲突记录展示）。"""
        if m["m_mal"] > m["m_ben"]:
            return "malicious"
        if m["m_ben"] > m["m_mal"]:
            return "benign"
        return "unknown"

    # ═══════════════════════ 决策映射 ═══════════════════════

    def _decide(self, belief: dict, K_total: float) -> FusionVerdict:
        b_mal = belief["malicious"]
        b_ben = belief["benign"]
        b_unk = belief["unknown"]
        needs_human = bool(K_total >= self.conflict_threshold)

        if b_mal >= BELIEF_MALICIOUS_HIGH:
            verdict = "malicious"
            risk = "高危"
            action = "block"
        elif b_ben >= BELIEF_BENIGN_HIGH:
            verdict = "benign"
            risk = "低危"
            action = "none"
        elif b_mal >= BELIEF_MALICIOUS_MID:
            verdict = "suspicious"
            risk = "中危"
            action = "escalate"
        else:
            # 未知主导：不放任"低危"，需人工
            verdict = "unknown"
            risk = "低危"
            action = "escalate"
            needs_human = True

        # ── v2.6: 风险概率与置信度分离（两个独立维度） ──
        # risk_probability = 事件为恶意的可能性 = belief_malicious（0~1）
        # confidence        = 判断的确定性 = 证据集中度 = 1 - belief_unknown（0~1）
        # 二者独立：概率高≠确定性高（如只有1条模糊情报 → 概率0.6但未知0.4 → 确定性仅0.6）
        risk_probability = round(b_mal, 4)

        # 无有效证据 → 强制低置信度
        if b_mal + b_ben + b_unk >= 0.999 and b_unk > 0.95:
            confidence = MIN_CONF_NO_AGENT
        else:
            # 确定性 = 已知部分（1 - unknown），反映证据是否充分
            confidence = round(1.0 - b_unk, 4)
            # 良性判定：风险概率清零（非恶意），但确定性仍来自证据集中度
            if verdict == "benign":
                risk_probability = 0.0
            # 若证据极不充分（未知主导），置信度收敛到低值
            if b_unk > 0.95:
                confidence = min(confidence, MIN_CONF_NO_AGENT)
            # unknown 且证据不足时，置信度不越过"可疑"阈值（未知 ≠ 高置信）
            if verdict == "unknown":
                confidence = min(confidence, UNKNOWN_VERDICT_CONF_CAP)

        return FusionVerdict(
            verdict=verdict,
            belief_malicious=round(b_mal, 4),
            belief_benign=round(b_ben, 4),
            belief_unknown=round(b_unk, 4),
            risk_probability=risk_probability,
            confidence=confidence,
            risk_level=risk,
            recommended_action=action,
            needs_human=needs_human,
        )

    # ═══════════════════════ 决策依据链 ═══════════════════════

    def _build_decision_path(self, active, masses, belief, verdict) -> list[dict]:
        path = []
        # 1. 证据收集
        for (p, w), m in zip(active, masses):
            findings_desc = "; ".join(
                (f.fact[:40] if isinstance(f, Finding) else str(f.get("fact", ""))[:40])
                for f in (p.findings or [])[:2]
            ) or f"证据包（{p.agent_id}）"
            path.append({
                "step": len(path) + 1,
                "desc": (f"收集 {p.agent_name or p.agent_id} 证据：{findings_desc} "
                         f"（可靠度 {p.evidence_confidence:.0%}，权重 {w:.0%}）"),
                "tag": "evidence",
            })
        # 2. 冲突检测
        if verdict.needs_human and self.conflict_coefficient_global(masses) >= self.conflict_threshold:
            path.append({
                "step": len(path) + 1,
                "desc": f"证据间存在显著冲突（K={self.conflict_coefficient_global(masses):.0%}），标记需人工介入",
                "tag": "conflict",
            })
        # 3. 融合结果
        path.append({
            "step": len(path) + 1,
            "desc": (f"Dempster 融合：恶意信念 {verdict.belief_malicious:.0%}，"
                     f"良性信念 {verdict.belief_benign:.0%}，未知 {verdict.belief_unknown:.0%}"),
            "tag": "fusion",
        })
        # 4. 最终裁决
        path.append({
            "step": len(path) + 1,
            "desc": f"最终裁决：{verdict.verdict}（风险 {verdict.risk_level}，"
                    f"置信度 {verdict.confidence:.0%}，动作 {verdict.recommended_action}）",
            "tag": "decision",
        })
        return path

    def conflict_coefficient_global(self, masses: list[dict]) -> float:
        """供 decision_path 展示全局 K。"""
        K, _ = self._conflict_coefficient(masses)
        return K

    def _empty_result(self, summary: str = "") -> FusionResult:
        """无有效证据时的兜底结果（未知 + 需人工）。"""
        verdict = FusionVerdict(
            verdict="unknown", belief_malicious=0.0, belief_benign=0.0,
            belief_unknown=1.0, risk_probability=0.0, confidence=MIN_CONF_NO_AGENT,
            risk_level="低危", recommended_action="escalate", needs_human=True,
        )
        return build_fusion_result(
            engine=self.name, method=self.name, status="completed",
            verdict=verdict, conflict_coefficient=0.0,
            conflicts=[], evidence_masses=[],
            decision_path=[{
                "step": 1, "desc": summary or "无有效证据，判定未知，需人工介入",
                "tag": "decision",
            }],
            risk_score=0, agent_count=0, evidence_count=0,
        )


# ── 注册到工厂（默认引擎） ──
FusionEngineFactory.register(DempsterShaferEngine.name, DempsterShaferEngine)


__all__ = ["DempsterShaferEngine"]

