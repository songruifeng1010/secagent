"""
动态权重引擎（Dynamic Weight Engine）— v2.4 (M1)

在静态基线权重（behavior 40% / intel 30% / asset 20% / context 10%）之上，
依据本轮证据质量动态调节各维度权重。

## 为什么需要动态权重
固定权重（40/30/20/10）无法体现"证据质量"差异：
  - 情报覆盖不足时，情报维度仍占 30%，会让"缺失≠干净"的中性分(50)过度拖拽总分；
  - 行为证据明确时，其结论应比证据模糊时更有话语权；
  - 资产画像/上下文线索的完整度也应影响其贡献度。

## 设计原则
  1. **确定性**: 所有调节因子来自规则表（rule_id），同一输入 → 同一权重。
  2. **可审计**: 每个调节因子带 rule_id + reason + base_weight + factor，逐条可追溯。
  3. **缺失≠干净**: 情报覆盖不足 → 降情报权重（缺失信息不可信），
     而非把"没查到"当作干净证据。
  4. **证据转移**: 情报维度不可靠时，行为证据权重增强（把话语权交给更可靠的维度）。
  5. **范围保护**: 单维度权重 clamp 到 [min_weight, max_weight]，防止过度放大/压缩。
  6. **归一化**: 最终权重归一化保证 ΣW=1。

## 用法
    weights, adjustments = DynamicWeightEngine.compute(ctx, base_weights=..., config=...)
    # 由 WeightedRiskScorer.score(dynamic_weights=True) 调用
"""
import logging
from typing import Optional

logger = logging.getLogger("secagentx.orchestrator.dynamic_weights")

DEFAULT_MIN_WEIGHT = 0.05
DEFAULT_MAX_WEIGHT = 0.70

# ──────────────────────────────────────────────────────────────
# 规则表：rule_id -> (维度, 调节因子, 原因说明)
# 因子 >1 升权，<1 降权；同一维度可叠加多个因子后 clamp + 归一化。
# ──────────────────────────────────────────────────────────────
RULES: dict[str, tuple] = {
    # ── intel 维度：情报覆盖度 + 失败标记 + 独立源数 ──
    "RULE-DYN-INTEL-01": ("intel", 0.55, "情报覆盖严重不足（coverage<33%），大幅降权"),
    "RULE-DYN-INTEL-02": ("intel", 0.70, "情报覆盖不足（33%~50%），降权"),
    "RULE-DYN-INTEL-03": ("intel", 0.85, "情报部分覆盖（50%~100%），轻微降权"),
    "RULE-DYN-INTEL-04": ("intel", 0.70, "情报未查询/不可用，按未知降权（缺失≠干净）"),
    "RULE-DYN-INTEL-05": ("intel", 0.50, "情报查询失败，大幅降权"),
    "RULE-DYN-INTEL-06": ("intel", 1.10, "独立情报源≥3 个，交叉验证增强，升权"),
    # ── behavior 维度：裁决明确度 ──
    "RULE-DYN-BEH-01": ("behavior", 1.05, "行为证据明确（存在明确裁决），轻微升权"),
    "RULE-DYN-BEH-02": ("behavior", 0.90, "行为证据未知/不足，降权"),
    "RULE-DYN-BEH-03": ("behavior", 0.60, "行为分析失败，大幅降权"),
    "RULE-DYN-BEH-04": ("behavior", 1.10, "情报维度不可靠，行为证据权重增强（证据转移）"),
    # ── asset 维度：画像完整度 ──
    "RULE-DYN-ASSET-01": ("asset", 1.10, "资产画像完整（价值+暴露+敏感数据），升权"),
    "RULE-DYN-ASSET-02": ("asset", 0.90, "资产画像部分缺失，轻微降权"),
    "RULE-DYN-ASSET-03": ("asset", 0.80, "无资产画像，降权（未知不当作高价值）"),
    # ── context 维度：线索丰富度 ──
    "RULE-DYN-CTX-01": ("context", 1.05, "上下文线索≥3 条，信息充分，升权"),
    "RULE-DYN-CTX-02": ("context", 0.90, "上下文线索不足，降权"),
    "RULE-DYN-CTX-03": ("context", 0.85, "无上下文线索，降权"),
}


def _find_package(ctx: dict, agent_id: str) -> Optional[dict]:
    """查找某 Agent 的证据包（优先 evidence_packages，兼容 agent_results）。"""
    for p in ctx.get("evidence_packages", []) or []:
        if p.get("agent_id") == agent_id:
            return p
    for r in ctx.get("agent_results", []) or []:
        if r.get("agent_id") == agent_id:
            return r
    return None


class DynamicWeightEngine:
    """动态权重计算引擎（纯确定性，无 IO、无 LLM）。"""

    @classmethod
    def compute(cls, ctx: dict, base_weights: dict = None,
                config: dict = None) -> dict:
        """
        计算动态权重。

        参数:
            ctx: 评分上下文（与 WeightedRiskScorer 同一结构）
            base_weights: 静态基线权重（默认取 risk_model.DEFAULT_WEIGHTS）
            config: 可选 {min_weight, max_weight}

        返回:
            {"weights": 归一化后权重, "adjustments": 逐条调节记录, "enabled": True}
        """
        from backend.orchestrator.risk_model import DEFAULT_WEIGHTS
        ctx = ctx or {}
        base = dict(base_weights if base_weights is not None else DEFAULT_WEIGHTS)
        min_w = float((config or {}).get("min_weight", DEFAULT_MIN_WEIGHT))
        max_w = float((config or {}).get("max_weight", DEFAULT_MAX_WEIGHT))
        factors = {k: 1.0 for k in base}
        adjustments = []

        # ── intel 维度：情报覆盖度 + 失败标记 + 独立源数 ──
        intel = _find_package(ctx, "intel-001")
        coverage = None
        failed = False
        independent = 0
        if intel is not None:
            coverage = intel.get("coverage")
            failed = bool(intel.get("failed"))
            try:
                independent = int(intel.get("independent_sources") or 0)
            except (TypeError, ValueError):
                independent = 0

        intel_unreliable = False
        if failed:
            # 情报查询失败，大幅降权
            factors["intel"] *= RULES["RULE-DYN-INTEL-05"][1]
            adjustments.append(cls._mk("intel", "RULE-DYN-INTEL-05", base, factors["intel"], coverage))
            intel_unreliable = True
        elif coverage is None:
            # 情报未查询/不可用，按未知降权（缺失≠干净）
            factors["intel"] *= RULES["RULE-DYN-INTEL-04"][1]
            adjustments.append(cls._mk("intel", "RULE-DYN-INTEL-04", base, factors["intel"], coverage))
            intel_unreliable = True
        elif coverage >= 1.0:
            if independent >= 3:
                # 独立情报源≥3 个，交叉验证增强，升权
                factors["intel"] *= RULES["RULE-DYN-INTEL-06"][1]
                adjustments.append(cls._mk("intel", "RULE-DYN-INTEL-06", base, factors["intel"], coverage))
        elif coverage >= 0.5:
            # 情报部分覆盖（50%~100%），轻微降权
            factors["intel"] *= RULES["RULE-DYN-INTEL-03"][1]
            adjustments.append(cls._mk("intel", "RULE-DYN-INTEL-03", base, factors["intel"], coverage))
        elif coverage >= 0.33:
            # 情报覆盖不足（33%~50%），降权
            factors["intel"] *= RULES["RULE-DYN-INTEL-02"][1]
            adjustments.append(cls._mk("intel", "RULE-DYN-INTEL-02", base, factors["intel"], coverage))
            intel_unreliable = True
        else:
            # 情报覆盖严重不足（coverage<33%），大幅降权
            factors["intel"] *= RULES["RULE-DYN-INTEL-01"][1]
            adjustments.append(cls._mk("intel", "RULE-DYN-INTEL-01", base, factors["intel"], coverage))
            intel_unreliable = True

        # ── behavior 维度：裁决明确度 ──
        behavior_clear = cls._behavior_is_clear(ctx)
        behavior_failed = cls._behavior_failed(ctx)
        if behavior_failed:
            # 行为分析失败，大幅降权
            factors["behavior"] *= RULES["RULE-DYN-BEH-03"][1]
            adjustments.append(cls._mk("behavior", "RULE-DYN-BEH-03", base, factors["behavior"], None))
        elif behavior_clear:
            # 行为证据明确（存在明确裁决），轻微升权
            factors["behavior"] *= RULES["RULE-DYN-BEH-01"][1]
            adjustments.append(cls._mk("behavior", "RULE-DYN-BEH-01", base, factors["behavior"], None))
        else:
            # 行为证据未知/不足，降权
            factors["behavior"] *= RULES["RULE-DYN-BEH-02"][1]
            adjustments.append(cls._mk("behavior", "RULE-DYN-BEH-02", base, factors["behavior"], None))

        # 证据转移：情报不可靠 -> 行为证据升权
        if intel_unreliable and not behavior_failed:
            factors["behavior"] *= RULES["RULE-DYN-BEH-04"][1]
            adjustments.append(cls._mk("behavior", "RULE-DYN-BEH-04", base, factors["behavior"], None))

        # ── asset 维度：画像完整度 ──
        asset = ctx.get("asset") or {}
        if not asset:
            # 无资产画像，降权（未知不当作高价值）
            factors["asset"] *= RULES["RULE-DYN-ASSET-03"][1]
            adjustments.append(cls._mk("asset", "RULE-DYN-ASSET-03", base, factors["asset"], None))
        else:
            has_crit = bool(asset.get("criticality") or asset.get("level"))
            has_expo = bool(asset.get("exposed") or asset.get("is_public"))
            has_pii = bool(asset.get("contains_pii") or asset.get("sensitive"))
            if has_crit and (has_expo or has_pii):
                # 资产画像完整（价值+暴露+敏感数据），升权
                factors["asset"] *= RULES["RULE-DYN-ASSET-01"][1]
                adjustments.append(cls._mk("asset", "RULE-DYN-ASSET-01", base, factors["asset"], None))
            else:
                # 资产画像部分缺失，轻微降权
                factors["asset"] *= RULES["RULE-DYN-ASSET-02"][1]
                adjustments.append(cls._mk("asset", "RULE-DYN-ASSET-02", base, factors["asset"], None))

        # ── context 维度：线索丰富度 ──
        clues = cls._count_context_clues(ctx)
        if clues >= 3:
            # 上下文线索≥3 条，信息充分，升权
            factors["context"] *= RULES["RULE-DYN-CTX-01"][1]
            adjustments.append(cls._mk("context", "RULE-DYN-CTX-01", base, factors["context"], None))
        elif clues == 0:
            # 无上下文线索，降权
            factors["context"] *= RULES["RULE-DYN-CTX-03"][1]
            adjustments.append(cls._mk("context", "RULE-DYN-CTX-03", base, factors["context"], None))
        else:
            # 上下文线索不足，降权
            factors["context"] *= RULES["RULE-DYN-CTX-02"][1]
            adjustments.append(cls._mk("context", "RULE-DYN-CTX-02", base, factors["context"], None))

        # ── 合成 + clamp + 归一化 ──
        adjusted = {k: base[k] * factors[k] for k in base}
        clamped = {k: max(min_w, min(max_w, adjusted[k])) for k in base}
        total = sum(clamped.values()) or 1.0
        norm = {k: v / total for k, v in clamped.items()}

        return {
            "weights": norm,
            "adjustments": adjustments,
            "enabled": True,
        }

    # ── 辅助 ──
    @staticmethod
    def _mk(dimension: str, rule_id: str, base: dict, current_factor: float,
            coverage) -> dict:
        """构造一条可审计的调节记录。"""
        _, factor, reason = RULES[rule_id]
        return {
            "dimension": dimension,
            "base_weight": base.get(dimension, 0.0),
            "factor": factor,
            "rule_id": rule_id,
            "reason": reason,
            "adjusted_weight": round(base.get(dimension, 0.0) * current_factor, 4),
            "coverage": coverage,
        }

    @staticmethod
    def _behavior_is_clear(ctx: dict) -> bool:
        """行为证据是否有明确裁决（fusion 或 analyst 证据包）。"""
        fusion = ctx.get("fusion_result")
        if fusion is not None:
            verdict = (fusion.get("verdict") or {}).get("verdict", "unknown")
            return verdict in ("malicious", "benign", "suspicious")
        pkg = _find_package(ctx, "analyst-001")
        if pkg is None:
            return False
        if pkg.get("failed"):
            return False
        return bool(pkg.get("verdict"))

    @staticmethod
    def _behavior_failed(ctx: dict) -> bool:
        """行为分析是否失败。"""
        fusion = ctx.get("fusion_result")
        if fusion is not None:
            return False
        pkg = _find_package(ctx, "analyst-001")
        return bool(pkg and pkg.get("failed"))

    @staticmethod
    def _count_context_clues(ctx: dict) -> int:
        """统计上下文线索条数（与 _score_context 的线索来源保持一致）。

        与风险评分维度对齐：普通公网 IP 无归属/历史/告警线索时计 0 条，
        避免"有 IP 就算有线索"的误判。
        """
        from backend.orchestrator.risk_model import (
            _is_private_or_reserved, ANON_PROXY_KEYWORDS, BENIGN_INFRA_KEYWORDS,
        )
        clues = 0

        # 私网/保留地址视为线索
        ip = ctx.get("ip")
        if ip:
            if _is_private_or_reserved(ip):
                clues += 1
            else:
                ip_info = ctx.get("ip_info") or {}
                org_text = " ".join(str(ip_info.get(k, "")) for k in ("org", "isp", "as", "note"))
                low = org_text.lower()
                if any(k in low for k in ANON_PROXY_KEYWORDS + BENIGN_INFRA_KEYWORDS):
                    clues += 1

        # 历史事件
        history = ctx.get("event_history")
        if history is not None and ip:
            clues += 1

        # 告警元信息
        alert_meta = ctx.get("alert_meta") or {}
        if alert_meta.get("severity"):
            clues += 1
        if alert_meta.get("mitre_tactic") or alert_meta.get("mitre_tactic_id"):
            clues += 1

        return clues


__all__ = ["DynamicWeightEngine", "RULES", "DEFAULT_MIN_WEIGHT", "DEFAULT_MAX_WEIGHT"]
