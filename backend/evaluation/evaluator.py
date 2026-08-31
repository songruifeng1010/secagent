"""
Agent 评估器（v2.4 M5）— 确定性评分卡

基于 AgentMetrics 计算每个 Agent 的 0~100 评分卡。
评分规则表驱动（RULE-EVAL-*），同一输入 -> 同一分数，可审计。

评分维度（每维度 0~100，加权求和）:
 availability 可用性 25% — 失败率越低越好
 efficiency 效率 20% — 平均耗时（<5s 满分，>30s 低分）
 reliability 可靠性 20% — 降级率越低越好
 precision 精度 20% — 平均置信度（有裁决时）
 tool_efficacy 工具效能 15% — 工具调用成功率
"""
import logging
from typing import Optional

logger = logging.getLogger("secagentx.evaluation")

# 评分卡维度权重
DIMENSION_WEIGHTS = {
    "availability": 0.25,
    "efficiency": 0.20,
    "reliability": 0.20,
    "precision": 0.20,
    "tool_efficacy": 0.15,
}

# 阈值规则（RULE-EVAL-*）
FAILURE_RATE_MAX = 0.5  # 失败率 ≥50% -> 可用性 0
DURATION_OK_MS = 5000  # 平均耗时 ≤5s -> 效率满分
DURATION_BAD_MS = 30000  # 平均耗时 ≥30s -> 效率 0
DEGRADED_RATE_MAX = 0.5  # 降级率 ≥50% -> 可靠性 0
CONFIDENCE_FLOOR = 0.3  # 平均置信度 ≤30% -> 精度低


class AgentEvaluator:
    """确定性 Agent 评分卡生成器。"""

    @classmethod
    async def evaluate_all(cls, metrics: "AgentMetrics") -> dict:
        """评估所有 Agent，返回 {agents, system, tool_metrics, route, consistency}。"""
        agents = await metrics.per_agent_metrics()
        scores = [cls._score_agent(a) for a in agents]
        tool_metrics = await metrics.tool_metrics()
        route = await metrics.route_correction_metrics()
        consistency = await metrics.decision_consistency()
        system = cls._score_system(scores, route, consistency)
        return {
            "agents": scores,
            "system": system,
            "tool_metrics": tool_metrics,
            "route": route,
            "consistency": consistency,
            "measurement_notice": (
                "precision 维度是模型自报置信度的运行指标，不代表金标准准确率；"
                "真实效果请使用 backend.evaluation.benchmark"
            ),
        }

    # ═══════════════ 单 Agent 评分 ═══════════════
    @classmethod
    def _score_agent(cls, a: dict) -> dict:
        dims = {}

        # 可用性: 失败率
        failure_rate = a.get("failure_rate", 0)
        avail = cls._linear_score(failure_rate, FAILURE_RATE_MAX, invert=True)
        dims["availability"] = {
            "score": avail, "value": f"失败率 {failure_rate:.0%}",
            "rule_id": "RULE-EVAL-AVAIL",
        }

        # 效率: 平均耗时
        dur = a.get("avg_duration_ms", 0)
        eff = cls._linear_score(dur, DURATION_BAD_MS, invert=True,
                                ok_at=DURATION_OK_MS)
        dims["efficiency"] = {
            "score": eff, "value": f"平均耗时 {dur}ms",
            "rule_id": "RULE-EVAL-EFF",
        }

        # 可靠性: 降级率
        degraded = a.get("degraded_rate", 0)
        rel = cls._linear_score(degraded, DEGRADED_RATE_MAX, invert=True)
        dims["reliability"] = {
            "score": rel, "value": f"降级率 {degraded:.0%}",
            "rule_id": "RULE-EVAL-REL",
        }

        # 精度: 平均置信度
        conf = a.get("avg_confidence")
        if conf is None:
            prec = 50  # 无裁决记录 -> 中性
            dims["precision"] = {
                "score": prec, "value": "无裁决记录", "rule_id": "RULE-EVAL-PREC-UNK",
            }
        else:
            prec = cls._linear_score(conf, CONFIDENCE_FLOOR, invert=False)
            dims["precision"] = {
                "score": prec, "value": f"模型自报平均置信度 {conf:.0%}",
                "rule_id": "RULE-EVAL-PREC",
                "measurement": "self_reported_confidence",
            }

        # 工具效能: 工具成功率
        tsr = a.get("tool_success_rate")
        if tsr is None:
            te = 50
            dims["tool_efficacy"] = {
                "score": te, "value": "无工具调用", "rule_id": "RULE-EVAL-TOOL-UNK",
            }
        else:
            te = cls._linear_score(tsr, 0.5, invert=False)
            dims["tool_efficacy"] = {
                "score": te, "value": f"工具成功率 {tsr:.0%}",
                "rule_id": "RULE-EVAL-TOOL",
            }

        # 加权总分
        total = sum(
            dims[k]["score"] * w for k, w in DIMENSION_WEIGHTS.items()
        )
        score = int(round(total))
        issues = cls._collect_issues(dims, a)
        return {
            "agent_id": a["agent_id"],
            "score": score,
            "grade": cls._grade(score),
            "dimensions": dims,
            "issues": issues,
            "tasks": a["tasks"],
            "metrics": {
                "tasks": a["tasks"], "failures": a["failures"],
                "avg_duration_ms": a["avg_duration_ms"],
                "avg_confidence": a["avg_confidence"],
                "tool_success_rate": a["tool_success_rate"],
            },
        }

    @staticmethod
    def _linear_score(value: float, bad_at: float,
                      invert: bool = False, ok_at: Optional[float] = None) -> int:
        """线性映射到 0~100。

        invert=True: 值越小越好（失败率）: value≥bad_at -> 0，value->0 -> 100
        invert=False: 值越大越好（成功率）: value≤bad_at -> 0，value->1/ok_at -> 100
        """
        if invert:
            if value <= 0: return 100
            if value >= bad_at: return 0
            return int(round((1 - value / bad_at) * 100)) if bad_at else 100
        # 值越大越好
        full_at = ok_at if ok_at is not None else 1.0
        if value >= full_at: return 100
        if value <= bad_at: return 0
        return int(round((value - bad_at) / (full_at - bad_at) * 100)) if full_at > bad_at else 100

    @staticmethod
    def _collect_issues(dims: dict, a: dict) -> list[str]:
        issues = []
        if dims["availability"]["score"] < 60:
            issues.append("失败率偏高")
        if dims["efficiency"]["score"] < 60:
            issues.append("响应耗时长")
        if dims["reliability"]["score"] < 60:
            issues.append("降级率偏高")
        if dims["precision"].get("score", 100) < 60:
            issues.append("置信度偏低")
        if a.get("tasks", 0) == 0:
            issues.append("尚无任务数据")
        return issues

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"

    # ═══════════════ 系统级评分 ═══════════════
    @classmethod
    def _score_system(cls, agent_scores: list[dict],
                      route: dict, consistency: dict) -> dict:
        avg = sum(a["score"] for a in agent_scores) / len(agent_scores) if agent_scores else 0
        # 路由修正率惩罚
        route_penalty = 1.0 - min(route.get("correction_rate", 0), 0.5)
        # 一致性
        consistency_rate = consistency.get("consistency_rate", 1.0)
        total = int(round(avg * route_penalty * consistency_rate))
        return {
            "score": max(0, total),
            "grade": cls._grade(max(0, total)),
            "agent_count": len(agent_scores),
            "avg_agent_score": int(round(avg)),
            "correction_rate": route.get("correction_rate", 0),
            "consistency_rate": consistency_rate,
        }


__all__ = ["AgentEvaluator", "DIMENSION_WEIGHTS"]
