"""
简化的推理引擎 — 直接消费 Agent 的结构化输出

不再做"文本→正则提取→假设生成→贝叶斯→模板拼接"的弯路。
Agent 已输出结构化 verdict/confidence/evidence，Reasoner 只做聚合和冲突检测。
"""
import uuid
import time
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class ConflictRecord:
    """冲突记录"""
    conflict_id: str = field(default_factory=lambda: f"cf-{uuid.uuid4().hex[:6]}")
    agent_a: str = ""
    agent_b: str = ""
    verdict_a: str = ""
    verdict_b: str = ""
    confidence_a: float = 0.0
    confidence_b: float = 0.0
    resolution: str = ""
    resolution_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "conflict_id": self.conflict_id,
            "between": f"{self.agent_a} vs {self.agent_b}",
            "verdicts": f"「{self.verdict_a}」vs「{self.verdict_b}」",
            "confidence": f"{self.confidence_a:.0%} vs {self.confidence_b:.0%}",
            "resolution": self.resolution,
            "reason": self.resolution_reason,
        }


class Reasoner:
    """
    简化推理引擎

    直接消费 Agent 的 structured 输出字段，无需文本解析。
    只做三件事：
      1. 聚合各 Agent 的 verdict 和置信度
      2. 检测冲突（verdict 矛盾 / 置信度差距过大）
      3. 生成简洁报告
    """

    def __init__(self, llm=None):
        self.llm = llm
        self._start_time = 0.0

    async def reason(self, query: str, agent_outputs: list[dict],
                     context: Optional[dict] = None) -> dict:
        """
        简化推理：直接聚合 Agent 的结构化输出

        参数:
            query: 用户原始问题
            agent_outputs: 包含 structured 字段的 Agent 输出列表
            context: 额外上下文（保留兼容）

        返回:
            综合推理结果 dict
        """
        self._start_time = time.time()
        conflicts = []

        # 提取所有结构化输出
        structured_results = []
        for output in agent_outputs:
            structured = output.get("structured") or {}
            if structured and structured.get("verdict") != "unknown":
                structured_results.append({
                    "agent_id": output.get("agent_id", ""),
                    "agent_name": output.get("agent_name", ""),
                    **structured,
                })

        # ═══════ 冲突检测（基于结构化字段，而非文本正则） ═══════
        for i in range(len(structured_results)):
            for j in range(i + 1, len(structured_results)):
                a, b = structured_results[i], structured_results[j]
                va, vb = a.get("verdict"), b.get("verdict")
                ca, cb = a.get("confidence", 0), b.get("confidence", 0)

                # 直接矛盾：malicious vs benign
                if va in ("malicious",) and vb in ("benign",):
                    verdict = f"{a['agent_name']}胜" if ca >= cb else f"{b['agent_name']}胜"
                    conflicts.append(ConflictRecord(
                        agent_a=a["agent_name"], agent_b=b["agent_name"],
                        verdict_a=va, verdict_b=vb,
                        confidence_a=ca, confidence_b=cb,
                        resolution=verdict,
                        resolution_reason=f"置信度 {ca:.0%} vs {cb:.0%}，取置信度高者",
                    ))
                elif va in ("benign",) and vb in ("malicious",):
                    verdict = f"{a['agent_name']}胜" if ca >= cb else f"{b['agent_name']}胜"
                    conflicts.append(ConflictRecord(
                        agent_a=a["agent_name"], agent_b=b["agent_name"],
                        verdict_a=va, verdict_b=vb,
                        confidence_a=ca, confidence_b=cb,
                        resolution=verdict,
                        resolution_reason=f"置信度 {ca:.0%} vs {cb:.0%}，取置信度高者",
                    ))

                # 置信度差距过大
                if abs(ca - cb) > 0.5:
                    conflicts.append(ConflictRecord(
                        agent_a=a["agent_name"], agent_b=b["agent_name"],
                        verdict_a=va, verdict_b=vb,
                        confidence_a=ca, confidence_b=cb,
                        resolution=f"{a['agent_name'] if ca > cb else b['agent_name']}的结论更可靠",
                        resolution_reason=f"置信度差距 {abs(ca - cb):.0%} > 50%",
                    ))

        # ═══════ 聚合结论 ═══════
        if not structured_results:
            # 无结构化数据时降级：直接用文本拼接
            report = "\n\n".join(
                ao.get("content", "") for ao in agent_outputs
            )
            elapsed = (time.time() - self._start_time) * 1000
            return {
                "status": "fallback",
                "confidence": 0.5,
                "winner": None,
                "report": report,
                "duration_ms": round(elapsed, 1),
                "conflicts": [],
                "hypotheses": [],
                "evidence": {"total": 0, "key_evidence": []},
            }

        # 按置信度加权聚合 verdict
        verdict_weights = {"malicious": 1.0, "suspicious": 0.6, "unknown": 0.4, "benign": 0.0}
        weighted_score = sum(
            r.get("confidence", 0) * verdict_weights.get(r.get("verdict", "unknown"), 0.4)
            for r in structured_results
        )
        total_weight = sum(r.get("confidence", 0) for r in structured_results)
        overall_score = weighted_score / max(total_weight, 0.001)

        # 最终 verdict
        if overall_score >= 0.65:
            final_verdict = "malicious"
        elif overall_score >= 0.35:
            final_verdict = "suspicious"
        elif overall_score <= 0.15:
            final_verdict = "benign"
        else:
            final_verdict = "unknown"

        # 综合置信度（加权平均）
        avg_confidence = total_weight / max(len(structured_results), 1)

        # 聚合技术ID
        all_technique_ids = []
        for r in structured_results:
            all_technique_ids.extend(r.get("technique_ids", []))
        seen = set()
        unique_techniques = []
        for tid in all_technique_ids:
            if tid not in seen:
                seen.add(tid)
                unique_techniques.append(tid)

        # 聚合 IOC
        all_iocs = {"ips": set(), "domains": set(), "hashes": set()}
        for r in structured_results:
            iocs = r.get("iocs", {})
            all_iocs["ips"].update(iocs.get("ips", []))
            all_iocs["domains"].update(iocs.get("domains", []))
            all_iocs["hashes"].update(iocs.get("hashes", []))

        # 收集关键证据
        all_evidence = []
        for r in structured_results:
            for ev in r.get("key_evidence", []):
                all_evidence.append({
                    "content": ev,
                    "source": r["agent_name"],
                    "confidence": r.get("confidence", 0),
                })

        # 建议动作（取最高置信度 Agent 的建议）
        sorted_by_conf = sorted(
            structured_results, key=lambda r: r.get("confidence", 0), reverse=True
        )
        recommended_action = sorted_by_conf[0].get("recommended_action", "monitoring") if sorted_by_conf else "monitoring"

        # 风险等级聚合（取最高）
        risk_order = {"低危": 0, "中危": 1, "高危": 2, "紧急": 3}
        max_risk = "低危"
        for r in structured_results:
            rl = r.get("risk_level", "低危")
            if risk_order.get(rl, 0) > risk_order.get(max_risk, 0):
                max_risk = rl

        elapsed = (time.time() - self._start_time) * 1000

        result = {
            "query": query,
            "status": "completed",
            "duration_ms": round(elapsed, 1),
            "confidence": round(avg_confidence, 2),

            "winner": {
                "verdict": final_verdict,
                "confidence": round(avg_confidence, 2),
                "risk_level": max_risk,
                "technique_ids": unique_techniques,
                "recommended_action": recommended_action,
            },

            "hypotheses": [r.get("verdict") for r in structured_results],
            "evidence": {
                "total": len(all_evidence),
                "key_evidence": all_evidence[:8],
            },
            "iocs": {k: list(v) for k, v in all_iocs.items()},

            "conflicts": [c.to_dict() for c in conflicts],

            # 人类可读报告
            "report": self._generate_report(
                query, structured_results, final_verdict, avg_confidence, max_risk, conflicts
            ),
        }

        return result

    def _generate_report(self, query: str, results: list[dict],
                          final_verdict: str, confidence: float,
                          risk_level: str, conflicts: list[ConflictRecord]) -> str:
        """生成简洁的人类可读报告"""
        verdict_emoji = {
            "malicious": "", "benign": "✅",
            "suspicious": "❓", "unknown": "❔",
        }
        emoji = verdict_emoji.get(final_verdict, "")

        parts = [f"##  综合分析结果\n"]
        parts.append(f"**原始问题**: {query}\n")
        parts.append(f"---")
        parts.append(f"###  最终判定: {emoji + ' ' if emoji else ''}**{final_verdict}**")
        parts.append(f"**综合置信度**: {confidence:.0%} | **风险等级**: {risk_level}\n")

        # 各 Agent 结论
        parts.append("###  各 Agent 分析结论\n")
        for r in results:
            e = verdict_emoji.get(r.get("verdict", ""), "")
            parts.append(f"- **{r['agent_name']}**: {e + ' ' if e else ''}{r.get('verdict', 'unknown')} "
                         f"(置信度: {r.get('confidence', 0):.0%})")
            if r.get("key_evidence"):
                for ev in r["key_evidence"][:2]:
                    parts.append(f"  - {ev}")
        parts.append("")

        # 攻击技术
        tech_ids = []
        for r in results:
            tech_ids.extend(r.get("technique_ids", []))
        if tech_ids:
            tech_ids = list(set(tech_ids))
            parts.append("###  MITRE ATT&CK 技术映射\n")
            parts.append(f"{', '.join(tech_ids)}\n")

        # IOC
        all_iocs = {"ips": set(), "domains": set(), "hashes": set()}
        for r in results:
            iocs = r.get("iocs", {})
            all_iocs["ips"].update(iocs.get("ips", []))
            all_iocs["domains"].update(iocs.get("domains", []))
            all_iocs["hashes"].update(iocs.get("hashes", []))
        has_iocs = any(v for v in all_iocs.values())
        if has_iocs:
            parts.append("###  威胁指标 (IOC)\n")
            if all_iocs["ips"]:
                parts.append(f"- IP: {', '.join(all_iocs['ips'])}")
            if all_iocs["domains"]:
                parts.append(f"- 域名: {', '.join(all_iocs['domains'])}")
            if all_iocs["hashes"]:
                parts.append(f"- 哈希: {', '.join(all_iocs['hashes'])}")
            parts.append("")

        # 冲突
        if conflicts:
            parts.append("###  Agent 冲突记录\n")
            for c in conflicts[:3]:
                parts.append(f"- **{c.agent_a}** vs **{c.agent_b}**: "
                             f"「{c.verdict_a}」vs「{c.verdict_b}」→ {c.resolution}")
            parts.append("")

        # 建议动作
        actions = set(r.get("recommended_action", "") for r in results)
        if actions:
            parts.append("###  建议处置\n")
            for a in sorted(actions):
                if a == "block":
                    parts.append(f"-   **封禁**: 建议立即封锁相关IP/域名")
                elif a == "escalate":
                    parts.append(f"-   **升级人工**: 需要安全分析师复核")
                elif a == "monitoring":
                    parts.append(f"-   **标记观察**: 持续监控后续行为")
                elif a == "none":
                    parts.append(f"- ✅ **无需处置**: 确认为正常行为")
            parts.append("")

        # 置信度不足提示
        if confidence < 0.4:
            parts.append("> 整体置信度偏低，建议人工复核\n")

        parts.append("---")
        parts.append(f"*分析耗时: {(time.time() - self._start_time) * 1000:.0f}ms*")

        return "\n".join(parts)
