"""
Agent 评估指标（v2.4 M5）— 从 agent_logs 轨迹计算确定性指标

数据源: agent_logs 表中 action_type='trajectory' 的记录（M3 已写入）。
轨迹步 phase: think/tool/agent/observe/route_correction。

指标（全部确定性、可审计）:
  单 Agent:
    tasks / failures / degraded_rate / avg_duration / avg_confidence
    tool_calls / tool_success_rate
  组合:
    工具总成功率 / 路由修正率（越低越好）/ 决策一致性
"""
import json
from typing import Optional
from ..storage.database import Repository


class AgentMetrics:
    """从 agent_logs 计算 Agent 评估指标（只读）。"""

    def __init__(self, db=None):
        self.db = db if db is not None else Repository()

    async def _fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        if isinstance(self.db, Repository):
            return await self.db.fetch_all(sql, params)
        return self.db.fetch_all(sql, params)

    async def _fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        if isinstance(self.db, Repository):
            return await self.db.fetch_one(sql, params)
        return self.db.fetch_one(sql, params)

    async def load_trajectories(self, limit: int = 500) -> list[dict]:
        """加载最近轨迹（含 steps）。"""
        rows = await self._fetch_all(
            "SELECT * FROM agent_logs WHERE action_type='trajectory' "
            "ORDER BY created_at DESC LIMIT ?", (limit,),
        )
        out = []
        for r in rows:
            try:
                action = json.loads(r.get("action_data") or "{}")
            except Exception:
                action = {}
            out.append({
                "id": r.get("id"),
                "conversation_id": r.get("conversation_id"),
                "created_at": r.get("created_at"),
                "total_duration_ms": action.get("total_duration_ms", r.get("duration_ms") or 0),
                "steps": action.get("steps", []) or [],
            })
        return out

    async def per_agent_metrics(self, limit: int = 500) -> list[dict]:
        """按 Agent 聚合指标。"""
        trajs = await self.load_trajectories(limit=limit)
        agents: dict[str, dict] = {}

        for t in trajs:
            for s in t.get("steps", []):
                phase = s.get("phase", "")
                actor = s.get("actor", "")
                success = s.get("success", True)
                dur = s.get("duration_ms", 0)
                if phase == "agent" and actor:
                    a = agents.setdefault(actor, {
                        "agent_id": actor, "tasks": 0, "failures": 0,
                        "total_duration_ms": 0, "total_confidence": 0.0,
                        "conf_count": 0, "tool_calls": 0, "tool_success": 0,
                        "degraded_count": 0,
                    })
                    a["tasks"] += 1
                    if not success:
                        a["failures"] += 1
                    a["total_duration_ms"] += dur
                    conf = _extract_confidence(s.get("output", ""))
                    if conf is not None:
                        a["total_confidence"] += conf
                        a["conf_count"] += 1
                elif phase == "tool" and actor:
                    a = agents.get(actor)
                    if a is not None:
                        a["tool_calls"] += 1
                        if success:
                            a["tool_success"] += 1
                if phase == "agent" and not success and actor:
                    agents.setdefault(actor, {
                        "agent_id": actor, "tasks": 0, "failures": 0,
                        "total_duration_ms": 0, "total_confidence": 0.0,
                        "conf_count": 0, "tool_calls": 0, "tool_success": 0,
                        "degraded_count": 0,
                    })["degraded_count"] += 1

        result = []
        for agent_id, a in agents.items():
            tasks = a["tasks"]
            result.append({
                "agent_id": agent_id,
                "tasks": tasks,
                "failures": a["failures"],
                "failure_rate": round(a["failures"] / tasks, 3) if tasks else 0,
                "degraded_rate": round(a["degraded_count"] / tasks, 3) if tasks else 0,
                "avg_duration_ms": round(a["total_duration_ms"] / tasks) if tasks else 0,
                "avg_confidence": round(a["total_confidence"] / a["conf_count"], 3) if a["conf_count"] else None,
                "tool_calls": a["tool_calls"],
                "tool_success_rate": round(a["tool_success"] / a["tool_calls"], 3) if a["tool_calls"] else None,
            })
        result.sort(key=lambda x: -x["tasks"])
        return result

    async def tool_metrics(self, limit: int = 500) -> list[dict]:
        """工具调用聚合指标。"""
        trajs = await self.load_trajectories(limit=limit)
        tools: dict[str, dict] = {}
        for t in trajs:
            for s in t.get("steps", []):
                if s.get("phase") != "tool":
                    continue
                name = s.get("actor", "")
                if not name:
                    continue
                tm = tools.setdefault(name, {
                    "tool": name, "calls": 0, "success": 0,
                    "total_duration_ms": 0,
                })
                tm["calls"] += 1
                if s.get("success"):
                    tm["success"] += 1
                tm["total_duration_ms"] += int(s.get("duration_ms", 0))
        result = [{
            "tool": t["tool"],
            "calls": t["calls"],
            "success_rate": round(t["success"] / t["calls"], 3) if t["calls"] else 0,
            "avg_duration_ms": round(t["total_duration_ms"] / t["calls"]) if t["calls"] else 0,
        } for t in tools.values()]
        result.sort(key=lambda x: -x["calls"])
        return result

    async def route_correction_metrics(self, limit: int = 500) -> dict:
        """路由修正统计（LLM 路由错误率，越低越好）。"""
        trajs = await self.load_trajectories(limit=limit)
        total_routes = 0
        corrections = 0
        for t in trajs:
            for s in t.get("steps", []):
                if s.get("phase") == "route_correction":
                    corrections += 1
                elif s.get("phase") == "agent":
                    total_routes += 1
        return {
            "total_routes": total_routes,
            "corrections": corrections,
            "correction_rate": round(corrections / total_routes, 3) if total_routes else 0,
        }

    async def decision_consistency(self, limit: int = 200) -> dict:
        """决策一致性：同一会话内同一 Agent 多次裁决是否稳定。"""
        trajs = await self.load_trajectories(limit=limit)
        seen: dict[tuple, set] = {}
        for t in trajs:
            conv = t.get("conversation_id", "")
            for s in t.get("steps", []):
                if s.get("phase") != "agent":
                    continue
                verdict = _extract_verdict(s.get("output", ""))
                key = (conv, s.get("actor", ""))
                seen.setdefault(key, set()).add(verdict or "unknown")
        consistent = sum(1 for v in seen.values() if len(v) == 1)
        total = len(seen)
        return {
            "groups": total,
            "consistent": consistent,
            "consistency_rate": round(consistent / total, 3) if total else 1.0,
        }


def _extract_confidence(output: str) -> Optional[float]:
    """从 agent 步 output 提取置信度（格式: confidence=0.85 或 85%）。"""
    import re
    if not output:
        return None
    # 优先百分比格式（避免 85% 被小数分支误匹配为 85）
    m = re.search(r"confidence=\s*(\d+)%", output)
    if m:
        try:
            return float(m.group(1)) / 100.0
        except ValueError:
            return None
    m = re.search(r"confidence=([\d.]+)", output)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _extract_verdict(output: str) -> Optional[str]:
    """从 agent 步 output 提取裁决（格式: verdict=malicious）。"""
    import re
    if not output:
        return None
    m = re.search(r"verdict=(\w+)", output)
    return m.group(1) if m else None


__all__ = ["AgentMetrics", "_extract_confidence", "_extract_verdict"]

