"""按会话 owner 隔离的 TrueReAct 执行轨迹仓储。"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from ..database import Repository
from .conversation_repo import ConversationAccessDenied


class TrajectoryRepository:
    def __init__(self, db, owner_id: str):
        if not owner_id or not owner_id.strip():
            raise ValueError("TrajectoryRepository 必须提供非空 owner_id")
        self._is_async = isinstance(db, Repository)
        self.db = db
        self.owner_id = owner_id

    async def _execute(self, sql: str, params: tuple = ()):
        if self._is_async:
            return await self.db.execute(sql, params)
        return self.db.execute(sql, params)

    async def _fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        if self._is_async:
            return await self.db.fetch_one(sql, params)
        return self.db.fetch_one(sql, params)

    async def _fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        if self._is_async:
            return await self.db.fetch_all(sql, params)
        return self.db.fetch_all(sql, params)

    async def _insert(self, sql: str, params: tuple = ()) -> int:
        if self._is_async:
            await self.db.execute(sql, params)
            return 0
        return self.db.insert(sql, params)

    async def _require_conversation(self, conversation_id: str) -> None:
        row = await self._fetch_one(
            "SELECT id FROM conversations WHERE id = ? AND owner_id = ?",
            (conversation_id, self.owner_id),
        )
        if not row:
            raise ConversationAccessDenied("会话不存在或无权访问")

    async def save_trajectory(
        self,
        conversation_id: str,
        trajectory: list[dict],
        total_duration_ms: int = 0,
        agent_id: str = "orchestrator",
    ) -> str:
        await self._require_conversation(conversation_id)
        trajectory_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        await self._insert(
            "INSERT INTO agent_logs (id, conversation_id, agent_id, action_type, "
            "action_data, duration_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                trajectory_id,
                conversation_id,
                agent_id,
                "trajectory",
                json.dumps(
                    {"steps": trajectory, "total_duration_ms": total_duration_ms},
                    ensure_ascii=False,
                ),
                int(total_duration_ms),
                now,
            ),
        )
        return trajectory_id

    _PHASE_ALIASES = {
        "think": "think",
        "tool": "tool",
        "agent": "agent",
        "observe": "observe",
        "route_correction": "route_correction",
        "complete": "complete",
        "round_complete": "round_complete",
        "tool_call": "tool",
        "tool_result": "tool",
        "agent_dispatch": "agent",
        "agent_result": "agent",
        "agent_error": "agent",
    }

    def _build_step(self, step: dict, base: dict) -> dict:
        result = dict(step)
        phase = step.get("phase") or self._PHASE_ALIASES.get(
            step.get("type", ""), "think"
        )
        result.setdefault(
            "step_id",
            step.get("step_id") or f"step-{step.get('timestamp', '')}-{len(str(step))}",
        )
        result["phase"] = phase
        result.setdefault("round", step.get("round") or base.get("round") or 1)
        result.setdefault("actor", step.get("actor") or step.get("actor_id") or "LLM")
        result.setdefault(
            "input", step.get("input") or step.get("args") or step.get("task") or ""
        )
        result.setdefault(
            "output",
            step.get("output") or step.get("result") or step.get("preview") or "",
        )
        result.setdefault("success", step.get("success", True))
        result.setdefault("duration_ms", step.get("duration_ms") or 0)
        result.setdefault("timestamp", step.get("timestamp") or 0)
        if phase in ("tool", "agent"):
            result.setdefault(
                "tool_name",
                step.get("tool_name")
                or step.get("tool")
                or (result["actor"] if phase == "tool" else ""),
            )
            result.setdefault(
                "agent_id",
                step.get("agent_id") or (result["actor"] if phase == "agent" else ""),
            )
            if phase == "agent":
                result.setdefault("verdict", step.get("verdict") or "")
                result.setdefault("confidence", step.get("confidence"))
                result.setdefault(
                    "risk_level", step.get("risk_level") or step.get("risk") or ""
                )
        if phase == "think":
            result.setdefault("type", "think")
        return result

    async def _conversation_title_map(self, ids: set[str]) -> dict:
        ids = [conversation_id for conversation_id in ids if conversation_id]
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        try:
            rows = await self._fetch_all(
                f"SELECT m.conversation_id, m.content FROM messages m "
                f"JOIN conversations c ON c.id=m.conversation_id "
                f"WHERE m.role='user' AND c.owner_id=? "
                f"AND m.conversation_id IN ({placeholders}) ORDER BY m.created_at ASC",
                (self.owner_id, *ids),
            )
        except Exception:
            return {}
        first = {}
        for row in rows:
            conversation_id = row.get("conversation_id")
            if conversation_id and conversation_id not in first:
                first[conversation_id] = (
                    (row.get("content") or "").strip().replace("\n", " ")[:40]
                )
        return first

    async def get_trajectories(
        self, conversation_id: Optional[str] = None, limit: int = 50
    ) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        if conversation_id:
            await self._require_conversation(conversation_id)
            rows = await self._fetch_all(
                "SELECT al.* FROM agent_logs al "
                "JOIN conversations c ON c.id=al.conversation_id "
                "WHERE al.action_type='trajectory' AND al.conversation_id=? "
                "AND c.owner_id=? ORDER BY al.created_at ASC LIMIT ?",
                (conversation_id, self.owner_id, limit),
            )
        else:
            rows = await self._fetch_all(
                "SELECT al.* FROM agent_logs al "
                "JOIN conversations c ON c.id=al.conversation_id "
                "WHERE al.action_type='trajectory' AND c.owner_id=? "
                "ORDER BY al.created_at DESC LIMIT ?",
                (self.owner_id, limit),
            )
        titles = await self._conversation_title_map(
            {row.get("conversation_id") for row in rows}
        )
        output = []
        for row in rows:
            try:
                action = json.loads(row.get("action_data") or "{}")
            except Exception:
                action = {}
            conversation = row.get("conversation_id")
            steps = [
                self._build_step(step, {"round": 1})
                for step in action.get("steps", [])
            ]
            fails = sum(1 for step in steps if step.get("success") is False)
            total = int(
                action.get("total_duration_ms") or row.get("duration_ms") or 0
            )
            output.append(
                {
                    "id": row.get("id"),
                    "conversation_id": conversation,
                    "conversation_title": titles.get(conversation, ""),
                    "agent_id": row.get("agent_id"),
                    "created_at": row.get("created_at"),
                    "total_duration_ms": total,
                    "step_count": len(steps),
                    "success_rate": round((len(steps) - fails) / len(steps), 3)
                    if steps
                    else 0,
                    "fail_count": fails,
                    "steps": steps,
                }
            )
        return output

    async def get_conversation_trajectory(self, conversation_id: str) -> dict:
        await self._require_conversation(conversation_id)
        rows = await self._fetch_all(
            "SELECT al.* FROM agent_logs al "
            "JOIN conversations c ON c.id=al.conversation_id "
            "WHERE al.action_type='trajectory' AND al.conversation_id=? "
            "AND c.owner_id=? ORDER BY al.created_at ASC",
            (conversation_id, self.owner_id),
        )
        all_steps = []
        total_duration = 0
        for row in rows:
            try:
                action = json.loads(row.get("action_data") or "{}")
            except Exception:
                action = {}
            all_steps.extend(action.get("steps", []) or [])
            total_duration += int(action.get("total_duration_ms") or 0)
        steps = [self._build_step(step, {"round": 1}) for step in all_steps]
        titles = await self._conversation_title_map({conversation_id})
        fails = sum(1 for step in steps if step.get("success") is False)
        return {
            "conversation_id": conversation_id,
            "conversation_title": titles.get(conversation_id, ""),
            "step_count": len(steps),
            "total_duration_ms": total_duration,
            "success_rate": round((len(steps) - fails) / len(steps), 3)
            if steps
            else 0,
            "fail_count": fails,
            "steps": steps,
            "trajectory_count": len(rows),
        }

    async def get_stats(self) -> dict:
        rows = await self._fetch_all(
            "SELECT al.* FROM agent_logs al "
            "JOIN conversations c ON c.id=al.conversation_id "
            "WHERE al.action_type='trajectory' AND c.owner_id=? "
            "ORDER BY al.created_at DESC LIMIT 500",
            (self.owner_id,),
        )
        total_steps = tool_calls = agent_calls = 0
        tool_success = agent_success = think_steps = rounds = 0
        conversations = set()
        for row in rows:
            conversations.add(row.get("conversation_id"))
            try:
                action = json.loads(row.get("action_data") or "{}")
            except Exception:
                continue
            for step in action.get("steps", []) or []:
                total_steps += 1
                phase = step.get("phase", "")
                rounds = max(rounds, int(step.get("round", 0) or 0))
                if phase == "tool":
                    tool_calls += 1
                    tool_success += int(bool(step.get("success")))
                elif phase == "agent":
                    agent_calls += 1
                    agent_success += int(bool(step.get("success")))
                elif phase == "think":
                    think_steps += 1
        return {
            "trajectory_count": len(rows),
            "conversation_count": len(conversations),
            "total_steps": total_steps,
            "tool_calls": tool_calls,
            "tool_success_rate": round(tool_success / tool_calls, 3)
            if tool_calls
            else 0,
            "agent_calls": agent_calls,
            "agent_success_rate": round(agent_success / agent_calls, 3)
            if agent_calls
            else 0,
            "max_rounds": rounds,
            "think_steps": think_steps,
            "avg_steps_per_traj": round(total_steps / len(rows), 1) if rows else 0,
        }

    async def delete_trajectories(
        self, conversation_id: Optional[str] = None
    ) -> int:
        if conversation_id:
            await self._require_conversation(conversation_id)
            result = await self._execute(
                "DELETE FROM agent_logs WHERE action_type='trajectory' "
                "AND conversation_id=? AND EXISTS "
                "(SELECT 1 FROM conversations c WHERE c.id=agent_logs.conversation_id "
                "AND c.owner_id=?)",
                (conversation_id, self.owner_id),
            )
        else:
            result = await self._execute(
                "DELETE FROM agent_logs WHERE action_type='trajectory' AND EXISTS "
                "(SELECT 1 FROM conversations c WHERE c.id=agent_logs.conversation_id "
                "AND c.owner_id=?)",
                (self.owner_id,),
            )
        if hasattr(result, "rowcount"):
            return max(0, int(result.rowcount))
        if isinstance(result, str):
            try:
                return int(result.split()[-1])
            except (ValueError, IndexError):
                pass
        return 0


__all__ = ["TrajectoryRepository"]
