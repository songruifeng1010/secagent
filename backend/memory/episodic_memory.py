"""
EpisodicMemory — 情景记忆（v2.4 M4）

沉淀已完成的安全研判案例（复用 experiences 表）：
  - record_episode: 完成一次威胁研判后写入案例
  - recall_similar: 按场景关键词/向量检索召回相似案例
  - 每次召回自增 times_used

字段（对齐 experiences 表）:
  scenario / input_summary / actions_taken / outcome / lessons / vector_id / times_used
"""
import uuid
import json
import re
from datetime import datetime, timezone
from typing import Optional
from ..storage.database import Repository


class EpisodicMemory:
    """情景记忆 — 历史研判案例沉淀与召回。"""

    def __init__(self, db=None):
        self.db = db if db is not None else Repository()

    async def _execute(self, sql: str, params: tuple = ()):
        if isinstance(self.db, Repository):
            return await self.db.execute(sql, params)
        return self.db.execute(sql, params)

    async def _fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        if isinstance(self.db, Repository):
            return await self.db.fetch_all(sql, params)
        return self.db.fetch_all(sql, params)

    async def _fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        if isinstance(self.db, Repository):
            return await self.db.fetch_one(sql, params)
        return self.db.fetch_one(sql, params)

    async def record_episode(self, scenario: str, input_summary: str = "",
                             actions_taken: list = None, outcome: str = "",
                             lessons: str = "") -> str:
        """沉淀一个研判案例。返回案例 ID。"""
        eid = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        await self._execute(
            "INSERT INTO experiences (id, scenario, input_summary, actions_taken, outcome, lessons, created_at, times_used) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (
                eid, scenario, input_summary,
                json.dumps(actions_taken or [], ensure_ascii=False),
                outcome, lessons, now,
            ),
        )
        return eid

    async def recall_similar(self, query: str, limit: int = 5) -> list[dict]:
        """按场景关键词召回相似案例（关键词重叠 + 时间倒序）。

        关键词提取策略：
          1. 按分隔符拆词（空格/逗号/句号）
          2. 整段无分隔时按 2-gram 拆分
        """
        import re
        terms = [t for t in re.split(r'[\s,，。；;、]+', query) if len(t) >= 2]
        if len(terms) <= 1 and len(query) >= 4:
            terms = [query[i:i + 2] for i in range(len(query) - 1)]
        query_terms = list(dict.fromkeys(terms))[:12]

        rows = await self._fetch_all(
            "SELECT * FROM experiences ORDER BY created_at DESC LIMIT 100", (),
        )
        scored = []
        for r in rows:
            scenario = r.get("scenario") or ""
            input_summary = r.get("input_summary") or ""
            score = 0
            for t in query_terms:
                if len(t) >= 2 and t in scenario:
                    score += 2
                elif len(t) >= 2 and t in input_summary:
                    score += 1
            if score > 0:
                scored.append((score, r))
        scored.sort(key=lambda x: -x[0])

        out = []
        for _, r in scored[:limit]:
            eid = r["id"]
            # 自增 times_used（失败静默，不影响召回）
            try:
                await self._execute(
                    "UPDATE experiences SET times_used = times_used + 1 WHERE id = ?",
                    (eid,),
                )
            except Exception:
                pass
            out.append({
                "id": eid,
                "scenario": r.get("scenario", ""),
                "input_summary": r.get("input_summary", ""),
                "actions_taken": json.loads(r.get("actions_taken") or "[]") or [],
                "outcome": r.get("outcome", ""),
                "lessons": r.get("lessons", ""),
                "times_used": (r.get("times_used") or 0) + 1,
                "created_at": r.get("created_at", ""),
            })
        return out

    async def list_episodes(self, limit: int = 20) -> list[dict]:
        rows = await self._fetch_all(
            "SELECT * FROM experiences ORDER BY times_used DESC, created_at DESC LIMIT ?",
            (limit,),
        )
        return [{
            "id": r.get("id"),
            "scenario": r.get("scenario"),
            "input_summary": r.get("input_summary", ""),
            "outcome": r.get("outcome", ""),
            "lessons": r.get("lessons", ""),
            "times_used": r.get("times_used", 0),
            "created_at": r.get("created_at", ""),
        } for r in rows]

    async def count(self) -> int:
        row = await self._fetch_one("SELECT COUNT(*) AS n FROM experiences", ())
        return row.get("n", 0) if row else 0


__all__ = ["EpisodicMemory"]

