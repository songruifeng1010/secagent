import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..database import Database, Repository


class ConversationAccessDenied(PermissionError):
    """会话不存在或不属于当前 owner。"""


class ConversationRepository:
    """始终按 owner 隔离的对话仓储。"""

    def __init__(self, db, owner_id: str):
        if not owner_id or not owner_id.strip():
            raise ValueError("ConversationRepository 必须提供非空 owner_id")
        self.db = db
        self.owner_id = owner_id
        self._is_async = isinstance(db, Repository)
        self._last_timestamp: Optional[datetime] = None

    def _utc_now_iso(self) -> str:
        """生成仓储实例内严格递增的时间戳，避免低精度系统时钟打乱消息顺序。"""
        now = datetime.now(timezone.utc)
        if self._last_timestamp is not None and now <= self._last_timestamp:
            now = self._last_timestamp + timedelta(microseconds=1)
        self._last_timestamp = now
        return now.isoformat()

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

    @staticmethod
    def _affected_rows(result) -> int:
        """统一 SQLite cursor 与 asyncpg ``COMMAND n`` 的影响行数。"""
        if hasattr(result, "rowcount"):
            return max(0, int(result.rowcount))
        if isinstance(result, str):
            try:
                return max(0, int(result.rsplit(" ", 1)[-1]))
            except (ValueError, IndexError):
                return 0
        return 0

    async def create_conversation(
        self, title: str = "", conversation_id: str = ""
    ) -> str:
        cid = conversation_id or uuid.uuid4().hex[:12]
        now = self._utc_now_iso()
        await self._insert(
            "INSERT INTO conversations "
            "(id, owner_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (cid, self.owner_id, title, now, now),
        )
        return cid

    async def get_conversation(self, conversation_id: str) -> Optional[dict]:
        return await self._fetch_one(
            "SELECT * FROM conversations WHERE id = ? AND owner_id = ?",
            (conversation_id, self.owner_id),
        )

    async def require_conversation(self, conversation_id: str) -> dict:
        conversation = await self.get_conversation(conversation_id)
        if not conversation:
            raise ConversationAccessDenied("会话不存在或无权访问")
        return conversation

    async def list_conversations(self, limit: int = 20) -> list[dict]:
        return await self._fetch_all(
            "SELECT * FROM conversations WHERE owner_id = ? "
            "ORDER BY updated_at DESC LIMIT ?",
            (self.owner_id, max(1, min(int(limit), 200))),
        )

    async def save_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        agent_id: str = "",
        metadata: Optional[dict] = None,
        parent_id: str = "",
    ) -> str:
        await self.require_conversation(conversation_id)
        mid = uuid.uuid4().hex[:12]
        now = self._utc_now_iso()
        meta_json = json.dumps(metadata or {}, ensure_ascii=False)
        await self._insert(
            """INSERT INTO messages
               (id, conversation_id, role, agent_id, content, metadata, parent_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (mid, conversation_id, role, agent_id, content, meta_json, parent_id, now),
        )
        await self._execute(
            "UPDATE conversations SET updated_at = ? "
            "WHERE id = ? AND owner_id = ?",
            (now, conversation_id, self.owner_id),
        )
        if role == "user" and content.strip():
            title = " ".join(content.split())[:20]
            await self._execute(
                "UPDATE conversations SET title = ? "
                "WHERE id = ? AND owner_id = ? AND "
                "(title = '' OR title LIKE 'WebSocket%' OR title LIKE 'CLI%')",
                (title, conversation_id, self.owner_id),
            )
        return mid

    async def get_messages(
        self, conversation_id: str, limit: int = 50
    ) -> list[dict]:
        await self.require_conversation(conversation_id)
        return await self._fetch_all(
            """SELECT m.* FROM messages m
               JOIN conversations c ON c.id = m.conversation_id
               WHERE m.conversation_id = ? AND c.owner_id = ?
               ORDER BY m.created_at ASC LIMIT ?""",
            (conversation_id, self.owner_id, max(1, min(int(limit), 500))),
        )

    async def update_message(
        self, conversation_id: str, message_id: str, content: str
    ) -> bool:
        """编辑当前用户会话中的消息。"""
        await self.require_conversation(conversation_id)
        now = self._utc_now_iso()
        result = await self._execute(
            "UPDATE messages SET content = ? WHERE id = ? AND conversation_id = ? "
            "AND EXISTS (SELECT 1 FROM conversations c WHERE c.id = messages.conversation_id "
            "AND c.owner_id = ?)",
            (content, message_id, conversation_id, self.owner_id),
        )
        changed = self._affected_rows(result) > 0
        if changed:
            await self._execute(
                "UPDATE conversations SET updated_at = ? WHERE id = ? AND owner_id = ?",
                (now, conversation_id, self.owner_id),
            )
        return changed

    async def delete_message(self, conversation_id: str, message_id: str) -> bool:
        """撤回当前用户会话中的单条消息。"""
        await self.require_conversation(conversation_id)
        result = await self._execute(
            "DELETE FROM messages WHERE id = ? AND conversation_id = ? "
            "AND EXISTS (SELECT 1 FROM conversations c WHERE c.id = messages.conversation_id "
            "AND c.owner_id = ?)",
            (message_id, conversation_id, self.owner_id),
        )
        return self._affected_rows(result) > 0

    async def delete_messages_since(
        self, conversation_id: str, message_id: str
    ) -> int:
        """删除指定消息以及同一会话中其后的消息。"""
        await self.require_conversation(conversation_id)
        target = await self._fetch_one(
            "SELECT m.created_at FROM messages m JOIN conversations c "
            "ON c.id = m.conversation_id WHERE m.id = ? AND m.conversation_id = ? "
            "AND c.owner_id = ?",
            (message_id, conversation_id, self.owner_id),
        )
        if not target:
            return 0
        result = await self._execute(
            "DELETE FROM messages WHERE conversation_id = ? AND created_at >= ? "
            "AND EXISTS (SELECT 1 FROM conversations c WHERE c.id = messages.conversation_id "
            "AND c.owner_id = ?)",
            (conversation_id, target["created_at"], self.owner_id),
        )
        return self._affected_rows(result)

    async def delete_conversation(self, conversation_id: str) -> bool:
        """删除当前用户的会话及其消息、执行轨迹。"""
        await self.require_conversation(conversation_id)
        await self._execute(
            "DELETE FROM messages WHERE conversation_id = ? AND EXISTS "
            "(SELECT 1 FROM conversations c WHERE c.id = messages.conversation_id "
            "AND c.owner_id = ?)",
            (conversation_id, self.owner_id),
        )
        await self._execute(
            "DELETE FROM agent_logs WHERE conversation_id = ? AND EXISTS "
            "(SELECT 1 FROM conversations c WHERE c.id = agent_logs.conversation_id "
            "AND c.owner_id = ?)",
            (conversation_id, self.owner_id),
        )
        result = await self._execute(
            "DELETE FROM conversations WHERE id = ? AND owner_id = ?",
            (conversation_id, self.owner_id),
        )
        return self._affected_rows(result) > 0


__all__ = ["ConversationAccessDenied", "ConversationRepository"]
