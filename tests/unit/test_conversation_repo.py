"""
会话仓库（v2.9 编辑/撤回）单元测试

覆盖:
  - save_message / get_messages 基础读写
  - update_message 编辑消息内容
  - delete_message 撤回单条
  - delete_messages_since 撤回某条及其后所有（连坐删除 AI 回复）
  - 编辑/撤回后 get_messages 结果正确
"""

import os
import sys
import pytest

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
    )
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.storage.database import Database
from backend.storage.repositories.conversation_repo import ConversationRepository


@pytest.fixture
def repo():
    db = Database(":memory:")
    conn = db.connect()
    from backend.storage.models import SCHEMA_SQL
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    yield ConversationRepository(db, owner_id="test-owner")
    db.close()


async def _seed_conversation(repo, cid="conv-1"):
    """写入：user 问 -> AI 答 -> user 再问 -> AI 再答"""
    await repo.create_conversation(title="测试会话", conversation_id=cid)
    m1 = await repo.save_message(cid, "user", "什么是SQLite", agent_id="orchestrator")
    a1 = await repo.save_message(cid, "assistant", "SQLite是嵌入式数据库", agent_id="orchestrator")
    m2 = await repo.save_message(cid, "user", "它和MySQL有什么区别", agent_id="orchestrator")
    a2 = await repo.save_message(cid, "assistant", "MySQL是服务器型数据库", agent_id="orchestrator")
    return m1, a1, m2, a2


class TestConversationRepo:
    @pytest.mark.asyncio
    async def test_save_and_get_messages(self, repo):
        await _seed_conversation(repo)
        rows = await repo.get_messages("conv-1")
        assert len(rows) == 4
        assert rows[0]["role"] == "user"
        assert rows[1]["role"] == "assistant"

    @pytest.mark.asyncio
    async def test_update_message(self, repo):
        m1, *_ = await _seed_conversation(repo)
        ok = await repo.update_message("conv-1", m1, "什么是SQLite（编辑后）")
        assert ok is True
        rows = await repo.get_messages("conv-1")
        assert rows[0]["content"] == "什么是SQLite（编辑后）"

    @pytest.mark.asyncio
    async def test_delete_single_message(self, repo):
        m1, a1, *_ = await _seed_conversation(repo)
        ok = await repo.delete_message("conv-1", a1)
        assert ok is True
        rows = await repo.get_messages("conv-1")
        # 仅删除 AI 回复，保留 3 条
        assert len(rows) == 3
        assert not any(r["id"] == a1 for r in rows)

    @pytest.mark.asyncio
    async def test_delete_messages_since_cascades(self, repo):
        """撤回 user 消息 -> 连带删除其后所有（AI 回复连坐）"""
        m1, a1, m2, a2 = await _seed_conversation(repo)
        deleted = await repo.delete_messages_since("conv-1", m2)
        assert deleted == 2 # m2 + a2
        rows = await repo.get_messages("conv-1")
        assert len(rows) == 2 # 仅剩 m1 + a1
        assert [r["id"] for r in rows] == [m1, a1]

    @pytest.mark.asyncio
    async def test_delete_messages_since_mid(self, repo):
        """撤回中间消息 -> 其后的全删（含前面 AI 回复前的 user）"""
        m1, a1, m2, a2 = await _seed_conversation(repo)
        deleted = await repo.delete_messages_since("conv-1", a1)
        assert deleted == 3 # a1 + m2 + a2
        rows = await repo.get_messages("conv-1")
        assert len(rows) == 1
        assert rows[0]["id"] == m1

    @pytest.mark.asyncio
    async def test_delete_nonexistent_returns_zero(self, repo):
        await repo.create_conversation(title="测试会话", conversation_id="conv-1")
        deleted = await repo.delete_messages_since("conv-1", "ghost-id")
        assert deleted == 0

    @pytest.mark.asyncio
    async def test_title_auto_generated_from_first_user_message(self, repo):
        """首条 user 消息自动生成会话标题（替换默认 WebSocket对话 xxx）"""
        cid = await repo.create_conversation(title="WebSocket对话 ws-xxx", conversation_id="conv-t")
        await repo.save_message(cid, "user", "分析一下 45.33.32.156 的可疑行为", agent_id="orchestrator")
        conv = await repo.get_conversation(cid)
        # 标题取首条 user 消息前 20 字
        assert conv["title"] == "分析一下 45.33.32.156 的可"
        # 已命名的会话不覆盖
        cid2 = await repo.create_conversation(title="我的自定义标题", conversation_id="conv-t2")
        await repo.save_message(cid2, "user", "另一个问题", agent_id="orchestrator")
        conv2 = await repo.get_conversation(cid2)
        assert conv2["title"] == "我的自定义标题"

    @pytest.mark.asyncio
    async def test_delete_conversation_cascades(self, repo):
        """删除会话 -> 连带删除消息和轨迹"""
        cid = await repo.create_conversation(title="待删", conversation_id="conv-del")
        await repo.save_message(cid, "user", "问题", agent_id="orchestrator")
        await repo.save_message(cid, "assistant", "回答", agent_id="orchestrator")
        # 写一条轨迹
        from backend.storage.repositories.trajectory_repo import TrajectoryRepository
        tr = TrajectoryRepository(repo.db, owner_id=repo.owner_id)
        await tr.save_trajectory(cid, [{"step_id": "s1", "phase": "think"}], total_duration_ms=100)
        await repo.delete_conversation(cid)
        from backend.storage.repositories.conversation_repo import ConversationAccessDenied
        with pytest.raises(ConversationAccessDenied):
            await repo.get_messages(cid)
        conv = await repo.get_conversation(cid)
        assert conv is None
