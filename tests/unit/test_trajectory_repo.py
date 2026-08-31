"""
执行轨迹仓库（v2.4 M3）单元测试

覆盖:
  - save_trajectory 写入 agent_logs 表
  - get_trajectories 查询（按会话过滤 / 全部）
  - get_conversation_trajectory 合并多段轨迹
  - get_stats 聚合统计（工具成功率 / Agent 成功率 / 轮次）
  - delete_trajectories 清理
"""

import os
import sys
import json
import pytest
from datetime import datetime, timezone

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
    )
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.storage.database import Database
from backend.storage.repositories.trajectory_repo import TrajectoryRepository


@pytest.fixture
def repo():
    db = Database(":memory:")
    conn = db.connect()
    from backend.storage.models import SCHEMA_SQL
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    now = datetime.now(timezone.utc).isoformat()
    for cid in ("conv-1", "conv-2"):
        db.execute(
            "INSERT INTO conversations (id, owner_id, title, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (cid, "test-owner", cid, now, now),
        )
    yield TrajectoryRepository(db, owner_id="test-owner")
    db.close()


def _sample_trajectory():
    return [
    {"step_id": "step-1", "phase": "think", "round": 1, "actor": "LLM",
    "input": "用户问题", "output": "决策", "success": True, "duration_ms": 500,
    "timestamp": 1.0, "type": "think"},
    {"step_id": "step-2", "phase": "tool", "round": 1, "actor": "threat_intel",
    "input": '{"ip": "1.2.3.4"}', "output": "{\"malicious\": true}",
    "success": True, "duration_ms": 120, "timestamp": 1.1, "type": "tool",
    "tool_name": "threat_intel"},
    {"step_id": "step-3", "phase": "agent", "round": 1, "actor": "analyst-001",
    "input": "分析告警", "output": "verdict=malicious", "success": True,
    "duration_ms": 800, "timestamp": 1.2, "type": "agent", "agent_id": "analyst-001"},
    ]


class TestTrajectorySave:
    @pytest.mark.asyncio
    async def test_save_and_get(self, repo):
        tid = await repo.save_trajectory("conv-1", _sample_trajectory(), total_duration_ms=1500)
        assert tid
        rows = await repo.get_trajectories(conversation_id="conv-1")
        assert len(rows) == 1
        assert rows[0]["conversation_id"] == "conv-1"
        assert rows[0]["step_count"] == 3
        assert rows[0]["steps"][1]["phase"] == "tool"
        assert rows[0]["total_duration_ms"] == 1500

    @pytest.mark.asyncio
    async def test_save_multiple_conversations(self, repo):
        await repo.save_trajectory("conv-1", _sample_trajectory())
        await repo.save_trajectory("conv-2", _sample_trajectory())
        rows = await repo.get_trajectories() # 全部
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_filter_by_conversation(self, repo):
        await repo.save_trajectory("conv-1", _sample_trajectory())
        await repo.save_trajectory("conv-2", _sample_trajectory())
        rows = await repo.get_trajectories(conversation_id="conv-1")
        assert len(rows) == 1
        assert rows[0]["conversation_id"] == "conv-1"


class TestTrajectoryMerge:
    @pytest.mark.asyncio
    async def test_merge_multiple_segments(self, repo):
        """同一会话多次执行 -> 合并为一条完整时间线。"""
        await repo.save_trajectory("conv-1", _sample_trajectory(), total_duration_ms=1000)
        await repo.save_trajectory("conv-1", _sample_trajectory(), total_duration_ms=2000)
        merged = await repo.get_conversation_trajectory("conv-1")
        assert merged["conversation_id"] == "conv-1"
        assert merged["step_count"] == 6 # 3+3
        assert merged["trajectory_count"] == 2
        assert merged["total_duration_ms"] == 3000

    @pytest.mark.asyncio
    async def test_merge_empty(self, repo):
        from backend.storage.repositories.conversation_repo import ConversationAccessDenied
        with pytest.raises(ConversationAccessDenied):
            await repo.get_conversation_trajectory("nonexistent")


class TestTrajectoryStats:
    @pytest.mark.asyncio
    async def test_stats(self, repo):
        await repo.save_trajectory("conv-1", _sample_trajectory())
        # 追加一条失败的工具调用
        await repo.save_trajectory("conv-1", [
        {"phase": "tool", "round": 2, "actor": "cve_search", "success": False,
        "duration_ms": 10, "type": "tool"},
        ])
        stats = await repo.get_stats()
        assert stats["trajectory_count"] == 2
        assert stats["conversation_count"] == 1
        assert stats["total_steps"] == 4
        assert stats["tool_calls"] == 2
        assert stats["tool_success_rate"] == 0.5
        assert stats["agent_calls"] == 1
        assert stats["agent_success_rate"] == 1.0
        assert stats["max_rounds"] == 2


class TestTrajectoryDelete:
    @pytest.mark.asyncio
    async def test_delete_by_conversation(self, repo):
        await repo.save_trajectory("conv-1", _sample_trajectory())
        await repo.save_trajectory("conv-2", _sample_trajectory())
        await repo.delete_trajectories(conversation_id="conv-1")
        rows = await repo.get_trajectories()
        assert len(rows) == 1
        assert rows[0]["conversation_id"] == "conv-2"

    @pytest.mark.asyncio
    async def test_delete_all(self, repo):
        await repo.save_trajectory("conv-1", _sample_trajectory())
        await repo.save_trajectory("conv-2", _sample_trajectory())
        await repo.delete_trajectories()
        assert len(await repo.get_trajectories()) == 0
