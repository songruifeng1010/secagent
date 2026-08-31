"""
记忆模块（v2.4 M4）单元测试

覆盖:
  - SessionMemory: 写入/去重/容量/时间衰减/召回排序
  - EpisodicMemory: 记录案例/关键词召回/次数自增
  - SemanticMemory: 高置信度沉淀/低置信度跳过/向量召回
  - MemoryManager: 三层整合/build_context/从研判结果沉淀
"""
import os
import sys
import json
import pytest
from unittest.mock import MagicMock

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
)
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.memory.session_memory import SessionMemory
from backend.memory.manager import MemoryManager


# ═══════════════════════ SessionMemory ═══════════════════════

class TestSessionMemory:
    def test_remember_and_recall(self):
        m = SessionMemory("s1")
        m.remember("IP 1.2.3.4 确认恶意", category="ip", confidence=0.9)
        m.remember("CVE-2024-3094 高危", category="cve", confidence=0.8)
        recalled = m.recall(limit=10)
        assert len(recalled) == 2
        # 按置信度排序：0.9 在前
        assert recalled[0]["content"].startswith("IP")
        assert recalled[0]["effective_confidence"] == pytest.approx(0.9)

    def test_deduplicate_same_content(self):
        m = SessionMemory("s1")
        m.remember("IP 1.2.3.4 确认恶意", category="ip", confidence=0.6)
        m.remember("IP 1.2.3.4 确认恶意", category="ip", confidence=0.95)
        assert m.count() == 1
        assert m.recall(limit=1)[0]["confidence"] == pytest.approx(0.95)

    def test_capacity_limit(self):
        m = SessionMemory("s1", max_facts=3)
        for i in range(5):
            m.remember(f"fact {i}", category="general", confidence=0.5)
        assert m.count() == 3
        # 最旧的被丢弃（fact 0, 1）
        contents = [f["content"] for f in m.recall(limit=10)]
        assert "fact 0" not in contents
        assert "fact 4" in contents

    def test_time_decay(self):
        m = SessionMemory("s1", half_life=1.0) # 1 秒半衰期
        m.remember("旧记忆", category="general", confidence=1.0)
        # 伪造旧时间戳
        m.facts[0]["created_at"] -= 2 # 2 秒前 -> 衰减到 0.25
        recalled = m.recall(limit=1)
        assert recalled[0]["effective_confidence"] < 0.3

    def test_filter_by_category_and_keyword(self):
        m = SessionMemory("s1")
        m.remember("IP 8.8.8.8 良性", category="ip", confidence=0.7)
        m.remember("CVE-2024-1111 中危", category="cve", confidence=0.6)
        ips = m.recall(category="ip", limit=10)
        assert len(ips) == 1
        assert ips[0]["category"] == "ip"
        cves = m.recall(keyword="CVE", limit=10)
        assert len(cves) == 1
        assert "CVE" in cves[0]["content"]

    def test_to_context_filters_low_confidence(self):
        m = SessionMemory("s1", half_life=1.0)
        m.remember("高置信事实", category="general", confidence=0.9)
        m.remember("低置信事实", category="general", confidence=0.2)
        ctx = m.to_context(limit=10)
        # 低置信度被过滤
        assert all(c["confidence"] >= 0.3 for c in ctx)


        # ═══════════════════════ EpisodicMemory ═══════════════════════

class TestEpisodicMemory:
    @pytest.mark.asyncio
    async def test_record_and_recall(self):
        import sqlite3
        from backend.storage.database import Database
        from backend.storage.models import SCHEMA_SQL
        from backend.memory.episodic_memory import EpisodicMemory
        db = Database(":memory:")
        conn = db.connect()
        conn.executescript(SCHEMA_SQL)
        conn.commit()

        ep = EpisodicMemory(db)
        await ep.record_episode(
            scenario="SSH暴力破解应急响应",
            input_summary="检测到来自 45.33.32.156 的 SSH 暴力破解",
            actions_taken=["封禁 IP", "加固 SSH 配置"],
            outcome="成功阻断",
            lessons="建议开启 fail2ban",
        )
        rows = await ep.list_episodes(limit=10)
        assert len(rows) == 1
        assert rows[0]["scenario"] == "SSH暴力破解应急响应"

        # 召回相似案例
        similar = await ep.recall_similar("SSH暴力破解怎么处理", limit=5)
        assert len(similar) == 1
        assert similar[0]["scenario"].startswith("SSH")
        assert similar[0]["times_used"] >= 1
        db.close()

    @pytest.mark.asyncio
    async def test_recall_no_match(self):
        import sqlite3
        from backend.storage.database import Database
        from backend.storage.models import SCHEMA_SQL
        from backend.memory.episodic_memory import EpisodicMemory
        db = Database(":memory:")
        conn = db.connect()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        ep = EpisodicMemory(db)
        await ep.record_episode(scenario="勒索病毒应急", input_summary="", outcome="")
        similar = await ep.recall_similar("完全无关的内容xyz", limit=5)
        assert similar == []
        db.close()


        # ═══════════════════════ SemanticMemory ═══════════════════════

class TestSemanticMemory:
    def test_low_confidence_not_stored(self):
        from backend.memory.semantic_memory import SemanticMemory
        vs = MagicMock()
        sem = SemanticMemory(vector_store=vs, min_confidence=0.7)
        mid = sem.add("低置信事实", confidence=0.3)
        assert mid is None # 不沉淀

    def test_store_and_recall(self):
        from backend.memory.semantic_memory import SemanticMemory
        vs = MagicMock()
        # 模拟 ChromaDB 返回
        vs.add_documents = MagicMock(return_value=None)
        vs.similarity_search = MagicMock(return_value=[{
            "id": "mem-1",
            "document": "IP 1.2.3.4 确认恶意",
            "metadata": {"category": "verdict", "confidence": 0.9, "created_at": 100},
            "distance": 0.1,
        }])
        vs.count = MagicMock(return_value=1)
        vs.get_or_create_collection = MagicMock()
        sem = SemanticMemory(vector_store=vs)
        mid = sem.add("IP 1.2.3.4 确认恶意", category="verdict", confidence=0.9)
        assert mid is not None
        recalled = sem.recall("这个IP恶意吗", k=5)
        assert len(recalled) == 1
        assert recalled[0]["category"] == "verdict"
        assert sem.count() == 1


        # ═══════════════════════ MemoryManager ═══════════════════════

class TestMemoryManager:
    def test_build_context_empty_when_no_memory(self):
        mm = MemoryManager()
        ctx = mm.build_context("测试", session_id="s1")
        assert ctx == ""

    def test_build_context_with_session_memory(self):
        mm = MemoryManager()
        mm.remember_session("s1", "IP 8.8.8.8 此前确认恶意", category="ip", confidence=0.9)
        ctx = mm.build_context("8.8.8.8 是什么？", session_id="s1")
        assert "8.8.8.8" in ctx
        assert "会话" in ctx
        assert "置信度" in ctx

    def test_remember_from_result_verdict(self):
        mm = MemoryManager()
        mm.remember_from_result(
            "s1", "分析恶意IP",
            agent_results=[{"agent_id": "analyst-001", "verdict": "malicious", "confidence": 0.9}],
            risk_scorecard={"risk_score": 85, "risk_level": "高危"},
            verdict={"verdict": "malicious", "confidence": 0.9},
        )
        mem = mm.list_session_memory("s1")
        categories = {m["category"] for m in mem}
        assert "verdict" in categories
        assert "agent_verdict" in categories
        assert "risk" in categories

    def test_remember_from_result_low_conf_skipped(self):
        """低置信度裁决不沉淀（防噪声）。"""
        mm = MemoryManager()
        mm.remember_from_result(
            "s1", "低置信",
            agent_results=[{"agent_id": "analyst-001", "verdict": "suspicious", "confidence": 0.3}],
            risk_scorecard=None,
            verdict={"verdict": "unknown", "confidence": 0.1},
        )
        mem = mm.list_session_memory("s1")
        assert mem == []

    def test_clear_session(self):
        mm = MemoryManager()
        mm.remember_session("s1", "记忆1", confidence=0.8)
        mm.clear_session("s1")
        assert mm.list_session_memory("s1") == []

    @pytest.mark.asyncio
    async def test_stats(self):
        mm = MemoryManager()
        mm.remember_session("s1", "记忆1", confidence=0.8)
        stats = await mm.stats()
        assert stats["sessions"] == 1
        assert "episodic_count" in stats
        assert "semantic_count" in stats
