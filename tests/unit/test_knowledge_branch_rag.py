"""
知识问答分支（v2.4 RAG 增强）单元测试

覆盖:
  - RAG 引擎存在时优先走 Agentic-RAG（answer 被调用）
  - 输出 rag_progress / rag_sources 事件
  - structured_result.rag 元信息完整（sources/grounding/used）
  - RAG 引擎不可用 → 降级 LLM 直答（不阻断）
  - RAG answer 抛异常 → 降级 LLM 直答（主链路永不阻断）
  - 兼容: 无 knowledge-001 Agent / 无 rag_engine 时行为不变
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, AsyncMock

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
    )
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.orchestrator.react_loop import TrueReActLoop


def _make_orchestrator():
    """构造带 knowledge-001 + rag_engine 的 orchestrator mock。"""
    orch = MagicMock()

    # RAG 引擎
    rag = AsyncMock()
    rag.answer = AsyncMock(return_value={
    "answer": "## 知识库检索结果\n> MITRE T1190 说明",
    "structured_sources": [
    {"source_type": "mitre", "id": "T1190", "title": "T1190: 利用面向公众的应用",
    "score": 1.0, "snippet": "利用面向公众的应用漏洞"},
    ],
    "grounding_score": 1.0,
    "grounding_detail": "知识库支撑充足",
    "has_grounding": True,
    "retrieval_rounds": 1,
    })

    knowledge_info = MagicMock()
    knowledge_info.instance = MagicMock()
    knowledge_info.instance.rag_engine = rag
    orch.agents = {"knowledge-001": knowledge_info}

    # LLM（降级直答用）— 显式追踪是否被调用
    orch.llm = MagicMock()
    orch.llm.chat_stream_called = False

    async def mock_chat_stream(messages):
        orch.llm.chat_stream_called = True
        for chunk in ["降级", "回答"]:
            yield chunk

    orch.llm.chat_stream = mock_chat_stream

    return orch, rag


async def _run_branch(orch, text="什么是SQLite"):
    loop = TrueReActLoop(orch)
    chunks = []
    async for c in loop._run_knowledge_branch(text, "conv-test", {
        "template_type": "安全知识", "is_knowledge_query": True,
    }):
        chunks.append(c)
    return chunks


class TestKnowledgeBranchRAG:
    @pytest.mark.asyncio
    async def test_rag_used_when_engine_present(self):
        """RAG 引擎存在 -> 优先调用 answer()，而非 LLM 直答。"""
        orch, rag = _make_orchestrator()
        chunks = await _run_branch(orch)
        rag.answer.assert_awaited_once()
        # 不调用 LLM 直答
        assert orch.llm.chat_stream_called is False

    @pytest.mark.asyncio
    async def test_rag_sources_event_emitted(self):
        """输出 rag_sources 事件（结构化来源 + grounding）。"""
        orch, _ = _make_orchestrator()
        chunks = await _run_branch(orch)
        rag_sources = [c for c in chunks if c.get("type") == "rag_sources"]
        assert len(rag_sources) == 1
        sources = rag_sources[0]["sources"]
        assert len(sources) == 1
        assert sources[0]["source_type"] == "mitre"
        assert sources[0]["id"] == "T1190"
        assert rag_sources[0]["grounding_score"] == 1.0
        assert rag_sources[0]["has_grounding"] is True

    @pytest.mark.asyncio
    async def test_rag_progress_events_emitted(self):
        """输出 rag_progress 检索阶段事件。"""
        orch, rag = _make_orchestrator()
        # 让 answer 回调一个进度事件
        async def answer_with_progress(query, progress_cb=None, **kw):
            if progress_cb:
                await progress_cb({"phase": "analyze", "message": "分析查询意图", "entities": []})
                return {
                "answer": "回答", "structured_sources": [], "grounding_score": 1.0,
                "grounding_detail": "充足", "has_grounding": True, "retrieval_rounds": 0,
                }
                rag.answer = answer_with_progress
                chunks = await _run_branch(orch)
                progress = [c for c in chunks if c.get("type") == "rag_progress"]
                assert len(progress) == 1
                assert progress[0]["phase"] == "analyze"
                assert progress[0]["conversation_id"] == "conv-test"

    @pytest.mark.asyncio
    async def test_structured_result_rag_metadata(self):
        """structured_result.rag 元信息完整（used/sources/grounding）。"""
        orch, _ = _make_orchestrator()
        chunks = await _run_branch(orch)
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert len(complete) == 1
        sr = complete[0]["structured_result"]
        assert sr["is_knowledge"] is True
        assert sr["score"] is None
        assert sr["rag"]["used"] is True
        assert len(sr["rag"]["sources"]) == 1
        assert sr["rag"]["has_grounding"] is True
        assert sr["rag"]["grounding_score"] == 1.0


class TestKnowledgeBranchFallback:
    @pytest.mark.asyncio
    async def test_no_rag_engine_falls_back_to_llm(self):
        """无 RAG 引擎 -> 降级 LLM 直答，不阻断。"""
        orch, _ = _make_orchestrator()
        orch.agents = {} # 移除 knowledge-001
        chunks = await _run_branch(orch)
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert len(complete) == 1
        sr = complete[0]["structured_result"]
        assert sr["rag"]["used"] is False
        assert "降级" in sr["summary_text"]

    @pytest.mark.asyncio
    async def test_rag_error_falls_back_to_llm(self):
        """RAG answer 抛异常 -> 降级 LLM 直答（主链路永不阻断）。"""
        orch, rag = _make_orchestrator()
        rag.answer = AsyncMock(side_effect=Exception("vector store 不可用"))
        chunks = await _run_branch(orch)
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert len(complete) == 1
        sr = complete[0]["structured_result"]
        assert sr["rag"]["used"] is False
        assert "降级" in sr["summary_text"]

    @pytest.mark.asyncio
    async def test_rag_no_grounding_falls_back_to_free_qa(self):
        """知识库未命中（has_grounding=False）-> 降级自由问答（LLM 直答），不被拒答。"""
        orch, rag = _make_orchestrator()
        rag.answer = AsyncMock(return_value={
        "answer": "## 知识库查询结果\n> **知识库中未找到与您问题直接匹配的安全知识内容。**\n接地评分: 0.0",
        "structured_sources": [],
        "grounding_score": 0.0,
        "grounding_detail": "知识库无相关记录",
        "has_grounding": False,
        "retrieval_rounds": 3,
        })
        chunks = await _run_branch(orch)
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert len(complete) == 1
        sr = complete[0]["structured_result"]
        # 不应输出 RAG 的"找不到就不答"文案
        assert "知识库中未找到" not in sr["summary_text"]
        # 已降级为自由问答：LLM 直答内容生效
        assert "降级" in sr["summary_text"]
        assert orch.llm.chat_stream_called is True
        # rag 元信息：used=True（RAG 执行了检索），但 free_qa_fallback=True
        assert sr["rag"]["used"] is True
        assert sr["rag"]["has_grounding"] is False
        assert sr["rag"]["free_qa_fallback"] is True

    @pytest.mark.asyncio
    async def test_rag_sources_event_carries_free_qa_flag(self):
        """rag_sources 事件透出 free_qa_fallback，供前端弱化'幻觉风险'措辞。"""
        orch, rag = _make_orchestrator()
        rag.answer = AsyncMock(return_value={
        "answer": "拒绝文案", "structured_sources": [],
        "grounding_score": 0.0, "grounding_detail": "无记录",
        "has_grounding": False, "retrieval_rounds": 3,
        })
        chunks = await _run_branch(orch)
        rag_sources = [c for c in chunks if c.get("type") == "rag_sources"]
        assert len(rag_sources) == 1
        assert rag_sources[0]["has_grounding"] is False
        assert rag_sources[0]["free_qa_fallback"] is True

    @pytest.mark.asyncio
    async def test_free_qa_fallback_can_be_disabled_by_config(self):
        """配置 free_qa_fallback=false -> 保留 RAG 原拒答文案（不回退 LLM 直答）。"""
        orch, rag = _make_orchestrator()
        # 配置关闭自由问答降级
        orch.get_config = MagicMock(return_value={
        "agents": {"knowledge": {"free_qa_fallback": False}},
        })

        refusal = "## 知识库查询结果\n> **知识库中未找到与您问题直接匹配的安全知识内容。**"
        rag.answer = AsyncMock(return_value={
        "answer": refusal, "structured_sources": [],
        "grounding_score": 0.0, "grounding_detail": "无记录",
        "has_grounding": False, "retrieval_rounds": 3,
        })
        chunks = await _run_branch(orch)
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        sr = complete[0]["structured_result"]
        assert "知识库中未找到" in sr["summary_text"]
        assert orch.llm.chat_stream_called is False
        assert sr["rag"]["free_qa_fallback"] is False

    @pytest.mark.asyncio
    async def test_no_agents_no_rag_no_llm_graceful(self):
        """极端: 无 Agent、无 rag_engine、LLM 也失败 -> 仍输出 complete 兜底。"""
        orch, _ = _make_orchestrator()
        orch.agents = {}

        async def broken_stream(messages):
            raise Exception("LLM API 失败")
            orch.llm.chat_stream = broken_stream

            chunks = await _run_branch(orch)
            complete = [c for c in chunks if c.get("type") == "true_react_complete"]
            assert len(complete) == 1
            assert complete[0]["structured_result"]["summary_text"]


class TestKnowledgeBranchCompat:
    @pytest.mark.asyncio
    async def test_start_event_payload(self):
        """true_react_start 事件含知识问答模式标记。"""
        orch, _ = _make_orchestrator()
        chunks = await _run_branch(orch)
        start = chunks[0]
        assert start["type"] == "true_react_start"
        assert "知识问答模式" in start["content"]
        assert start["max_rounds"] == 1
