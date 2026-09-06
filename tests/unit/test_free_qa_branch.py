"""
自由问答分支（v2.8）单元测试

覆盖:
  - answer_mode 规则判定（free / rag / analysis）
  - 自由问答分支：不调用 RAG、不发 rag_sources、直接 LLM 直答
  - free_qa_direct=false → 一般咨询回退知识分支
  - free 分支注入会话历史（P3）
  - 兼容: 旧 is_knowledge_query 语义
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

from backend.models.output import predict_answer_mode
from backend.orchestrator.react_loop import TrueReActLoop


class TestPredictAnswerMode:
    def test_general_knowledge_is_free(self):
        """一般知识咨询 -> free"""
        assert predict_answer_mode("安全知识", "什么是SQLite") == "free"
        assert predict_answer_mode("安全知识", "TCP是什么") == "free"
        assert predict_answer_mode("安全知识", "你好") == "free"
        assert predict_answer_mode("安全知识", "介绍一下你自己") == "free"

    def test_security_knowledge_is_rag(self):
        """安全专业查询 -> rag"""
        assert predict_answer_mode("安全知识", "什么是SQL注入") == "rag"
        assert predict_answer_mode("安全知识", "CVE-2024-6387 漏洞详情") == "rag"
        assert predict_answer_mode("安全知识", "说说勒索软件的攻击方式") == "rag"
        assert predict_answer_mode("安全知识", "如何处置 DDoS 攻击") == "rag"
        assert predict_answer_mode("安全知识", "解释一下横向移动和提权") == "rag"
        assert predict_answer_mode("安全知识", "介绍等保合规要求") == "rag"

    def test_non_knowledge_is_analysis(self):
        """非安全知识意图 -> analysis（威胁研判）"""
        assert predict_answer_mode("攻击检测", "检测到暴力破解") == "analysis"
        assert predict_answer_mode("威胁情报", "查一下这个IP") == "analysis"

    def test_ip_domain_query_is_analysis(self):
        """IP/域名查询即使被归为安全知识 -> analysis（威胁研判，不能当闲聊直答）"""
        assert predict_answer_mode("安全知识", "查一下这个IP 45.33.32.156") == "analysis"
        assert predict_answer_mode("安全知识", "帮我分析恶意域名 evil.com") == "analysis"
        assert predict_answer_mode("安全知识", "10.0.0.1 是什么") == "analysis"


def _make_orchestrator():
    """构造带 knowledge-001 + rag_engine 的 orchestrator mock（free 分支不应使用）。"""
    orch = MagicMock()

    rag = AsyncMock()
    rag.answer = AsyncMock(return_value={
        "answer": "## 知识库检索结果\n> MITRE T1190 说明",
        "structured_sources": [],
        "grounding_score": 1.0,
        "grounding_detail": "知识库支撑充足",
        "has_grounding": True,
        "retrieval_rounds": 1,
    })
    knowledge_info = MagicMock()
    knowledge_info.instance = MagicMock()
    knowledge_info.instance.rag_engine = rag
    orch.agents = {"knowledge-001": knowledge_info}

    orch.llm = MagicMock()
    orch.llm.chat_stream_called = False
    orch.llm.last_messages = None

    async def mock_chat_stream(messages):
        orch.llm.chat_stream_called = True
        orch.llm.last_messages = messages
        for chunk in ["SQLite", " 是一种", " 嵌入式数据库"]:
            yield chunk

    orch.llm.chat_stream = mock_chat_stream
    orch.get_config = MagicMock(return_value={})
    return orch, rag


async def _run_free_branch(orch, text="什么是SQLite", history=None):
    loop = TrueReActLoop(orch)
    chunks = []
    async for c in loop._run_free_qa_branch(text, "conv-free", {
        "template_type": "安全知识", "is_knowledge_query": True, "answer_mode": "free",
    }, history):
        chunks.append(c)
    return chunks


class TestFreeQABranch:
    @pytest.mark.asyncio
    async def test_free_qa_does_not_use_rag(self):
        """free 分支：不调用 RAG、不发 rag_sources、LLM 直答。"""
        orch, rag = _make_orchestrator()
        chunks = await _run_free_branch(orch)
        rag.answer.assert_not_awaited()
        # 不出现 rag_sources / rag_progress 事件
        assert not [c for c in chunks if c.get("type") == "rag_sources"]
        assert not [c for c in chunks if c.get("type") == "rag_progress"]
        assert orch.llm.chat_stream_called is True

    @pytest.mark.asyncio
    async def test_free_qa_streams_as_plain_text(self):
        """free 分支流式回答走 stream 事件（free_qa=True），不带 structured_result。"""
        orch, _ = _make_orchestrator()
        chunks = await _run_free_branch(orch)
        # 流式 chunk -> stream 事件
        stream_chunks = [c for c in chunks if c.get("type") == "stream"]
        assert len(stream_chunks) == 3  # "SQLite" " 是一种" " 嵌入式数据库"
        assert all(c.get("free_qa") is True for c in stream_chunks)
        assert "".join(c.get("content", "") for c in stream_chunks) == "SQLite 是一种 嵌入式数据库"
        # complete 事件：不带 structured_result、answer_mode=free、content 完整
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert len(complete) == 1
        ev = complete[0]
        assert ev.get("answer_mode") == "free"
        assert ev.get("response_mode") == "plain_text"
        assert ev.get("structured_result") is None
        assert "SQLite" in ev.get("content", "")
        # 不出现 true_react_think_content（避免被收进过程时间线）
        assert not [c for c in chunks if c.get("type") == "true_react_think_content"]

    @pytest.mark.asyncio
    async def test_free_qa_injects_history(self):
        """free 分支注入最近会话历史（P3 多轮上下文）。"""
        orch, _ = _make_orchestrator()
        history = [
            {"role": "user", "content": "什么是 SQLite？"},
            {"role": "assistant", "content": "SQLite 是嵌入式数据库。"},
        ]
        await _run_free_branch(orch, "那它和 MySQL 有什么区别？", history=history)
        msgs = orch.llm.last_messages
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert msgs[1]["content"] == "什么是 SQLite？"
        assert msgs[2]["role"] == "assistant"
        assert msgs[-1]["role"] == "user"
        assert msgs[-1]["content"] == "那它和 MySQL 有什么区别？"

    @pytest.mark.asyncio
    async def test_free_qa_llm_failure_graceful(self):
        """free 分支 LLM 失败 -> 输出兜底文案，不阻断。"""
        orch, _ = _make_orchestrator()

        async def broken_stream(messages):
            raise Exception("API 失败")

        orch.llm.chat_stream = broken_stream
        chunks = await _run_free_branch(orch)
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert len(complete) == 1
        ev = complete[0]
        assert "抱歉" in ev.get("content", "")
        assert ev.get("structured_result") is None


class TestAnswerModeRouting:
    @pytest.mark.asyncio
    async def test_free_mode_routes_to_free_branch(self):
        """answer_mode=free -> 走自由问答分支，不调用 RAG 分支的 answer()。"""
        orch, rag = _make_orchestrator()
        orch.agents = {}  # 移除 knowledge-001，模拟 free 不需要 RAG
        loop = TrueReActLoop(orch)
        chunks = []
        async for c in loop.run("什么是SQLite"):
            chunks.append(c)
        # run() 会先走 _invoke_classifier（mock 返回默认），此处验证 free 分支产物
        assert orch.llm.chat_stream_called is True
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert complete
        ev = complete[0]
        assert ev.get("answer_mode") == "free"
        assert ev.get("structured_result") is None
        # 流式走 stream（free_qa 纯文本气泡）
        stream_chunks = [c for c in chunks if c.get("type") == "stream"]
        assert stream_chunks and all(c.get("free_qa") is True for c in stream_chunks)

    @pytest.mark.asyncio
    async def test_free_qa_direct_false_routes_to_rag_branch(self):
        """free_qa_direct=false -> 一般咨询也走知识分支（回退 v2.7）。"""
        orch, rag = _make_orchestrator()
        orch.get_config = MagicMock(return_value={
            "agents": {"knowledge": {"free_qa_direct": False}},
        })
        # 强制分类器判定为 free（模拟一般咨询）
        from unittest.mock import patch
        with patch.object(TrueReActLoop, "_invoke_classifier", new=AsyncMock(return_value={
            "template_type": "安全知识", "is_knowledge_query": True,
            "category_reason": "关键词预判", "priority": "中", "answer_mode": "free",
        })):
            loop = TrueReActLoop(orch)
            chunks = []
            async for c in loop.run("什么是SQLite"):
                chunks.append(c)
        # 走了知识分支 -> rag_engine.answer 被调用
        rag.answer.assert_awaited_once()
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert complete
        assert complete[0]["structured_result"]["rag"]["used"] is True

    @pytest.mark.asyncio
    async def test_rag_mode_routes_to_knowledge_branch(self):
        """answer_mode=rag -> 走知识分支（RAG 被调用）。"""
        orch, rag = _make_orchestrator()
        from unittest.mock import patch
        with patch.object(TrueReActLoop, "_invoke_classifier", new=AsyncMock(return_value={
            "template_type": "安全知识", "is_knowledge_query": True,
            "category_reason": "安全关键词", "priority": "中", "answer_mode": "rag",
        })):
            loop = TrueReActLoop(orch)
            chunks = []
            async for c in loop.run("什么是SQL注入"):
                chunks.append(c)
        rag.answer.assert_awaited_once()
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        assert complete
        sr = complete[0]["structured_result"]
        assert sr["rag"]["used"] is True
        assert sr["rag"]["has_grounding"] is True
