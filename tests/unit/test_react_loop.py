"""
TrueReAct 循环引擎单元测试
覆盖: 路由分发、重复检测、超时熔断、Agent 结果聚合

运行: python -m pytest tests/unit/test_react_loop.py -v
"""
import os
import sys
import json
import tempfile
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

_test_dir = tempfile.mkdtemp(prefix="secagentx_test_react_")
os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(os.path.dirname(__file__), "..", "..", "knowledge_data")
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


async def _async_gen_from_list(items):
    """辅助函数：将列表转为异步生成器"""
    for item in items:
        yield item


class TestRouteToAgent:
    """_route_to_agent 方法测试"""

    @pytest.mark.asyncio
    async def test_route_to_agent_success(self):
        """路由到 Agent 成功返回分析结果"""
        from backend.orchestrator.react_loop import TrueReActLoop
        from backend.tools.registry import ToolRegistry
        from backend.tools.geoip import GeoIPTool

        orch = MagicMock()
        orch.llm = MagicMock()
        orch.tools = ToolRegistry()
        orch.tools.register(GeoIPTool())

        # 使用真正的 async generator 函数（不通过 AsyncMock 包装）
        async def mock_process(msg):
            yield {
                "type": "agent_result",
                "content": "分析完成，IP 45.33.32.156 存在 SSH 暴力破解",
                "structured": {"verdict": "malicious", "confidence": 0.85},
                "tool_calls": [],
                "duration_ms": 1234,
            }

        mock_info = MagicMock()
        mock_info.name = "安全分析师"
        mock_info.description = "告警分析"
        mock_info.enabled = True
        mock_info.instance = MagicMock()
        mock_info.instance.status = "idle"
        mock_info.instance.stats = {"tasks_completed": 0, "tasks_failed": 0, "total_duration_ms": 0, "total_tokens": 0, "last_duration_ms": 0, "last_tokens": 0}
        mock_info.instance.process_message = mock_process

        orch.agents = {"analyst-001": mock_info}

        loop = TrueReActLoop(orch)
        result = await loop._route_to_agent("analyst-001", "分析告警", {"ip": "45.33.32.156"})

        assert result["content"] == "分析完成，IP 45.33.32.156 存在 SSH 暴力破解"
        assert result["structured"]["verdict"] == "malicious"

    @pytest.mark.asyncio
    async def test_route_to_disabled_agent(self):
        """路由到已禁用的 Agent 应返回错误"""
        from backend.orchestrator.react_loop import TrueReActLoop

        orch = MagicMock()
        orch.llm = MagicMock()
        orch.tools = MagicMock()
        orch.tools.list_tools.return_value = []

        mock_info = MagicMock()
        mock_info.enabled = False
        orch.agents = {"analyst-001": mock_info}

        loop = TrueReActLoop(orch)
        result = await loop._route_to_agent("analyst-001", "任务")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_route_to_nonexistent_agent(self):
        """路由到不存在的 Agent 应返回错误"""
        from backend.orchestrator.react_loop import TrueReActLoop

        orch = MagicMock()
        orch.llm = MagicMock()
        orch.tools = MagicMock()
        orch.tools.list_tools.return_value = []
        orch.agents = {}

        loop = TrueReActLoop(orch)
        result = await loop._route_to_agent("ghost-999", "任务")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_agent_error_propagated(self):
        """Agent 内部错误应传播"""
        from backend.orchestrator.react_loop import TrueReActLoop
        from backend.tools.registry import ToolRegistry

        orch = MagicMock()
        orch.llm = MagicMock()
        orch.tools = ToolRegistry()

        async def mock_process_with_error(msg):
            yield {"type": "agent_error", "error": "LLM 调用超时"}

        mock_info = MagicMock()
        mock_info.name = "分析师"
        mock_info.description = "分析"
        mock_info.enabled = True
        mock_info.instance = MagicMock()
        mock_info.instance.status = "idle"
        mock_info.instance.stats = {"tasks_completed": 0, "tasks_failed": 0, "total_duration_ms": 0, "total_tokens": 0, "last_duration_ms": 0, "last_tokens": 0}
        mock_info.instance.process_message = mock_process_with_error
        orch.agents = {"analyst-001": mock_info}

        loop = TrueReActLoop(orch)
        result = await loop._route_to_agent("analyst-001", "任务")
        assert "error" in result
        assert "LLM 调用超时" in result["error"]


class TestBuildAgentRouterTool:
    """构建 route_to_agent 工具定义测试"""

    def test_build_agent_router_tool(self):
        from backend.orchestrator.react_loop import TrueReActLoop

        orch = MagicMock()
        orch.llm = MagicMock()
        orch.tools = MagicMock()
        orch.tools.list_tools.return_value = []

        mock_info1 = MagicMock()
        mock_info1.name = "安全分析师"
        mock_info1.description = "告警分析"
        mock_info1.enabled = True

        mock_info2 = MagicMock()
        mock_info2.name = "威胁情报员"
        mock_info2.description = "情报查询"
        mock_info2.enabled = True

        orch.agents = {"analyst-001": mock_info1, "intel-001": mock_info2}

        loop = TrueReActLoop(orch)
        router_def = loop._build_agent_router_tool()

        assert router_def["type"] == "function"
        assert router_def["function"]["name"] == "route_to_agent"
        params = router_def["function"]["parameters"]
        assert "analyst-001" in params["properties"]["agent_id"]["enum"]
        assert "intel-001" in params["properties"]["agent_id"]["enum"]


class TestReactLoopStreaming:
    """循环流式输出测试"""

    @pytest.mark.asyncio
    async def test_react_loop_streams_start_and_complete(self):
        """验证循环正确输出 start 和 complete 事件"""
        from backend.orchestrator.react_loop import TrueReActLoop
        from backend.tools.registry import ToolRegistry
        from backend.tools.geoip import GeoIPTool

        orch = MagicMock()
        orch.llm = AsyncMock()
        orch.tools = ToolRegistry()
        orch.tools.register(GeoIPTool())
        orch.agents = {}

        # Mock LLM 返回流式数据 — 无工具调用，直接输出最终结果
        async def mock_stream(messages, tools_def, **kwargs):
            yield {"type": "text", "content": "分析结果"}
            yield {"type": "tool_calls", "tool_calls": []}

        orch.llm.chat_with_tools_stream = mock_stream

        loop = TrueReActLoop(orch)
        chunks = []
        async for chunk in loop.run("测试"):
            chunks.append(chunk)

        types = [c.get("type") for c in chunks]
        assert "true_react_start" in types
        assert "true_react_complete" in types

        # 检查 complete 事件结构
        complete = [c for c in chunks if c.get("type") == "true_react_complete"]
        if complete:
            assert "rounds" in complete[0]
            assert "total_duration_ms" in complete[0]


class TestAgentRouterKeywords:
    """Agent 路由关键词匹配集成测试（确保 ReactLoop 中的 LLM 提示含 Agent 描述）"""

    def test_agent_descriptions_in_system_prompt(self):
        """Agent 描述应出现在系统提示词中"""
        from backend.orchestrator.react_loop import TRUE_REACT_SYSTEM_PROMPT

        # 系统提示词中应包含路由相关关键词
        assert "route_to_agent" in TRUE_REACT_SYSTEM_PROMPT
        assert "agent_id" in TRUE_REACT_SYSTEM_PROMPT
        assert "专业 Agent" in TRUE_REACT_SYSTEM_PROMPT


class TestConfidenceAggregation:
    """确定性置信度聚合（修复：最终置信度可复现、可解释）"""

    def _make_loop(self):
        from backend.orchestrator.react_loop import TrueReActLoop
        from unittest.mock import MagicMock
        return TrueReActLoop(MagicMock())

    def test_aggregate_weighted(self):
        """加权聚合可复现"""
        loop = self._make_loop()
        results = [
            {"agent_id": "analyst-001", "confidence": 0.75, "verdict": "malicious", "degraded": False, "failed": False, "coverage": None},
            {"agent_id": "intel-001", "confidence": 0.35, "verdict": "suspicious", "degraded": False, "failed": False, "coverage": 1.0},
            {"agent_id": "responder-001", "confidence": 0.35, "verdict": "suspicious", "degraded": False, "failed": False, "coverage": None},
        ]
        # 期望值: (0.35*0.75 + 0.25*0.35 + 0.20*0.35) / (0.35+0.25+0.20) = 0.42/0.80 = 0.525
        agg = loop._aggregate_confidence(results)
        assert round(agg["confidence"], 4) == 0.525
        assert agg["verdict"] == "suspicious"

    def test_aggregate_deterministic(self):
        """同输入多次聚合结果完全一致（确定性）"""
        loop = self._make_loop()
        results = [
            {"agent_id": "analyst-001", "confidence": 0.75, "verdict": "malicious", "degraded": False, "failed": False, "coverage": None},
            {"agent_id": "intel-001", "confidence": 0.35, "verdict": "suspicious", "degraded": False, "failed": False, "coverage": 1.0},
        ]
        outs = {loop._aggregate_confidence(results)["confidence"] for _ in range(5)}
        assert len(outs) == 1

    def test_degraded_agent_weight_halved(self):
        """降级（曾失败重试成功）的 Agent 权重减半"""
        loop = self._make_loop()
        results = [
            {"agent_id": "analyst-001", "confidence": 0.75, "verdict": "malicious", "degraded": False, "failed": False, "coverage": None},
            {"agent_id": "intel-001", "confidence": 0.35, "verdict": "suspicious", "degraded": True, "failed": False, "coverage": 1.0},
        ]
        agg = loop._aggregate_confidence(results)
        # intel 权重 0.25 → 0.125
        expected = (0.35 * 0.75 + 0.125 * 0.35) / (0.35 + 0.125)
        assert round(agg["confidence"], 4) == round(expected, 4)
        assert agg["degraded_count"] == 1

    def test_coverage_penalty(self):
        """情报覆盖不足时置信度打折"""
        loop = self._make_loop()
        base = [
            {"agent_id": "analyst-001", "confidence": 0.75, "verdict": "malicious", "degraded": False, "failed": False, "coverage": 1.0},
            {"agent_id": "intel-001", "confidence": 0.35, "verdict": "suspicious", "degraded": False, "failed": False, "coverage": 1.0},
        ]
        full = loop._aggregate_confidence([dict(r, coverage=1.0) for r in base])
        partial = loop._aggregate_confidence([dict(r, coverage=0.33) for r in base])
        assert partial["confidence"] < full["confidence"]

    def test_no_agent_results_needs_human(self):
        """无任何 Agent 结构化裁决 → 强制低置信度 + 需人工"""
        loop = self._make_loop()
        agg = loop._aggregate_confidence([])
        assert agg["confidence"] <= 0.3
        assert agg["needs_human"] is True
        assert agg["verdict"] == "unknown"

    def test_agent_without_confidence_not_counted(self):
        """未返回结构化置信度的 Agent 不参与加权（不拉低结果）"""
        loop = self._make_loop()
        results = [
            {"agent_id": "analyst-001", "confidence": 0.80, "verdict": "malicious", "degraded": False, "failed": False, "coverage": None},
            {"agent_id": "knowledge-001", "confidence": None, "verdict": None, "degraded": False, "failed": False, "coverage": None},
        ]
        agg = loop._aggregate_confidence(results)
        assert agg["confidence"] == 0.80  # 只有 analyst 参与

    def test_render_summary_marks_degraded_and_failed(self):
        """渲染摘要标注降级/失败 Agent（P1-3：失败不掩盖）"""
        loop = self._make_loop()
        results = [
            {"agent_id": "analyst-001", "confidence": 0.75, "verdict": "malicious", "degraded": False, "failed": False, "coverage": None},
            {"agent_id": "intel-001", "confidence": 0.35, "verdict": "suspicious", "degraded": True, "failed": False, "coverage": 0.33},
            {"agent_id": "alert-filter-001", "confidence": None, "verdict": None, "degraded": False, "failed": True, "coverage": None},
        ]
        agg = loop._aggregate_confidence(results)
        text = loop._render_aggregate_summary(agg)
        assert "已降级" in text
        assert "失败" in text
        assert "情报覆盖度" in text
        assert "确定性置信度" in text
