"""
TrueReActLoop 集成测试 — 使用 Mock LLM 避免真实 API 调用
"""
import os
import sys
import json
import pytest
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.orchestrator.react_loop import TrueReActLoop
from backend.orchestrator.core import Orchestrator
from backend.tools.registry import ToolRegistry
from backend.llm.base import LLMInterface, LLMResponse


class MockLLM(LLMInterface):
    """Mock LLM — 不调用真实 API"""

    def __init__(self):
        self._last_usage = {"total_tokens": 100}

    @property
    def last_usage(self) -> dict:
        return self._last_usage or {}

    async def chat(self, messages, stream=False) -> LLMResponse:
        return LLMResponse(content="Mock response")

    async def chat_stream(self, messages):
        yield "Mock analysis result"

    async def structured_output(self, messages, response_model) -> dict:
        return {"result": "mock"}

    async def chat_with_tools(self, messages, tools, tool_choice="auto"):
        """模拟 LLM 决定不调工具直接回复"""
        return "这是一个模拟的测试响应，不调用任何工具。", []

    async def chat_with_tools_stream(self, messages, tools, tool_choice="auto"):
        """模拟流式调用 — 直接回复"""
        content = "这是一个模拟的测试响应，不调用任何工具。"
        yield {"type": "text", "content": content}
        # 不返回 tool_calls，触发 complete 路径
        yield {"type": "tool_calls", "tool_calls": []}

    async def close(self):
        pass


class MockToolCallingLLM(LLMInterface):
    """Mock LLM — 模拟调用一次工具后回复"""

    def __init__(self):
        self._last_usage = {"total_tokens": 200}
        self._call_count = 0

    @property
    def last_usage(self) -> dict:
        return self._last_usage or {}

    async def chat(self, messages, stream=False) -> LLMResponse:
        return LLMResponse(content="Mock")

    async def chat_stream(self, messages):
        yield "最终分析结果"

    async def structured_output(self, messages, response_model) -> dict:
        return {"result": "mock"}
        self._call_count = 0

    async def chat_stream(self, messages):
        yield "最终分析结果"

    async def chat_with_tools(self, messages, tools, tool_choice="auto"):
        self._call_count += 1
        if self._call_count == 1:
            content = "我需要查询这个 IP 的信息"
            tool_calls = [
                {
                    "id": "call-mock-1",
                    "type": "function",
                    "function": {
                        "name": "geoip",
                        "arguments": json.dumps({"ip": "8.8.8.8"})
                    }
                }
            ]
            return content, tool_calls
        else:
            return "分析完成，该 IP 来自美国，没有发现恶意行为。", []

    async def chat_with_tools_stream(self, messages, tools, tool_choice="auto"):
        """模拟流式调用"""
        self._call_count += 1
        if self._call_count == 1:
            content = "我需要查询这个 IP 的信息"
            yield {"type": "text", "content": content}
            yield {"type": "tool_calls", "tool_calls": [
                {
                    "id": "call-mock-1",
                    "type": "function",
                    "function": {
                        "name": "geoip",
                        "arguments": json.dumps({"ip": "8.8.8.8"})
                    }
                }
            ]}
        else:
            yield {"type": "text", "content": "分析完成，该 IP 来自美国，没有发现恶意行为。"}
            yield {"type": "tool_calls", "tool_calls": []}

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_react_loop_direct_reply():
    """测试：LLM 直接回复不调工具的场景"""
    orchestrator = Orchestrator(config={}, tools=ToolRegistry())
    orchestrator.llm = MockLLM()

    loop = TrueReActLoop(orchestrator)
    results = []
    async for chunk in loop.run("测试查询"):
        results.append(chunk)

    # 验证：应该有 start 和 complete 事件
    types = [r["type"] for r in results]
    assert "true_react_start" in types
    assert "true_react_complete" in types
    # 验证：没有 tool call
    assert "true_react_tool_call" not in types


@pytest.mark.asyncio
async def test_react_loop_with_history():
    """测试：带历史消息的 ReAct 循环"""
    orchestrator = Orchestrator(config={}, tools=ToolRegistry())
    orchestrator.llm = MockLLM()

    history = [
        {"role": "user", "content": "之前问过的问题"},
        {"role": "assistant", "content": "之前的回答"},
    ]

    loop = TrueReActLoop(orchestrator)
    results = []
    async for chunk in loop.run("新的问题", history_messages=history):
        results.append(chunk)

    types = [r["type"] for r in results]
    assert "true_react_start" in types
    assert "true_react_complete" in types


class TestAgentInfo:
    """AgentInfo 数据结构测试"""

    def test_register_agent(self):
        """测试：注册 Agent"""
        from backend.agents.base import BaseAgent, AgentConfig
        from backend.orchestrator.core import AgentInfo

        info = AgentInfo(
            name="测试Agent",
            instance=MagicMock(spec=BaseAgent),
            description="测试用",
            enabled=True,
        )
        assert info.name == "测试Agent"
        assert info.description == "测试用"
        assert info.enabled is True

    def test_disabled_agent(self):
        """测试：禁用 Agent"""
        from backend.orchestrator.core import AgentInfo
        info = AgentInfo(
            name="禁用Agent",
            instance=MagicMock(),
            description="",
            enabled=False,
        )
        assert info.enabled is False
