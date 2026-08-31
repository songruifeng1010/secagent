"""
TrueReAct 轨迹集成测试（v2.4 M3）

覆盖:
  - _trace_step 构造结构化轨迹步（step_id/phase/actor/input/output）
  - _emit_trace_steps 转 trace_step WS 事件（兼容旧字段）
  - _persist_trajectory 旁路持久化（失败不阻断）
  - run() 完整循环输出 trace_step 事件
"""

import os
import sys
import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
    )
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.orchestrator.react_loop import TrueReActLoop
from backend.tools.registry import ToolRegistry
from backend.tools.geoip import GeoIPTool


class TestTraceStepBuilder:
    def test_trace_step_structure(self):
        orch = MagicMock()
        loop = TrueReActLoop(orch)
        step = loop._trace_step("tool", 1, "threat_intel",
        input_='{"ip": "1.2.3.4"}',
        output='{"malicious": true}',
        success=True, duration_ms=120,
        extra={"type": "tool", "tool_name": "threat_intel"})
        assert step["step_id"] == "step-1"
        assert step["phase"] == "tool"
        assert step["round"] == 1
        assert step["actor"] == "threat_intel"
        assert step["input"] == '{"ip": "1.2.3.4"}'
        assert step["output"] == '{"malicious": true}'
        assert step["success"] is True
        assert step["duration_ms"] == 120
        assert step["timestamp"] > 0
        assert step["tool_name"] == "threat_intel" # extra 合并

    def test_trace_step_increments(self):
        orch = MagicMock()
        loop = TrueReActLoop(orch)
        s1 = loop._trace_step("think", 1, "LLM")
        s2 = loop._trace_step("think", 1, "LLM")
        assert s1["step_id"] == "step-1"
        assert s2["step_id"] == "step-2"


class TestEmitTraceSteps:
    @pytest.mark.asyncio
    async def test_emit_trace_steps_events(self):
        orch = MagicMock()
        loop = TrueReActLoop(orch)
        steps = [
        loop._trace_step("think", 1, "LLM", output="决策"),
        loop._trace_step("tool", 1, "threat_intel",
        output="ok", success=True,
        extra={"type": "tool", "tool_name": "threat_intel"}),
        loop._trace_step("agent", 1, "analyst-001", output="malicious",
        extra={"type": "agent", "agent_id": "analyst-001"}),
        ]
        events = []
        async for ev in loop._emit_trace_steps(steps):
            events.append(ev)
        assert len(events) == 3
        assert events[0]["type"] == "trace_step"
        assert events[0]["phase"] == "think"
        # 兼容旧字段
        assert events[1]["tool_name"] == "threat_intel"
        assert events[2]["agent_id"] == "analyst-001"


class TestPersistTrajectory:
    @pytest.mark.asyncio
    async def test_persist_success(self):
        orch = MagicMock()
        loop = TrueReActLoop(orch)
        steps = [loop._trace_step("think", 1, "LLM", output="决策")]

        # 直接 patch 函数内导入的模块路径
        saved = {}
        fake_repo = MagicMock()
        fake_repo.save_trajectory = AsyncMock(return_value="tid")

        fake_db = MagicMock()
        fake_db.close = AsyncMock()

        with patch("backend.storage.database.Repository",
                  return_value=fake_db), \
                patch("backend.storage.repositories.trajectory_repo.Repository",
                      return_value=fake_db), \
                patch("backend.storage.repositories.trajectory_repo.TrajectoryRepository",
                      return_value=fake_repo):
            await loop._persist_trajectory("conv-1", steps, 1500)

            fake_repo.save_trajectory.assert_awaited_once()
            args, kwargs = fake_repo.save_trajectory.await_args
            assert kwargs["conversation_id"] == "conv-1"
            assert len(kwargs["trajectory"]) == 1
            assert kwargs["total_duration_ms"] == 1500

    @pytest.mark.asyncio
    async def test_persist_empty_noop(self):
        orch = MagicMock()
        loop = TrueReActLoop(orch)
        # 空轨迹 -> 直接返回，不抛异常
        await loop._persist_trajectory("conv-1", [], 0)

    @pytest.mark.asyncio
    async def test_persist_error_swallowed(self):
        """持久化异常 -> 被吞掉，主链路不受影响。"""
        orch = MagicMock()
        loop = TrueReActLoop(orch)
        steps = [loop._trace_step("think", 1, "LLM")]
        # 模拟 Repository 构造抛异常
        with patch("backend.storage.database.Repository",
                  side_effect=Exception("db down")):
            await loop._persist_trajectory("conv-1", steps, 100)
        # 不抛异常即通过


class TestReactLoopTraceEvents:
    @pytest.mark.asyncio
    async def test_run_emits_trace_steps_on_complete(self):
        """run() 在 complete 时输出 trace_step 事件（含 think 步骤）。"""
        orch = MagicMock()
        orch.llm = AsyncMock()
        orch.tools = ToolRegistry()
        orch.tools.register(GeoIPTool())
        orch.agents = {}

        async def mock_stream(messages, tools_def, **kwargs):
            yield {"type": "text", "content": "分析结果"}
            yield {"type": "tool_calls", "tool_calls": []}
            orch.llm.chat_with_tools_stream = mock_stream

            loop = TrueReActLoop(orch)
            # 意图识别：返回非知识查询 -> 走威胁分析主链路
        async def mock_classifier(text):
            return {"template_type": "攻击检测", "is_knowledge_query": False}
            loop._invoke_classifier = mock_classifier

            # 阻止真实持久化，并验证 _emit_trace_steps 被调用
            loop._persist_trajectory = AsyncMock()

            # 无工具调用的场景 trace_events 为空 -> 模拟 _emit_trace_steps 注入一条
        async def fake_emit(steps):
            for s in steps:
                ev = dict(s)
                ev["type"] = "trace_step"
                yield ev
                loop._emit_trace_steps = fake_emit

                chunks = []
                async for c in loop.run("测试"):
                    chunks.append(c)
                    # complete 事件仍然正常输出
                    types = [c.get("type") for c in chunks]
                    assert "true_react_complete" in types
                    # _persist_trajectory 被调用（轨迹持久化接入主链路）
                    loop._persist_trajectory.assert_called_once()
                    # 完整事件携带 agent_trace 字段
                    complete = [c for c in chunks if c.get("type") == "true_react_complete"][0]
                    assert "agent_trace" in complete
