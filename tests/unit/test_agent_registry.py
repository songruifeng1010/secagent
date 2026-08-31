"""
Agent 注册表单元测试
覆盖: 装饰器注册、自动发现、元数据管理

运行: python -m pytest tests/unit/test_agent_registry.py -v
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TestAgentRegistry:
    """Agent 注册表测试"""

    def setup_method(self):
        from backend.agents.registry import clear_registry
        clear_registry()

    def test_register_agent_via_decorator(self):
        """装饰器注册 Agent"""
        from backend.agents.registry import register_agent, AgentMeta, get_registry

        @register_agent(AgentMeta(agent_id="test-agent-001", name="测试Agent", description="测试用"))
        class TestAgent:
            pass

        registry = get_registry()
        assert "test-agent-001" in registry
        meta, cls = registry["test-agent-001"]
        assert meta.name == "测试Agent"
        assert meta.description == "测试用"
        assert cls == TestAgent

    def test_register_multiple_agents(self):
        """注册多个 Agent"""
        from backend.agents.registry import register_agent, AgentMeta, list_agents

        @register_agent(AgentMeta(agent_id="agent-a", name="A", capabilities=["cap1"]))
        class AgentA:
            pass

        @register_agent(AgentMeta(agent_id="agent-b", name="B", capabilities=["cap2"]))
        class AgentB:
            pass

        agents = list_agents()
        assert len(agents) == 2
        ids = [a["agent_id"] for a in agents]
        assert "agent-a" in ids
        assert "agent-b" in ids

    def test_register_duplicate_overwrites(self):
        """重复注册应覆盖"""
        from backend.agents.registry import register_agent, AgentMeta, get_agent_class

        @register_agent(AgentMeta(agent_id="dup-agent"))
        class FirstAgent:
            pass

        @register_agent(AgentMeta(agent_id="dup-agent"))
        class SecondAgent:
            pass

        cls = get_agent_class("dup-agent")
        assert cls == SecondAgent

    def test_get_agent_meta_not_found(self):
        """查询不存在的 Agent 应返回 None"""
        from backend.agents.registry import get_agent_meta, get_agent_class
        assert get_agent_meta("ghost") is None
        assert get_agent_class("ghost") is None

    def test_agent_meta_auto_name(self):
        """未设置 name 时自动从 agent_id 生成"""
        from backend.agents.registry import AgentMeta
        meta = AgentMeta(agent_id="my-custom-agent")
        assert meta.name == "my-custom-agent"  # 自动填充

    def test_agent_meta_defaults(self):
        """AgentMeta 默认值验证"""
        from backend.agents.registry import AgentMeta
        meta = AgentMeta(agent_id="test")
        assert meta.enabled is True
        assert meta.llm_provider == "deepseek"
        assert meta.version == "1.0.0"
        assert meta.capabilities == []
        assert meta.tags == []

    def test_clear_registry(self):
        """清空注册表"""
        from backend.agents.registry import register_agent, AgentMeta, clear_registry, get_registry

        @register_agent(AgentMeta(agent_id="temp"))
        class Temp:
            pass

        assert len(get_registry()) == 1
        clear_registry()
        assert len(get_registry()) == 0


class TestAgentCapabilitiesRegistration:
    """Agent 能力关键词注册测试"""

    def test_register_capabilities_new(self):
        """注册新 Agent 的能力关键词"""
        from backend.orchestrator.agent_router import register_capabilities, AGENT_CAPABILITIES

        # 清理（以防已有）
        original = AGENT_CAPABILITIES.get("test-router-agent", [])
        if "test-router-agent" in AGENT_CAPABILITIES:
            del AGENT_CAPABILITIES["test-router-agent"]

        register_capabilities("test-router-agent", ["关键词1", "关键词2", "关键词3"])
        assert "test-router-agent" in AGENT_CAPABILITIES
        assert "关键词1" in AGENT_CAPABILITIES["test-router-agent"]
        assert len(AGENT_CAPABILITIES["test-router-agent"]) == 3

        # 恢复
        if "test-router-agent" in AGENT_CAPABILITIES:
            del AGENT_CAPABILITIES["test-router-agent"]
        if original:
            AGENT_CAPABILITIES["test-router-agent"] = original

    def test_register_capabilities_append(self):
        """追加已存在 Agent 的能力关键词"""
        from backend.orchestrator.agent_router import register_capabilities, AGENT_CAPABILITIES

        original = list(AGENT_CAPABILITIES.get("analyst-001", []))

        count_before = len(AGENT_CAPABILITIES.get("analyst-001", []))
        register_capabilities("analyst-001", ["新能力"])
        assert len(AGENT_CAPABILITIES["analyst-001"]) == count_before + 1
        assert "新能力" in AGENT_CAPABILITIES["analyst-001"]

        # 恢复
        if original:
            AGENT_CAPABILITIES["analyst-001"] = original

    def test_register_capabilities_empty_ignored(self):
        """空能力列表不注册"""
        from backend.orchestrator.agent_router import register_capabilities, AGENT_CAPABILITIES

        count_before = len(AGENT_CAPABILITIES)
        register_capabilities("", ["cap"])
        register_capabilities("test-empty", [])
        assert len(AGENT_CAPABILITIES) == count_before

        # 清理
        if "test-empty" in AGENT_CAPABILITIES:
            del AGENT_CAPABILITIES["test-empty"]
