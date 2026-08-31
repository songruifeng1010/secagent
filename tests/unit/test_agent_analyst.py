"""
Agent 单元测试

覆盖:
  - Analyst / Intel / Responder / Knowledge Agent 创建与初始化
  - Agent 基本属性与方法
  - 工具注册
"""

import pytest


class TestAnalystAgent:
    """安全分析师 Agent 单元测试"""

    @pytest.fixture
    def tool_registry(self):
        from backend.tools.registry import ToolRegistry
        from backend.tools.threat_intel import ThreatIntelTool
        from backend.tools.log_analyzer import LogAnalyzerTool
        from backend.tools.cve_search import CVESearchTool
        from backend.tools.geoip import GeoIPTool

        registry = ToolRegistry()
        registry.register(ThreatIntelTool())
        registry.register(LogAnalyzerTool())
        registry.register(CVESearchTool())
        registry.register(GeoIPTool())
        return registry

    def test_analyst_agent_creation(self, tool_registry):
        """创建 Analyst Agent"""
        from backend.agents.analyst import AnalystAgent
        agent = AnalystAgent(tool_registry)
        assert agent is not None
        assert agent.tools.count() >= 2
        assert agent.status == "idle"

    def test_analyst_agent_id(self, tool_registry):
        """Agent ID"""
        from backend.agents.analyst import AnalystAgent
        agent = AnalystAgent(tool_registry)
        assert agent.agent_id is not None
        assert len(agent.agent_id) > 0

    def test_analyst_build_system_prompt(self, tool_registry):
        """Analyst Agent 构建系统提示"""
        from backend.agents.analyst import AnalystAgent
        agent = AnalystAgent(tool_registry)
        prompt = agent.build_system_prompt()
        assert prompt is not None
        assert len(prompt) > 50
        assert "安全" in prompt or "analysis" in prompt.lower()

    def test_analyst_stats(self, tool_registry):
        """统计信息"""
        from backend.agents.analyst import AnalystAgent
        agent = AnalystAgent(tool_registry)
        stats = agent.stats
        assert stats is not None
        assert "tasks_completed" in stats
        assert stats["tasks_completed"] == 0

    @pytest.mark.asyncio
    async def test_analyst_process_message(self, tool_registry):
        """处理消息"""
        from backend.agents.analyst import AnalystAgent
        from backend.llm.mock import MockLLMProvider
        from backend.models.message import AgentMessage, MessageType, Task
        agent = AnalystAgent(tool_registry)
        # 注入 Mock LLM 避免真实网络请求
        agent._llm = MockLLMProvider({"api_key": "not-a-real-provider-key"})
        msg = AgentMessage(
            sender="user",
            msg_type=MessageType.CHAT,
            payload={"task": "分析安全事件: SSH暴力破解"},
        )
        async for chunk in agent.process_message(msg):
            pass
        assert True

    def test_analyst_tools(self, tool_registry):
        """Agent 关联的工具"""
        from backend.agents.analyst import AnalystAgent
        agent = AnalystAgent(tool_registry)
        tool_list = agent.tools.list_tools()
        assert len(tool_list) >= 2

    def test_analyst_conversation_history(self, tool_registry):
        """对话历史"""
        from backend.agents.analyst import AnalystAgent
        agent = AnalystAgent(tool_registry)
        assert agent.conversation_history == []


class TestIntelAgent:
    """威胁情报 Agent 单元测试"""

    @pytest.fixture
    def tool_registry(self):
        from backend.tools.registry import ToolRegistry
        from backend.tools.threat_intel import ThreatIntelTool
        registry = ToolRegistry()
        registry.register(ThreatIntelTool())
        return registry

    def test_intel_agent_creation(self, tool_registry):
        """创建 Intel Agent"""
        from backend.agents.intel import IntelAgent
        agent = IntelAgent(tool_registry)
        assert agent is not None
        assert agent.status == "idle"

    def test_intel_agent_id(self, tool_registry):
        """Intel Agent ID"""
        from backend.agents.intel import IntelAgent
        agent = IntelAgent(tool_registry)
        assert agent.agent_id is not None

    def test_intel_build_system_prompt(self, tool_registry):
        """Intel Agent 系统提示"""
        from backend.agents.intel import IntelAgent
        agent = IntelAgent(tool_registry)
        prompt = agent.build_system_prompt()
        assert prompt is not None

    @pytest.mark.asyncio
    async def test_intel_process_message(self, tool_registry):
        """处理威胁情报查询"""
        from backend.agents.intel import IntelAgent
        from backend.llm.mock import MockLLMProvider
        from backend.models.message import AgentMessage, MessageType
        agent = IntelAgent(tool_registry)
        agent._llm = MockLLMProvider({"api_key": "not-a-real-provider-key"})
        msg = AgentMessage(
            sender="user",
            msg_type=MessageType.CHAT,
            payload={"task": "查询IP: 8.8.8.8"},
        )
        async for chunk in agent.process_message(msg):
            pass
        assert True


class TestResponderAgent:
    """应急响应 Agent 单元测试"""

    @pytest.fixture
    def tool_registry(self):
        from backend.tools.registry import ToolRegistry
        from backend.tools.firewall import FirewallTool
        registry = ToolRegistry()
        registry.register(FirewallTool(whitelist=["10.0.0.1"], backend="mock"))
        return registry

    def test_responder_creation(self, tool_registry):
        """创建 Responder Agent"""
        from backend.agents.responder import ResponderAgent
        agent = ResponderAgent(tool_registry)
        assert agent is not None
        assert agent.status == "idle"

    def test_responder_agent_id(self, tool_registry):
        """Responder Agent ID"""
        from backend.agents.responder import ResponderAgent
        agent = ResponderAgent(tool_registry)
        assert agent.agent_id is not None

    def test_responder_build_system_prompt(self, tool_registry):
        """Responder Agent 系统提示"""
        from backend.agents.responder import ResponderAgent
        agent = ResponderAgent(tool_registry)
        prompt = agent.build_system_prompt()
        assert prompt is not None

    @pytest.mark.asyncio
    async def test_responder_process_message(self, tool_registry):
        """处理响应指令"""
        from backend.agents.responder import ResponderAgent
        from backend.llm.mock import MockLLMProvider
        from backend.models.message import AgentMessage, MessageType
        agent = ResponderAgent(tool_registry)
        agent._llm = MockLLMProvider({"api_key": "not-a-real-provider-key"})
        msg = AgentMessage(
            sender="user",
            msg_type=MessageType.CHAT,
            payload={"task": "封禁IP 1.2.3.4"},
        )
        async for chunk in agent.process_message(msg):
            pass
        assert True


class TestKnowledgeAgent:
    """知识 Agent 单元测试"""

    @pytest.fixture
    def tool_registry(self):
        from backend.tools.registry import ToolRegistry
        from backend.tools.cve_search import CVESearchTool
        registry = ToolRegistry()
        registry.register(CVESearchTool())
        return registry

    def test_knowledge_agent_creation(self, tool_registry):
        """创建 Knowledge Agent"""
        from backend.agents.knowledge.knowledge_agent import KnowledgeAgent
        agent = KnowledgeAgent(tool_registry)
        assert agent is not None
        assert agent.status == "idle"

    def test_knowledge_agent_id(self, tool_registry):
        """Knowledge Agent ID"""
        from backend.agents.knowledge.knowledge_agent import KnowledgeAgent
        agent = KnowledgeAgent(tool_registry)
        assert agent.agent_id is not None

    def test_knowledge_build_system_prompt(self, tool_registry):
        """Knowledge Agent 系统提示"""
        from backend.agents.knowledge.knowledge_agent import KnowledgeAgent
        agent = KnowledgeAgent(tool_registry)
        prompt = agent.build_system_prompt()
        assert prompt is not None


class TestAgentRegistry:
    """Agent 注册器测试"""

    def test_register_and_list_agents(self):
        """注册和列出 Agent"""
        from backend.agents.registry import list_agents, clear_registry, register_agent, AgentMeta

        clear_registry()

        # 注册一个测试 Agent
        @register_agent(AgentMeta(
            agent_id="test-agent-001",
            name="测试Agent",
            description="测试用",
        ))
        class TestAgent:
            pass

        agents = list_agents()
        assert len(agents) >= 1
        found = [a for a in agents if a["agent_id"] == "test-agent-001"]
        assert len(found) == 1

        clear_registry()

    def test_get_agent_class(self):
        """获取 Agent 类"""
        from backend.agents.registry import get_agent_class, clear_registry, register_agent, AgentMeta

        clear_registry()

        @register_agent(AgentMeta(agent_id="get-test-001", name="GetTest", description=""))
        class GetTestAgent:
            pass

        cls = get_agent_class("get-test-001")
        assert cls is GetTestAgent

        clear_registry()

    def test_get_registry(self):
        """获取完整注册表"""
        from backend.agents.registry import get_registry, clear_registry
        clear_registry()
        reg = get_registry()
        assert isinstance(reg, dict)
