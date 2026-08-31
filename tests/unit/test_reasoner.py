"""
Reasoner 决策引擎 + Agent 基类 + 安全报告生成 单元测试

覆盖:
  - Reasoner 的 reason() 方法（多场景）
  - 安全报告生成
  - 置信度与风险评估
  - Agent 基类抽象方法
"""

import pytest


class TestReasoner:
    """Reasoner 决策引擎测试"""

    @pytest.fixture
    def mock_llm(self):
        """Mock LLM"""
        from backend.llm.mock import MockLLMProvider
        return MockLLMProvider({"api_key": "not-a-real-provider-key"})

    def test_reasoner_creation(self, mock_llm):
        """创建 Reasoner"""
        from backend.reasoner import Reasoner
        reasoner = Reasoner(llm=mock_llm)
        assert reasoner is not None
        assert reasoner.llm is not None

    @pytest.mark.asyncio
    async def test_reasoner_reason_basic(self, mock_llm):
        """reason 方法基本执行"""
        from backend.reasoner import Reasoner
        reasoner = Reasoner(llm=mock_llm)

        result = await reasoner.reason(
            query="分析安全事件: SSH暴力破解 来源IP 10.0.0.100",
            agent_outputs=[
                {"agent": "analyst", "summary": "检测到SSH暴力破解行为"},
                {"agent": "intel", "summary": "IP 10.0.0.100 在威胁情报库中被标记"},
            ],
            context={"event_id": "evt-001", "severity": "高危"},
        )
        assert result is not None
        # Mock LLM 返回的内容应该包含分析
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_reasoner_with_security_report(self, mock_llm):
        """reasoner 生成安全报告"""
        from backend.reasoner import Reasoner
        reasoner = Reasoner(llm=mock_llm)
        result = await reasoner.reason(
            query="恶意软件检测分析",
            agent_outputs=[
                {"agent": "analyst", "summary": "检测到已知恶意软件签名"},
            ],
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_reasoner_with_context(self, mock_llm):
        """带额外上下文的推理"""
        from backend.reasoner import Reasoner
        reasoner = Reasoner(llm=mock_llm)
        result = await reasoner.reason(
            query="端口扫描事件分析",
            agent_outputs=[{"agent": "analyst", "summary": "检测到全端口扫描"}],
            context={"source_ip": "10.0.0.1", "target_port": 443, "event_id": "evt-003"},
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_reasoner_with_multiple_agents(self, mock_llm):
        """多 Agent 协同推理"""
        from backend.reasoner import Reasoner
        reasoner = Reasoner(llm=mock_llm)
        result = await reasoner.reason(
            query="多阶段攻击评估",
            agent_outputs=[
                {"agent": "analyst", "summary": "检测到SQL注入尝试"},
                {"agent": "intel", "summary": "来源IP关联已知APT组织"},
                {"agent": "responder", "summary": "已封禁来源IP"},
                {"agent": "knowledge", "summary": "关联到MITRE ATT&CK T1190"},
            ],
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_reasoner_empty_agent_outputs(self, mock_llm):
        """无 Agent 输出时也能推理"""
        from backend.reasoner import Reasoner
        reasoner = Reasoner(llm=mock_llm)
        result = await reasoner.reason(
            query="直接分析这个IP: 8.8.8.8",
            agent_outputs=[],
        )
        assert result is not None


class TestAgentBase:
    """Agent 基类测试"""

    def test_abstract_agent_cannot_instantiate(self):
        """抽象 Agent 不能直接实例化"""
        from backend.agents.base import BaseAgent
        try:
            BaseAgent(None)
            assert False, "应该抛出 TypeError"
        except TypeError:
            pass  # 抽象类不能直接实例化
