"""
生产级 RBAC 工具权限隔离测试

验证:
  1. 各 Agent 只能调用白名单内的工具
  2. 指挥官(Orchestrator)只读，无处置权限
  3. 越权工具调用被拦截
  4. responder-001 是唯一有处置权的 Agent
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ.setdefault("SECAGENTX_PASSWORD", "SecAgentX-E2E-Only-2026!")
os.environ.setdefault("SECAGENTX_JWT_SECRET", "test-jwt-secret-at-least-32-chars")

import pytest
from backend.agents.analyst import AnalystAgent
from backend.agents.intel import IntelAgent
from backend.agents.responder import ResponderAgent
from backend.agents.knowledge.knowledge_agent import KnowledgeAgent
from backend.agents.alert_filter.alert_filter_agent import AlertFilterAgent
from backend.orchestrator.core import Orchestrator
from backend.tools.registry import ToolRegistry
from backend.tools.threat_intel import ThreatIntelTool
from backend.tools.geoip import GeoIPTool
from backend.tools.log_analyzer import LogAnalyzerTool
from backend.tools.firewall import FirewallTool
from backend.tools.cve_search import CVESearchTool
from backend.tools.alert_filter import AlertFilterTool


def _build_registry() -> ToolRegistry:
    """构建包含全部工具的总注册表"""
    reg = ToolRegistry()
    reg.register(ThreatIntelTool())
    reg.register(GeoIPTool())
    reg.register(LogAnalyzerTool())
    reg.register(FirewallTool(backend="mock"))
    reg.register(CVESearchTool())
    reg.register(AlertFilterTool())
    return reg


def _agent_tool_names(agent) -> set:
    return {t.name for t in agent._get_allowed_tools().list_tools()}


class TestAgentToolIsolation:
    """各 Agent 只能调用白名单工具"""

    def setup_method(self):
        self.tools = _build_registry()

    def test_intel_only_read_only(self):
        agent = IntelAgent(self.tools)
        names = _agent_tool_names(agent)
        assert "threat_intel" in names
        assert "firewall_manage" not in names  # 情报员不能封禁

    def test_analyst_no_disposal(self):
        agent = AnalystAgent(self.tools)
        names = _agent_tool_names(agent)
        assert "log_analyzer" in names
        assert "firewall_manage" not in names  # 分析师不能封禁

    def test_responder_has_disposal(self):
        agent = ResponderAgent(self.tools)
        names = _agent_tool_names(agent)
        assert "firewall_manage" in names  # 响应员可处置

    def test_knowledge_only_query(self):
        agent = KnowledgeAgent(self.tools)
        names = _agent_tool_names(agent)
        assert "cve_search" in names
        assert "firewall_manage" not in names

    def test_alert_filter_no_disposal(self):
        agent = AlertFilterAgent(self.tools)
        names = _agent_tool_names(agent)
        assert "alert_filter" in names
        assert "firewall_manage" not in names


class TestOrchestratorReadOnly:
    """指挥官只读，无处置权限"""

    def setup_method(self):
        self.tools = _build_registry()
        self.orch = Orchestrator({}, tools=self.tools)

    def test_readonly_excludes_firewall(self):
        ro_tools = {t.name for t in self.orch.get_readonly_tools().list_tools()}
        assert "firewall_manage" not in ro_tools
        assert "threat_intel" in ro_tools

    def test_firewall_only_via_responder(self):
        """只有 responder-001 拥有 firewall_manage"""
        agents_with_firewall = []
        for agent_cls in [AnalystAgent, IntelAgent, ResponderAgent, KnowledgeAgent, AlertFilterAgent]:
            agent = agent_cls(self.tools)
            if "firewall_manage" in _agent_tool_names(agent):
                agents_with_firewall.append(agent_cls.__name__)
        assert agents_with_firewall == ["ResponderAgent"]


class TestUnblockConfidenceGate:
    """解封/封禁置信度门控（防 AI 误操作）"""

    def setup_method(self):
        self.tools = _build_registry()
        self.fw = self.tools.get("firewall_manage")

    @pytest.mark.asyncio
    async def test_block_rejected_low_confidence(self):
        res = await self.fw.execute(action="block", ip="1.2.3.4", confidence=0.3)
        assert not res.success
        assert "置信度" in (res.data.get("message", "") if res.data else "") or "置信度" in (res.error or "")

    @pytest.mark.asyncio
    async def test_block_allowed_high_confidence(self):
        res = await self.fw.execute(action="block", ip="1.2.3.4", confidence=0.9)
        assert res.success
        # 清理
        await self.fw.execute(action="unblock", ip="1.2.3.4", confidence=0.9)

    @pytest.mark.asyncio
    async def test_unblock_rejected_low_confidence(self):
        res = await self.fw.execute(action="unblock", ip="1.2.3.4", confidence=0.1)
        assert not res.success
