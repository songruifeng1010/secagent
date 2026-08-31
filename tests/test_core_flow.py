"""
核心流程集成测试

测试 3 条核心链路，使用 MockLLM 和 Mock 工具，不依赖外部 API。

运行方式:
    python -m pytest secagentx/tests/test_core_flow.py -v --tb=short
"""

import os
import sys
import pytest

# 确保项目根目录在 path 中
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# 设置 Mock 环境变量，让 LLMFactory 自动使用 MockLLM
os.environ.setdefault("DEEPSEEK_API_KEY", "mock")
os.environ.setdefault("KNOWLEDGE_BASE_DIR", os.path.join(_PROJECT_ROOT, "knowledge_data"))


@pytest.fixture
def orch():
    """准备一个完整但全部 Mock 的 Orchestrator"""
    os.environ["SECAGENTX_ACTIVE_PROVIDER"] = "mock"
    os.environ["SECAGENTX_LLM_MODEL"] = "mock-llm"
    from backend.tools.registry import ToolRegistry
    from backend.llm.provider import LLMFactory
    from backend.tools.geoip import GeoIPTool
    from backend.tools.threat_intel import ThreatIntelTool
    from backend.orchestrator.core import Orchestrator
    from backend.agents.analyst import AnalystAgent
    from backend.agents.intel import IntelAgent

    LLMFactory.clear()
    tools = ToolRegistry()

    # 注册 GeoIP（无外部依赖，可正常执行）
    tools.register(GeoIPTool())

    # 注册 ThreatIntelTool（无 API Key 时会返回明确的配置错误）
    tools.register(ThreatIntelTool())

    config = {
        "llm": {"api_key": "mock", "model": "mock"},
    }
    orchestrator = Orchestrator(config, tools=tools)
    orchestrator.register_agent("analyst-001", "安全分析师", AnalystAgent(tools),
                                "告警分析、日志分析")
    orchestrator.register_agent("intel-001", "威胁情报员", IntelAgent(tools),
                                "IOC查询、威胁情报关联")
    return orchestrator


@pytest.mark.asyncio
async def test_basic_geoip_query(orch):
    """测试 1: 系统能完整处理查询（MockLLM 模式）"""
    chunks = []
    async for chunk in orch.process("查询 8.8.8.8 的地理位置"):
        chunks.append(chunk)

    types = [c.get("type") for c in chunks]
    print(f"\n[test_basic_geoip] chunk types: {types}")

    # 系统不应崩溃
    assert len(chunks) > 0, "无任何返回"
    # 不应有 error 类型（MockLLM 不应尝试连接真实 API）
    assert not any(c.get("type") == "error" for c in chunks), (
        f"出现错误响应: {[c for c in chunks if c.get('type') == 'error']}"
    )


@pytest.mark.asyncio
async def test_analyst_route(orch):
    """测试 2: 告警分析请求不导致崩溃"""
    chunks = []
    async for chunk in orch.process("分析这个告警: SSH 暴力破解来自 10.0.0.5"):
        chunks.append(chunk)

    types = [c.get("type") for c in chunks]
    print(f"\n[test_analyst_route] chunk types: {types}")
    assert len(chunks) > 0, "无任何返回"


@pytest.mark.asyncio
async def test_threat_intel_no_api_error(orch):
    """测试 3: 威胁情报在无 API Key 时不崩溃"""
    chunks = []
    async for chunk in orch.process("查询 8.8.8.8 的威胁情报"):
        chunks.append(chunk)

    all_text = "".join(c.get("content", "") or "" for c in chunks)
    types = [c.get("type") for c in chunks]
    print(f"\n[test_threat_intel] chunk types: {types}")
    print(f"[test_threat_intel] text snippet: {all_text[:300]}")
    assert len(chunks) > 0, "无任何返回"


@pytest.mark.asyncio
async def test_empty_input(orch):
    """测试 4: 空输入健壮性"""
    chunks = []
    async for chunk in orch.process(""):
        chunks.append(chunk)
    types = [c.get("type") for c in chunks]
    print(f"\n[test_empty_input] chunk types: {types}")
    # 不应该崩溃，应有合理返回
    assert len(chunks) > 0, "空输入无任何返回"


@pytest.mark.asyncio
async def test_multiple_tools(orch):
    """测试 5: 包含多个工具调用的复杂查询"""
    chunks = []
    async for chunk in orch.process("查询 1.1.1.1 的地理位置和威胁情报"):
        chunks.append(chunk)

    types = [c.get("type") for c in chunks]
    finals = [c for c in chunks if c.get("type") in ("true_react_complete", "orchestrator_complete")]
    print(f"\n[test_multiple_tools] chunk types: {types}")
    # 不要求一定成功（Mock LLM 可能无法正确规划工具链），但不应崩溃
    assert len(chunks) > 0, "多工具查询无任何返回"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
