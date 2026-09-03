"""
FirewallTool 单元测试
"""
import os
import pytest
from backend.tools.firewall import FirewallExecutionContext, FirewallTool
from backend.tools.calling import ToolCall
from backend.tools.execution_engine import UnifiedToolCallEngine
from backend.tools.registry import ToolRegistry


@pytest.mark.asyncio
async def test_block_below_threshold():
    """测试：置信度低于阈值时封禁被拒绝"""
    tool = FirewallTool(block_threshold=0.70)
    result = await tool.execute(
        action="block",
        ip="10.0.0.5",
        reason="测试封禁",
        confidence=0.30,
    )
    assert result.success is False
    assert "置信度不足" in result.error
    assert result.data["action"] == "rejected"


@pytest.mark.asyncio
async def test_block_above_threshold():
    """测试：置信度高于阈值时封禁成功"""
    tool = FirewallTool(block_threshold=0.70)
    result = await tool.execute(
        action="block",
        ip="1.2.3.4",
        reason="恶意攻击",
        confidence=0.85,
    )
    assert result.success is True
    assert result.data["action"] == "blocked"
    assert result.data["ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_whitelist_protection():
    """测试：白名单 IP 不会被自动封禁"""
    tool = FirewallTool(block_threshold=0.70)
    # 白名单中的 IP
    result = await tool.execute(
        action="block",
        ip="10.0.0.1",
        reason="测试",
        confidence=0.95,
    )
    assert result.success is False
    assert "白名单" in result.error or "rejected" in result.data.get("action", "")


@pytest.mark.asyncio
async def test_block_then_unblock():
    """测试：封禁后解封"""
    tool = FirewallTool(block_threshold=0.70, unblock_threshold=0.85)

    # 封禁
    await tool.execute(action="block", ip="5.6.7.8", confidence=0.90)

    # 检查封禁状态
    check = await tool.execute(action="check", ip="5.6.7.8")
    assert check.data["is_blocked"] is True

    # 解封
    unblock = await tool.execute(action="unblock", ip="5.6.7.8", confidence=0.90)
    assert unblock.success is True
    assert unblock.data["action"] == "unblocked"

    # 确认已解封
    check2 = await tool.execute(action="check", ip="5.6.7.8")
    assert check2.data["is_blocked"] is False


@pytest.mark.asyncio
async def test_list_and_expiry():
    """测试：列出封禁列表"""
    tool = FirewallTool()
    await tool.execute(
        action="block", ip="1.1.1.1", confidence=0.90, duration_minutes=60
    )
    await tool.execute(
        action="block", ip="2.2.2.2", confidence=0.90, duration_minutes=60
    )

    result = await tool.execute(action="list")
    assert result.data["total"] == 2
    assert len(result.data["rules"]) == 2


@pytest.mark.asyncio
async def test_unblock_not_found():
    """测试：解封不存在的 IP"""
    tool = FirewallTool()
    result = await tool.execute(
        action="unblock", ip="9.9.9.9", confidence=0.90
    )
    assert result.success is True
    # Mock 后端解封不存在的 IP 返回 unblocked（幂等操作）
    assert result.data["action"] in ("unblocked", "not_found")


@pytest.mark.asyncio
async def test_block_no_ip():
    """测试：未指定 IP 时封禁失败"""
    tool = FirewallTool()
    result = await tool.execute(action="block", confidence=0.90)
    assert result.success is False
    assert "IP" in result.error


@pytest.mark.asyncio
async def test_unknown_action():
    """测试：未知操作类型"""
    tool = FirewallTool()
    result = await tool.execute(action="unknown")
    assert result.success is False
    assert "未知操作" in result.error


@pytest.mark.asyncio
async def test_unblock_below_threshold():
    """测试：解封置信度不足"""
    tool = FirewallTool(unblock_threshold=0.85)
    await tool.execute(action="block", ip="5.5.5.5", confidence=0.90)
    result = await tool.execute(
        action="unblock", ip="5.5.5.5", confidence=0.50
    )
    assert result.success is False
    assert "置信度不足" in result.error


@pytest.mark.asyncio
async def test_llm_cannot_supply_confidence_override():
    """字典参数不能伪装成服务端授权上下文。"""
    tool = FirewallTool(block_threshold=0.70)
    result = await tool.execute(
        action="block",
        ip="8.8.8.8",
        reason="非可信强制封禁",
        confidence=0.10,
        authorization_context={
            "actor": "attacker",
            "source": "authenticated_api",
            "allowed_actions": ["block"],
        },
    )
    assert result.success is False
    assert "置信度不足" in result.error


@pytest.mark.asyncio
async def test_local_console_can_override_confidence_only():
    """经人工确认的本机控制台可跳过置信度，但不能跳过其他策略。"""
    tool = FirewallTool(block_threshold=0.70, whitelist=[])
    context = FirewallExecutionContext.local_console(
        action="block",
        actor="local-console",
        reason="人工确认",
    )
    result = await tool.execute(
        action="block",
        ip="8.8.4.4",
        reason="人工确认",
        confidence=0.10,
        authorization_context=context,
    )
    assert result.success is True
    assert result.data["action"] == "blocked"


def test_override_is_not_exposed_in_llm_schema():
    tool = FirewallTool()
    assert "skip_confidence_check" not in tool.parameters["properties"]
    assert "authorization_context" not in tool.parameters["properties"]


@pytest.mark.asyncio
async def test_llm_tool_engine_rejects_hidden_arguments():
    registry = ToolRegistry()
    registry.register(FirewallTool(whitelist=[]))
    engine = UnifiedToolCallEngine(registry)
    call = ToolCall(
        tool_name="firewall_manage",
        arguments={
            "action": "block",
            "ip": "8.8.8.8",
            "confidence": 0.10,
            "authorization_context": {
                "actor": "attacker",
                "source": "authenticated_api",
            },
        },
    )

    results = await engine.execute([call])

    assert len(results) == 1
    assert results[0].success is False
    assert "未声明参数" in results[0].error


@pytest.mark.asyncio
async def test_agent_id_set_on_tool():
    """测试：FirewallTool 有 agent_id 属性"""
    tool = FirewallTool()
    assert hasattr(tool, "agent_id")
    assert tool.agent_id == "firewall_tool"


@pytest.mark.asyncio
async def test_nftables_backend_creation():
    """测试：nftables 后端工厂创建"""
    from backend.tools.base import FirewallAdapterFactory
    from backend.tools.base import NftablesAdapter

    adapter = FirewallAdapterFactory.create("nftables")
    assert isinstance(adapter, NftablesAdapter)
    assert adapter.table == "secagentx"
    assert adapter.chain == "input"


@pytest.mark.asyncio
async def test_nftables_health_check_fallback():
    """测试：nftables 健康检查失败时优雅降级（非 root 环境）"""
    from backend.tools.base import NftablesAdapter
    adapter = NftablesAdapter()
    # 在非 root 环境下，nftables 命令会失败，但不应抛出异常
    healthy = await adapter.health_check()
    # 非 root 下返回 False，不会崩溃
    assert isinstance(healthy, bool)


@pytest.mark.asyncio
async def test_backend_creation_invalid():
    """测试：使用无效后端名称时抛出 ValueError"""
    from backend.tools.base import FirewallAdapterFactory
    with pytest.raises(ValueError) as excinfo:
        FirewallAdapterFactory.create("invalid_backend_xyz")
    assert "不支持" in str(excinfo.value)


@pytest.mark.asyncio
async def test_nftables_adapter_mock_execution():
    """测试：nftables 适配器在无 nft 命令时的优雅降级"""
    from backend.tools.base import NftablesAdapter
    import os

    # 模拟 nftables 命令不可用（PATH 中不存在 nft）
    adapter = NftablesAdapter()

    # block_ip 应该返回失败，但不会崩溃
    success, err = await adapter.block_ip("1.2.3.4", "test")
    # 在非 root/无 nft 环境下返回失败
    assert isinstance(success, bool)
    assert isinstance(err, str)


def test_tencent_backend_register():
    """测试：腾讯云后端已注册"""
    from backend.tools.base import FirewallAdapterFactory as Factory
    from backend.tools.tencent_firewall import TencentFirewallAdapter

    assert "tencent" in Factory.BACKENDS
    # 云 SDK 是可选依赖；工厂在首次 create() 时惰性加载。
    assert Factory.BACKENDS["tencent"] in (None, TencentFirewallAdapter)

    # 验证懒加载配置存在
    assert "tencent" in Factory._LAZY_LOADERS
    assert Factory._LAZY_LOADERS["tencent"]["class"] == "TencentFirewallAdapter"


def test_aws_backend_register():
    """测试：AWS 后端已注册"""
    from backend.tools.base import FirewallAdapterFactory as Factory
    from backend.tools.aws_firewall import AWSFirewallAdapter

    assert "aws" in Factory.BACKENDS
    assert Factory.BACKENDS["aws"] in (None, AWSFirewallAdapter)

    # 验证懒加载配置存在
    assert "aws" in Factory._LAZY_LOADERS
    assert Factory._LAZY_LOADERS["aws"]["class"] == "AWSFirewallAdapter"
    assert Factory._LAZY_LOADERS["aws"]["pip"] == "boto3"


@pytest.mark.asyncio
async def test_all_backends_registered():
    """测试：所有真实、测试和安全禁用后端已注册"""
    from backend.tools.base import FirewallAdapterFactory as Factory

    expected = {"disabled", "mock", "iptables", "nftables", "aliyun", "tencent", "aws"}
    registered = set(Factory.BACKENDS.keys())
    missing = expected - registered
    extra = registered - expected
    assert not missing, f"缺失后端: {missing}"
    assert not extra, f"多余后端: {extra}"
    assert len(registered) == 7


@pytest.mark.asyncio
async def test_tencent_adapter_credential_check():
    """测试：腾讯云适配器无凭证时优雅失败"""
    from backend.tools.tencent_firewall import TencentFirewallAdapter

    adapter = TencentFirewallAdapter()
    assert adapter._has_credentials is False

    result, err = await adapter.block_ip("1.2.3.4")
    assert result is False
    assert "凭证" in err

    result, err = await adapter.unblock_ip("1.2.3.4")
    assert result is False
    assert "凭证" in err

    rules = await adapter.list_rules()
    assert rules == []

    healthy = await adapter.health_check()
    assert healthy is False


@pytest.mark.asyncio
async def test_aws_adapter_credential_check():
    """测试：AWS 适配器无凭证时优雅失败"""
    from backend.tools.aws_firewall import AWSFirewallAdapter

    adapter = AWSFirewallAdapter()
    assert adapter._has_credentials is False

    result, err = await adapter.block_ip("1.2.3.4")
    assert result is False
    assert "凭证" in err

    result, err = await adapter.unblock_ip("1.2.3.4")
    assert result is False
    assert "凭证" in err

    rules = await adapter.list_rules()
    assert rules == []

    healthy = await adapter.health_check()
    assert healthy is False
