"""
FirewallTool 进阶测试 — 覆盖阿里云凭证、熔断器集成、Mock 过期等场景
"""
import os
import json
import time
import pytest
from unittest.mock import MagicMock, patch
from backend.tools.firewall import FirewallExecutionContext, FirewallTool


# ═══════════════════ 阿里云适配器凭证测试 ═══════════════════

class TestAliyunCredential:
    """阿里云与 AWS/腾讯云同样的凭证检查测试"""

    @pytest.mark.asyncio
    async def test_aliyun_no_credentials(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        assert adapter._has_credentials is False

    @pytest.mark.asyncio
    async def test_aliyun_block_no_creds(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        result, err = await adapter.block_ip("1.2.3.4")
        assert result is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_aliyun_unblock_no_creds(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        result, err = await adapter.unblock_ip("1.2.3.4")
        assert result is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_aliyun_list_no_creds(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        rules = await adapter.list_rules()
        assert rules == []

    @pytest.mark.asyncio
    async def test_aliyun_health_no_creds(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        healthy = await adapter.health_check()
        assert healthy is False

    @pytest.mark.asyncio
    async def test_aliyun_has_credentials(self):
        """设置环境变量后验证 credentials 识别"""
        with patch.dict(os.environ, {
            "ALIBABA_CLOUD_ACCESS_KEY_ID": "test-key",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "test-secret",
            "ALIYUN_SECURITY_GROUP_ID": "sg-test",
        }):
            from backend.tools.aliyun_firewall import AliyunFirewallAdapter
            adapter = AliyunFirewallAdapter()
            assert adapter._has_credentials is True


# ═══════════════════ Mock 后端到期测试 ═══════════════════

class TestMockExpiry:
    @pytest.mark.asyncio
    async def test_block_with_duration(self):
        tool = FirewallTool()
        await tool.execute(action="block", ip="1.1.1.1",
                           confidence=0.90, duration_minutes=60)
        result = await tool.execute(action="check", ip="1.1.1.1")
        assert result.data["is_blocked"] is True

    @pytest.mark.asyncio
    async def test_list_expiry_excludes_expired(self):
        """过期规则不应出现在封禁列表中"""
        from datetime import datetime, timezone, timedelta
        import backend.tools.base as base

        adapter = base.MockFirewallAdapter()
        # 手动写入一条极短有效期的规则（已过期）
        ip = "expired-test-ip"
        adapter._rules[ip] = {
            "reason": "should-expire",
            "blocked_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            "expire_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "duration_minutes": 1,
        }
        rules = await adapter.list_rules()
        assert all(r["ip"] != ip for r in rules), "过期规则应被排除"

    @pytest.mark.asyncio
    async def test_check_expired_returns_false(self):
        from datetime import datetime, timezone, timedelta
        import backend.tools.base as base

        adapter = base.MockFirewallAdapter()
        ip = "expired-ip"
        adapter._rules[ip] = {
            "reason": "expired",
            "blocked_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            "expire_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "duration_minutes": 1,
        }
        result = await adapter.check_ip(ip)
        assert result["is_blocked"] is False

    @pytest.mark.asyncio
    async def test_mock_save_and_load_persistence(self):
        """Mock 后端应支持序列化到文件并重新加载"""
        import tempfile
        import backend.tools.base as base

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp_path = f.name

        with patch.dict(os.environ, {"BLACKLIST_FILE": tmp_path}):
            adapter = base.MockFirewallAdapter()
            await adapter.block_ip("10.0.0.99", "persist-test", 120)
            assert "10.0.0.99" in adapter._rules

            # 新建一个适配器，应能从文件加载
            adapter2 = base.MockFirewallAdapter()
            result = await adapter2.check_ip("10.0.0.99")
            assert result["is_blocked"] is True

        os.unlink(tmp_path)


# ═══════════════════ 熔断器集成测试 ═══════════════════

class TestCircuitBreakerIntegration:
    @pytest.fixture(autouse=True)
    def _save_restore_cb(self, monkeypatch):
        """保存并在测试后恢复熔断器完整状态"""
        from backend.security.circuit_breaker import circuit_breaker
        from datetime import datetime, timezone
        # 构造“今天刚触发”的状态，避免被合法的每日重置/半开超时清除。
        monkeypatch.setattr(circuit_breaker, '_last_failure_time', time.time())
        monkeypatch.setattr(circuit_breaker, '_last_reset_date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
        saved = (circuit_breaker._state, circuit_breaker._failures,
                 circuit_breaker._total_blocks_today)
        yield
        (circuit_breaker._state, circuit_breaker._failures,
         circuit_breaker._total_blocks_today) = saved

    @pytest.mark.asyncio
    async def test_block_rejected_when_cb_open(self):
        """熔断器 OPEN 时封禁应被拒绝"""
        from backend.security.circuit_breaker import circuit_breaker
        circuit_breaker._state = "open"
        circuit_breaker._failures = 3
        circuit_breaker._total_blocks_today = 20

        tool = FirewallTool(block_threshold=0.70)
        result = await tool.execute(
            action="block", ip="1.2.3.4",
            reason="测试", confidence=0.95,
        )
        assert result.success is False
        assert "熔断器" in result.error
        assert result.data["action"] == "rejected"

    @pytest.mark.asyncio
    async def test_manual_context_cannot_bypass_circuit_breaker(self):
        """人工授权只绕过置信度，不能绕过熔断器。"""
        from backend.security.circuit_breaker import circuit_breaker
        circuit_breaker._state = "open"
        circuit_breaker._failures = 3
        circuit_breaker._total_blocks_today = 20

        tool = FirewallTool(block_threshold=0.70)
        context = FirewallExecutionContext.local_console(
            action="block", actor="local-console", reason="紧急"
        )
        result = await tool.execute(
            action="block", ip="2.2.2.2",
            reason="紧急", confidence=0.10,
            authorization_context=context,
        )
        assert result.success is False
        assert "熔断器" in result.error

    @pytest.mark.asyncio
    async def test_daily_limit_rejected(self):
        """每日限额已满时应拒绝封禁"""
        from backend.security.circuit_breaker import circuit_breaker
        from backend.security.circuit_breaker import MAX_DAILY_BLOCKS
        circuit_breaker._total_blocks_today = MAX_DAILY_BLOCKS

        tool = FirewallTool(block_threshold=0.70)
        result = await tool.execute(
            action="block", ip="3.3.3.3",
            reason="测试", confidence=0.95,
        )
        assert result.success is False
        assert "熔断器" in result.error or "限额" in result.error


# ═══════════════════ 边界条件测试 ═══════════════════

class TestEdgeCases:
    @pytest.fixture(autouse=True)
    def _reset_cb(self):
        """每个边界测试前重置熔断器状态（避免被其他测试遗留状态影响）"""
        from backend.security.circuit_breaker import circuit_breaker
        from datetime import datetime, timezone
        circuit_breaker._state = "closed"
        circuit_breaker._total_blocks_today = 0
        circuit_breaker._failures = 0
        circuit_breaker._last_reset_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        yield

    @pytest.mark.asyncio
    async def test_block_empty_ip(self):
        tool = FirewallTool()
        result = await tool.execute(action="block", ip="", confidence=0.90)
        assert result.success is False
        assert "IP" in result.error

    @pytest.mark.asyncio
    async def test_unblock_empty_ip(self):
        tool = FirewallTool()
        result = await tool.execute(action="unblock", ip="", confidence=0.90)
        assert result.success is False
        assert "IP" in result.error

    @pytest.mark.asyncio
    async def test_check_empty_ip(self):
        tool = FirewallTool()
        result = await tool.execute(action="check", ip="")
        assert result.success is False
        assert "IP" in result.error

    @pytest.mark.asyncio
    async def test_block_zero_duration(self):
        tool = FirewallTool()
        result = await tool.execute(
            action="block", ip="4.4.4.4",
            confidence=0.90, duration_minutes=0,
        )
        assert result.success is True
        assert result.data["duration_minutes"] == 0

    @pytest.mark.asyncio
    async def test_block_very_long_reason(self):
        tool = FirewallTool()
        long_reason = "A" * 500
        result = await tool.execute(
            action="block", ip="5.5.5.5",
            reason=long_reason, confidence=0.90,
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_block_confidence_exactly_threshold(self):
        tool = FirewallTool(block_threshold=0.70)
        result = await tool.execute(
            action="block", ip="6.6.6.6",
            confidence=0.70, reason="exactly at threshold",
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_unblock_confidence_exactly_threshold(self):
        tool = FirewallTool(unblock_threshold=0.85)
        await tool.execute(
            action="block", ip="7.7.7.7",
            confidence=0.90,
        )
        result = await tool.execute(
            action="unblock", ip="7.7.7.7",
            confidence=0.85,
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_whitelist_cannot_be_bypassed_by_manual_context(self):
        tool = FirewallTool(whitelist=["10.0.0.1"])
        context = FirewallExecutionContext.local_console(
            action="block", actor="local-console", reason="白名单测试"
        )
        result = await tool.execute(
            action="block", ip="10.0.0.1",
            confidence=0.10, authorization_context=context,
        )
        assert result.success is False
        assert "白名单" in result.error

    @pytest.mark.asyncio
    async def test_circuit_breaker_error_fails_closed(self, monkeypatch):
        from backend.security.circuit_breaker import circuit_breaker

        def broken_check():
            raise RuntimeError("state store unavailable")

        monkeypatch.setattr(circuit_breaker, "check", broken_check)
        tool = FirewallTool(block_threshold=0.70, whitelist=[])
        result = await tool.execute(
            action="block", ip="8.8.8.8", confidence=0.99
        )
        assert result.success is False
        assert "安全检查失败" in result.error
