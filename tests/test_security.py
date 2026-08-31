"""
安全模块单元测试（auth / sanitizer / circuit_breaker）
"""
import os
import sys
import time
import json
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestAuth:
    """JWT 认证模块测试"""

    def test_create_and_verify_token(self):
        """测试：创建和验证 JWT Token"""
        from backend.security.auth import create_access_token, verify_token

        token = create_access_token(sub="admin", role="admin")
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20

        # 验证 token
        # 注意：这里需要 mock FastAPI 的 Depends
        # 直接测试 decode 逻辑
        import jwt as pyjwt
        from backend.security.auth import JWT_SECRET, JWT_ALGORITHM

        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "admin"
        assert payload["role"] == "admin"
        assert "exp" in payload
        assert "jti" in payload

    def test_token_expiry(self):
        """测试：Token 有过期时间"""
        from backend.security.auth import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
        token = create_access_token(sub="test")
        import jwt as pyjwt
        from backend.security.auth import JWT_SECRET, JWT_ALGORITHM
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # 应该在未来某个时间过期
        import time
        assert payload["exp"] > time.time()
        # 应该在 8 小时 + 5 分钟误差内过期
        max_exp = time.time() + (ACCESS_TOKEN_EXPIRE_MINUTES + 5) * 60
        assert payload["exp"] < max_exp


class TestSanitizer:
    """敏感信息脱敏测试"""

    def test_sanitize_api_key(self):
        """测试：API Key 脱敏"""
        from backend.security.sanitizer import sanitize_error

        msg = "Error: api_key=not-a-real-provider-key"
        result = sanitize_error(msg)
        assert "***REDACTED***" in result
        assert "abcdef1234567890abcdef12" not in result

    def test_sanitize_deepseek_key(self):
        """测试：DeepSeek API Key 脱敏"""
        from backend.security.sanitizer import sanitize_error

        msg = "DEEPSEEK_API_KEY=sk-secret-key-here"
        result = sanitize_error(msg)
        assert "***REDACTED***" in result
        assert "sk-secret-key-here" not in result

    def test_sanitize_qwen_key(self):
        """测试：Qwen API Key 脱敏"""
        from backend.security.sanitizer import sanitize_error

        msg = "QWEN_API_KEY=sk-another-secret"
        result = sanitize_error(msg)
        assert "***REDACTED***" in result

    def test_sanitize_normal_message(self):
        """测试：普通消息不受影响"""
        from backend.security.sanitizer import sanitize_error

        msg = "这是一个普通错误消息: connection refused"
        result = sanitize_error(msg)
        assert result == msg

    def test_sanitize_empty(self):
        """测试：空字符串"""
        from backend.security.sanitizer import sanitize_error
        assert sanitize_error("") == ""


class TestCircuitBreaker:
    """熔断器测试"""

    def _make_cb(self):
        """创建一个干净的熔断器实例"""
        from backend.security.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker()
        cb._state = "closed"
        cb._failures = 0
        cb._total_blocks_today = 0
        cb._last_failure_time = 0.0
        return cb

    def test_initial_state(self):
        """测试：初始状态为 CLOSED"""
        cb = self._make_cb()
        assert cb._state == "closed"

    def test_record_failure(self):
        """测试：记录失败"""
        from backend.security.circuit_breaker import MAX_CONSECUTIVE_FAILURES
        import asyncio

        cb = self._make_cb()
        async def run():
            for i in range(MAX_CONSECUTIVE_FAILURES - 1):
                await cb.record_failure()
                assert cb._state == "closed"
            # 第 N 次触发熔断
            await cb.record_failure()
            assert cb._state == "open"
        asyncio.run(run())

    def test_open_state_blocks(self):
        """测试：OPEN 状态下 check 返回 False"""
        from backend.security.circuit_breaker import MAX_CONSECUTIVE_FAILURES

        cb = self._make_cb()
        cb._failures = MAX_CONSECUTIVE_FAILURES
        cb._state = "open"
        cb._last_failure_time = time.time()  # 刚发生失败，不应自动恢复

        assert cb.check() is False

    def test_record_success_resets(self):
        """测试：成功记录重置状态"""
        cb = self._make_cb()
        cb._failures = 3
        cb._state = "open"

        cb.record_success()
        assert cb._state == "closed"
        assert cb._failures == 0

    def test_get_status(self):
        """测试：状态信息"""
        from backend.security.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker()
        status = cb.get_status()
        assert "state" in status
        assert "failures" in status
        assert "blocks_today" in status
        assert "is_blocked" in status

    def test_record_block_increments(self):
        """测试：封禁计数递增"""
        from backend.security.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker()
        initial = cb._total_blocks_today
        cb.record_block()
        assert cb._total_blocks_today == initial + 1

    def test_daily_limit(self):
        """测试：每日限额"""
        import datetime
        from backend.security.circuit_breaker import CircuitBreaker, MAX_DAILY_BLOCKS

        cb = CircuitBreaker()
        cb._last_failure_time = time.time()  # 确保不是在半开状态
        cb._last_reset_date = datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%d")  # 防止每日重置
        # 模拟达到限额
        cb._total_blocks_today = MAX_DAILY_BLOCKS
        assert cb.check() is False
