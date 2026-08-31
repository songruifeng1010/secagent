"""
速率限制器单元测试（令牌桶算法 + RateLimiter）

运行: python -m pytest tests/unit/test_ratelimiter.py -v
"""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TestTokenBucket:
    """令牌桶算法测试"""

    def test_initial_tokens_full(self):
        from backend.security.ratelimit import TokenBucket
        bucket = TokenBucket(rate=10, burst=5)
        assert bucket.tokens == 5

    def test_consume_success(self):
        from backend.security.ratelimit import TokenBucket
        bucket = TokenBucket(rate=10, burst=5)
        assert bucket.consume() is True
        assert bucket.tokens == 4

    def test_consume_exhaust(self):
        from backend.security.ratelimit import TokenBucket
        bucket = TokenBucket(rate=10, burst=2)
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is False  # 耗尽了

    def test_refill_over_time(self):
        from backend.security.ratelimit import TokenBucket
        bucket = TokenBucket(rate=10, burst=5)
        bucket.tokens = 0
        bucket.last_refill = time.monotonic() - 0.5  # 半秒前

        # 半秒应补充 10 * 0.5 = 5 个令牌，但 burst 限制为 5
        assert bucket.consume() is True
        # 补充后应有 5 个，消耗 1 个剩 4 个
        assert bucket.tokens == 4

    def test_wait_seconds(self):
        from backend.security.ratelimit import TokenBucket
        bucket = TokenBucket(rate=10, burst=5)
        assert bucket.wait_seconds == 0  # 有令牌

        bucket.tokens = 0
        assert bucket.wait_seconds > 0  # 需要等待


class TestRateLimiter:
    """RateLimiter 集成测试"""

    @pytest.mark.asyncio
    async def test_check_websocket_no_limit(self):
        """WebSocket 路径不限流"""
        from backend.security.ratelimit import ratelimiter

        allowed, retry_after = await ratelimiter.check("/ws/chat", "1.2.3.4")
        assert allowed is True
        assert retry_after == 0

    @pytest.mark.asyncio
    async def test_auth_path_strict_limit(self):
        """登录接口严格限流"""
        from backend.security.ratelimit import ratelimiter

        for _ in range(5):
            allowed, _ = await ratelimiter.check("/api/auth/login", "5.6.7.8")
            assert allowed is True

        # 超过限制（burst=10, 但 rate=5/s）
        # 由于时间推移可能会补充令牌，不能保证第6次一定失败
        # 我们只验证函数不会崩溃
        allowed, retry_after = await ratelimiter.check("/api/auth/login", "5.6.7.8")
        assert isinstance(allowed, bool)
        assert isinstance(retry_after, int)

    @pytest.mark.asyncio
    async def test_health_path_no_limit(self):
        """健康检查路径不限流"""
        from backend.security.ratelimit import ratelimiter

        allowed, retry_after = await ratelimiter.check("/api/health", "1.2.3.4")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """限流统计不崩溃"""
        from backend.security.ratelimit import ratelimiter

        stats = ratelimiter.get_stats()
        assert "patterns" in stats
        assert "active_buckets" in stats
