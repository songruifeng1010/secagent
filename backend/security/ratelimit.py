"""
SecAgentX API 速率限制器 — 令牌桶算法（支持 Redis 分布式）

防止 API 滥用和暴力攻击。支持:
  - 按路径区分限流策略
  - 按 IP 维度隔离
  - 内存存储（单实例，默认）
  - Redis 存储（分布式部署，通过环境变量 REDIS_URL 启用）

使用方式（FastAPI 中间件）:
    from backend.security.ratelimit import RateLimiter, TokenBucket, ratelimiter
    # 直接使用全局单例:
    allowed, retry_after = await ratelimiter.check(path, ip)
"""
import os
import time
import logging
from collections import defaultdict
from typing import Optional

logger = logging.getLogger("secagentx.ratelimit")


class TokenBucket:
    """令牌桶限流算法"""

    __slots__ = ("rate", "burst", "tokens", "last_refill")

    def __init__(self, rate: float, burst: int):
        self.rate = rate          # 每秒补充令牌数
        self.burst = burst        # 桶容量（最大突发）
        self.tokens = float(burst)
        self.last_refill = time.monotonic()

    def consume(self, count: int = 1) -> bool:
        """消费 tokens，返回是否允许通过"""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

    @property
    def wait_seconds(self) -> float:
        """获取下一次可用所需的等待秒数"""
        if self.tokens >= 1:
            return 0
        return (1 - self.tokens) / self.rate if self.rate > 0 else float("inf")


class RateLimiter:
    """
    速率限制器

    默认限制（按 IP 维度）:
      - /api/auth/*   : 5 req/s, burst=10     (登录接口严格限流)
      - /api/*        : 30 req/s, burst=60     (一般 API)
      - /webhook/*    : 100 req/s, burst=200   (告警接入)
      - /ws/*         : 不限流（WebSocket 长连接）
      - 其他          : 20 req/s, burst=40
    """

    DEFAULTS: dict[str, tuple[float, int]] = {
        "/api/auth/": (5, 10),
        "/api/": (30, 60),
        "/webhook/": (100, 200),
    }

    def __init__(self, config: Optional[dict] = None):
        self._buckets: dict[str, dict[str, TokenBucket]] = defaultdict(dict)
        self._config = config or self.DEFAULTS
        self._storage_type = "memory"

    def _get_path_pattern(self, path: str) -> Optional[str]:
        """匹配最具体的路径模式"""
        matched = None
        matched_len = 0
        for pattern in self._config:
            if path.startswith(pattern) and len(pattern) > matched_len:
                matched = pattern
                matched_len = len(pattern)
        return matched

    async def check(self, path: str, ip: str = "") -> tuple[bool, int]:
        """
        检查请求是否允许通过

        返回:
            (allowed: bool, retry_after_seconds: int)
        """
        # WebSocket 不限流
        if path.startswith("/ws/"):
            return True, 0

        pattern = self._get_path_pattern(path)
        if pattern is None:
            # 默认限制
            rate, burst = 20, 40
        else:
            rate, burst = self._config[pattern]

        key = f"{pattern or '__default__'}:{ip}"
        bucket = self._buckets[pattern or "__default__"].get(ip)
        if bucket is None:
            bucket = TokenBucket(rate, burst)
            self._buckets[pattern or "__default__"][ip] = bucket

        allowed = bucket.consume()
        if not allowed:
            wait = int(bucket.wait_seconds) + 1
            logger.warning(f"速率限制触发: path={path}, ip={ip}, wait={wait}s")
            return False, wait

        # 定期清理过期桶（惰性清理）
        if len(self._buckets) > 10000:
            self._cleanup()

        return True, 0

    def _cleanup(self):
        """清理超过 60 秒不活跃的桶"""
        now = time.monotonic()
        for pattern, ip_buckets in list(self._buckets.items()):
            for ip, bucket in list(ip_buckets.items()):
                if now - bucket.last_refill > 60:
                    del ip_buckets[ip]
            if not ip_buckets:
                del self._buckets[pattern]

    def get_stats(self) -> dict:
        """获取限流统计"""
        total_buckets = sum(len(b) for b in self._buckets.values())
        return {
            "patterns": len(self._config),
            "active_buckets": total_buckets,
            "storage": self._storage_type,
        }


# ═══════════════════════ Redis 分布式限流器 ═══════════════════════

class RedisRateLimiter(RateLimiter):
    """
    Redis 分布式速率限制器

    用于多副本部署场景，所有实例共享同一个限流状态。
    通过环境变量 REDIS_URL 启用:
      REDIS_URL=redis://:password@redis:6379/0

    回退策略: 如果 Redis 连接失败，自动降级到内存模式。
    """

    def __init__(self, config: Optional[dict] = None, redis_url: str = ""):
        super().__init__(config)
        self._redis_url = redis_url or os.getenv("REDIS_URL", "")
        self._redis = None
        self._redis_available = False
        self._storage_type = "redis" if self._redis_url else "memory"

        if self._redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                self._redis_available = True
            except Exception as e:
                logger.warning(f"Redis 连接失败，降级到内存模式: {e}")
                self._storage_type = "memory(fallback)"

    async def check(self, path: str, ip: str = "") -> tuple[bool, int]:
        if path.startswith("/ws/"):
            return True, 0

        pattern = self._get_path_pattern(path)
        if pattern is None:
            rate, burst = 20, 40
        else:
            rate, burst = self._config[pattern]

        key = f"ratelimit:{pattern or '__default__'}:{ip}"

        # Redis 模式
        if self._redis_available and self._redis:
            try:
                import time
                now = time.time()
                pipe = self._redis.pipeline()
                pipe.set(key, now, ex=60)  # 60s TTL
                pipe.ttl(key)
                results = await pipe.execute()

                # Redis SETNX 风格的限流：滑动窗口
                current = await self._redis.get(f"{key}:count")
                if current is None:
                    await self._redis.setex(f"{key}:count", 1, 1)
                    await self._redis.setex(f"{key}:window", 1, now)
                    return True, 0

                count = int(current)
                if count >= burst:
                    return False, 1

                await self._redis.incr(f"{key}:count")
                return True, 0

            except Exception as e:
                logger.warning(f"Redis 限流失败，降级到内存: {e}")
                self._redis_available = False
                self._storage_type = "memory(fallback)"

        # 内存模式（回退）
        return await super().check(path, ip)

    async def close(self):
        if self._redis:
            try:
                await self._redis.close()
            except Exception:
                pass


# 全局单例 — 自动检测 Redis 配置
_redis_url = os.getenv("REDIS_URL", "")
if _redis_url:
    ratelimiter = RedisRateLimiter(redis_url=_redis_url)
    logger.info(f"速率限制器: Redis 模式 ({_redis_url[:30]}...)")
else:
    ratelimiter = RateLimiter()
    logger.info("速率限制器: 内存模式")
