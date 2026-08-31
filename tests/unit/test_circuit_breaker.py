"""
熔断器状态机单元测试
覆盖: CLOSED → OPEN → HALF_OPEN → CLOSED 全状态转换

运行: python -m pytest tests/unit/test_circuit_breaker.py -v
"""
import os
import sys
import json
import time
import tempfile
import pytest

# 测试环境 — 确保使用临时文件
_test_dir = tempfile.mkdtemp(prefix="secagentx_test_cb_")
os.environ["CIRCUIT_FILE"] = os.path.join(_test_dir, ".circuit_breaker.json")
os.environ["SECAGENTX_DB_PATH"] = os.path.join(_test_dir, "test.db")
os.environ["CI"] = "true"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# 模块级常量 — 测试需要引用
from backend.security.circuit_breaker import (
    MAX_CONSECUTIVE_FAILURES, MAX_DAILY_BLOCKS, CIRCUIT_RESET_MINUTES,
    CIRCUIT_FILE as MODULE_CIRCUIT_FILE,
)


@pytest.fixture(autouse=True)
def reset_circuit_breaker():
    """每个测试前重置熔断器状态"""
    from backend.security.circuit_breaker import CircuitBreaker
    from datetime import datetime, timezone
    cb = CircuitBreaker()
    cb._state = "closed"
    cb._failures = 0
    cb._total_blocks_today = 0
    cb._last_failure_time = 0.0
    cb._last_reset_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    yield cb


class TestCircuitBreakerInitialState:
    """熔断器初始状态测试"""

    def test_initial_state_is_closed(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        status = cb.get_status()
        assert status["state"] == "closed"
        assert status["failures"] == 0
        assert status["is_blocked"] is False

    def test_initial_check_passes(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        assert cb.check() is True

    def test_initial_daily_blocks_zero(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        assert cb._total_blocks_today == 0

    def test_module_constants_are_positive(self):
        assert MAX_CONSECUTIVE_FAILURES >= 1
        assert MAX_DAILY_BLOCKS >= 1
        assert CIRCUIT_RESET_MINUTES >= 1


class TestCircuitBreakerOpenOnFailures:
    """熔断器触发开启测试"""

    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        for i in range(MAX_CONSECUTIVE_FAILURES - 1):
            await cb.record_failure()
            assert cb._state == "closed", f"第{i+1}次失败不应熔断"

        # 第 MAX 次失败 → 应熔断
        await cb.record_failure()
        assert cb._state == "open"

    @pytest.mark.asyncio
    async def test_check_returns_false_when_open(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        for _ in range(MAX_CONSECUTIVE_FAILURES):
            await cb.record_failure()

        assert cb.check() is False

    @pytest.mark.asyncio
    async def test_daily_limit_blocks_operations(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        cb._total_blocks_today = MAX_DAILY_BLOCKS

        assert cb.check() is False


class TestCircuitBreakerRecovery:
    """熔断器自动恢复测试"""

    @pytest.mark.asyncio
    async def test_half_open_after_reset_period(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        cb._state = "open"
        cb._last_failure_time = time.time() - (CIRCUIT_RESET_MINUTES * 60 + 1)

        assert cb.check() is True
        assert cb._state == "half_open"

    @pytest.mark.asyncio
    async def test_success_resets_to_closed(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        await cb.record_failure()
        cb.record_success()

        status = cb.get_status()
        assert status["state"] == "closed"
        assert status["failures"] == 0

    @pytest.mark.asyncio
    async def test_failure_in_half_open_triggers_escalation(self, reset_circuit_breaker):
        """半开状态下再次失败 → 触发升级通知回调"""
        cb = reset_circuit_breaker
        cb._state = "half_open"
        cb._failures = MAX_CONSECUTIVE_FAILURES - 1

        escalation_called = []
        async def mock_callback(msg):
            escalation_called.append(msg)

        cb.set_escalate_callback(mock_callback)
        await cb.record_failure()

        assert cb._state == "open"
        assert len(escalation_called) == 1
        assert "自动恢复失败" in escalation_called[0]


class TestCircuitBreakerPersistence:
    """熔断器状态持久化测试"""

    @pytest.mark.asyncio
    async def test_state_persisted_to_file(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        for _ in range(MAX_CONSECUTIVE_FAILURES):
            await cb.record_failure()

        # 使用模块实际的 CIRCUIT_FILE 路径检查
        assert os.path.exists(MODULE_CIRCUIT_FILE), f"文件不存在: {MODULE_CIRCUIT_FILE}"

        with open(MODULE_CIRCUIT_FILE, "r") as f:
            data = json.load(f)
        assert data["state"] == "open"
        assert data["failures"] == MAX_CONSECUTIVE_FAILURES


class TestRecordBlock:
    """封禁记录测试"""

    def test_record_block_increments_counter(self, reset_circuit_breaker):
        cb = reset_circuit_breaker
        initial = cb._total_blocks_today
        cb.record_block()
        assert cb._total_blocks_today == initial + 1
