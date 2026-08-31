"""
测试自动安全巡检器 — AutoPatrol
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from backend.auto_patrol import AutoPatrol
from backend.security.circuit_breaker import circuit_breaker


@pytest.fixture
def mock_orchestrator():
    orch = MagicMock()
    orch.tools = MagicMock()
    orch.tools.execute = AsyncMock()
    orch.tools.count = MagicMock(return_value=6)
    orch.get_agent_statuses = MagicMock(return_value=[
        {"id": "analyst-001", "name": "分析师", "status": "idle", "enabled": True},
        {"id": "intel-001", "name": "情报员", "status": "idle", "enabled": True},
    ])
    orch.process_with_true_react = MagicMock()
    orch.process_with_true_react.return_value = AsyncMock()
    orch.process_with_true_react.return_value.__aiter__ = MagicMock(
        return_value=iter([{"type": "orchestrator_complete", "content": "ok"}])
    )
    return orch


@pytest.fixture
def mock_escalator():
    e = AsyncMock()
    e.escalate = AsyncMock()
    return e


@pytest.fixture
def config():
    return {
        "patrol": {
            "interval_seconds": 1800,
            "block_renew_threshold": 0.50,
            "reopen_window_hours": 24,
            "max_renew_count": 3,
        }
    }


class TestAutoPatrolInit:
    def test_default_config(self):
        patrol = AutoPatrol(orchestrator="mock", config={})
        assert patrol._interval == 1800
        assert patrol._renew_threshold == 0.50
        assert patrol._reopen_window == 24
        assert patrol._max_renew == 3
        assert patrol._running is False
        assert patrol._patrol_count == 0

    def test_custom_config(self):
        cfg = {"patrol": {
            "interval_seconds": 300,
            "block_renew_threshold": 0.70,
            "reopen_window_hours": 48,
            "max_renew_count": 5,
        }}
        patrol = AutoPatrol(orchestrator="mock", config=cfg)
        assert patrol._interval == 300
        assert patrol._renew_threshold == 0.70
        assert patrol._reopen_window == 48
        assert patrol._max_renew == 5

    def test_empty_patrol_config(self):
        patrol = AutoPatrol(orchestrator="mock", config={"patrol": {}})
        assert patrol._interval == 1800


class TestAutoPatrolStartStop:
    @pytest.mark.asyncio
    async def test_start_stop(self):
        patrol = AutoPatrol(orchestrator=MagicMock(), config={})
        # stop 前 _running 应为 False
        patrol._running = True
        await patrol.stop()
        assert patrol._running is False

    @pytest.mark.asyncio
    async def test_start_twice(self, mock_orchestrator):
        patrol = AutoPatrol(orchestrator=mock_orchestrator, config={})
        patrol._running = True
        await patrol.start()


class TestGetStats:
    def test_initial_stats(self):
        patrol = AutoPatrol(orchestrator="mock", config={})
        stats = patrol.get_stats()
        assert stats["patrol_count"] == 0
        assert stats["running"] is False
        assert stats["renew_counts"] == {}

    def test_stats_after_patrol(self, mock_orchestrator, mock_escalator, config):
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        patrol._patrol_count = 5
        patrol._renew_count = {"10.0.0.1": 2}
        stats = patrol.get_stats()
        assert stats["patrol_count"] == 5
        assert stats["renew_counts"]["10.0.0.1"] == 2


class TestPatrolBlockList:
    @pytest.mark.asyncio
    async def test_no_rules(self, mock_orchestrator, mock_escalator, config):
        mock_orchestrator.tools.execute.return_value = MagicMock(
            success=True, data={"rules": []}
        )
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        result = await patrol._patrol_block_list()
        assert result["active"] == 0
        assert result["expiring"] == 0
        assert result["errors"] == 0

    @pytest.mark.asyncio
    async def test_firewall_error(self, mock_orchestrator, mock_escalator, config):
        mock_orchestrator.tools.execute.return_value = MagicMock(
            success=False, error="防火墙不可达"
        )
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        result = await patrol._patrol_block_list()
        assert result["errors"] == 1

    @pytest.mark.asyncio
    async def test_renew_threshold_met(self, mock_orchestrator, mock_escalator, config):
        from datetime import datetime, timezone, timedelta
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        mock_orchestrator.tools.execute = AsyncMock()
        mock_orchestrator.tools.execute.side_effect = [
            MagicMock(success=True, data={"rules": [{
                "ip": "10.0.0.1",
                "expire_at": future,
                "duration_minutes": 120,
            }]}),
            MagicMock(success=True, data={"score": 0.85}),
            MagicMock(success=True, data={"expire_at": future}),
        ]

        # Patch circuit_breaker.check() 直接返回 True
        original_check = circuit_breaker.check
        circuit_breaker.check = MagicMock(return_value=True)
        try:
            patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
            result = await patrol._patrol_block_list()
            assert result["active"] == 1
            assert result["renewed"] == 1
        finally:
            circuit_breaker.check = original_check

    @pytest.mark.asyncio
    async def test_renew_skipped_low_score(self, mock_orchestrator, mock_escalator, config):
        from datetime import datetime, timezone, timedelta
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        mock_orchestrator.tools.execute = AsyncMock()
        mock_orchestrator.tools.execute.side_effect = [
            MagicMock(success=True, data={"rules": [{
                "ip": "10.0.0.1",
                "expire_at": future,
                "duration_minutes": 120,
            }]}),
            MagicMock(success=True, data={"score": 0.10}),
        ]
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        result = await patrol._patrol_block_list()
        assert result["active"] == 1
        assert result["renewed"] == 0

    @pytest.mark.asyncio
    async def test_max_renew_escalated(self, mock_orchestrator, mock_escalator, config):
        from datetime import datetime, timezone, timedelta
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        mock_orchestrator.tools.execute.return_value = MagicMock(
            success=True, data={"rules": [{
                "ip": "10.0.0.1",
                "expire_at": future,
                "duration_minutes": 120,
            }]}
        )
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        patrol._renew_count["10.0.0.1"] = 3
        result = await patrol._patrol_block_list()
        assert result["escalated"] == 1


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_status(self, mock_orchestrator, config):
        patrol = AutoPatrol(orchestrator=mock_orchestrator, config=config)
        result = await patrol._health_check()
        assert result["status"] == "healthy"
        assert len(result["agents"]) == 2
        assert result["tools"] == 6

    @pytest.mark.asyncio
    async def test_orchestrator_error(self, config):
        broken = MagicMock()
        broken.get_agent_statuses.side_effect = Exception("不通")
        patrol = AutoPatrol(orchestrator=broken, config=config)
        result = await patrol._health_check()
        assert "error" in result


class TestPatrolCycle:
    @pytest.mark.asyncio
    async def test_full_cycle(self, mock_orchestrator, mock_escalator, config):
        mock_orchestrator.tools.execute.return_value = MagicMock(
            success=True, data={"rules": []}
        )
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        result = await patrol._patrol_cycle()
        assert "timestamp" in result
        assert "block_renewal" in result
        assert "event_reopen" in result
        assert "health" in result

    @pytest.mark.asyncio
    async def test_patrol_once(self, mock_orchestrator, mock_escalator, config):
        mock_orchestrator.tools.execute.return_value = MagicMock(
            success=True, data={"rules": []}
        )
        patrol = AutoPatrol(orchestrator=mock_orchestrator, escalator=mock_escalator, config=config)
        result = await patrol.patrol_once()
        assert "block_renewal" in result
