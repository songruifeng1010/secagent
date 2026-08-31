"""
跨区域联邦同步集成测试
覆盖: 事件双向同步、防环路 ID 前缀过滤、黑名单 LWW 冲突裁决

运行: python -m pytest tests/integration/test_federation.py -v --tb=short
"""
import os
import sys
import json
import tempfile
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

_test_dir = tempfile.mkdtemp(prefix="secagentx_intg_fed_")
os.environ["SECAGENTX_DB_PATH"] = os.path.join(_test_dir, "test.db")
os.environ["CIRCUIT_FILE"] = os.path.join(_test_dir, ".circuit_breaker.json")
os.environ["DEEPSEEK_API_KEY"] = "mock"
os.environ["CI"] = "true"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.main import init_db

# 使用独立临时数据库文件
_test_db_path = os.path.join(_test_dir, "test.db")
os.environ["SECAGENTX_DB_PATH"] = _test_db_path
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"
init_db()  # 使用 SECAGENTX_DB_PATH 环境变量


SAMPLE_FED_CONFIG = {
    "enabled": True,
    "region_id": "beijing",
    "region_name": "北京",
    "peers": [
        {
            "region_id": "shanghai",
            "region_name": "上海",
            "api_url": "http://shanghai-secagentx:8000",
            "api_token": "test-fed-token-shanghai",
            "sync_events": True,
            "sync_blacklist": True,
        },
    ],
    "sync": {
        "event_interval_seconds": 60,
        "blacklist_interval_seconds": 30,
        "max_batch_size": 100,
        "timeout_seconds": 10,
    },
}


class TestFederationInit:
    """联邦初始化测试"""

    def test_init_disabled(self):
        from backend.federation.core import Federation
        fed = Federation({"enabled": False})
        assert fed.enabled is False
        assert len(fed._peers) == 0

    def test_init_enabled_mesh(self):
        from backend.federation.core import Federation
        fed = Federation(SAMPLE_FED_CONFIG)
        assert fed.enabled is True
        assert fed.region_id == "beijing"
        assert fed.mode == "mesh"
        assert len(fed._peers) == 1

    def test_init_skip_self(self):
        """不应将自己加为对端"""
        from backend.federation.core import Federation
        cfg = dict(SAMPLE_FED_CONFIG)
        cfg["peers"] = [
            {"region_id": "beijing", "api_url": "http://localhost", "api_token": "tok"},
            {"region_id": "shanghai", "api_url": "http://shanghai", "api_token": "tok"},
        ]
        fed = Federation(cfg)
        peer_ids = [p.region_id for p in fed._peers]
        assert "beijing" not in peer_ids  # 跳过自己
        assert "shanghai" in peer_ids


class TestFederationIdentity:
    """联邦身份验证测试"""

    @pytest.mark.asyncio
    async def test_verify_peer_valid_token(self, monkeypatch):
        from backend.federation.core import verify_peer_request, _PEER_TOKENS
        # 注入测试 Token
        _PEER_TOKENS.clear()
        _PEER_TOKENS["shanghai"] = "test-token"

        mock_request = MagicMock()
        mock_request.headers = {
            "authorization": "Bearer test-token",
            "x-region-id": "shanghai",
        }

        valid, detail = await verify_peer_request(mock_request)
        assert valid is True
        assert detail == "shanghai"

    @pytest.mark.asyncio
    async def test_verify_peer_invalid_token(self):
        from backend.federation.core import verify_peer_request, _PEER_TOKENS
        _PEER_TOKENS.clear()
        _PEER_TOKENS["beijing"] = "correct-token"

        mock_request = MagicMock()
        mock_request.headers = {
            "authorization": "Bearer wrong-token",
            "x-region-id": "beijing",
        }

        valid, detail = await verify_peer_request(mock_request)
        assert valid is False

    @pytest.mark.asyncio
    async def test_verify_peer_missing_token(self):
        from backend.federation.core import verify_peer_request
        mock_request = MagicMock()
        mock_request.headers = {"authorization": ""}

        valid, detail = await verify_peer_request(mock_request)
        assert valid is False


class TestFederationEventSync:
    """事件同步测试"""

    @pytest.mark.asyncio
    async def test_add_pending_event(self):
        from backend.federation.core import Federation
        fed = Federation(SAMPLE_FED_CONFIG)

        await fed.add_pending_event({
            "id": "evt-001", "title": "SSH暴力破解",
            "severity": "高危", "source_ip": "1.2.3.4",
        })
        assert len(fed._pending["events"]) == 1

        # 防丢失：验证持久化文件
        import os
        from backend.federation.core import _PENDING_FILE
        assert os.path.exists(_PENDING_FILE)

    @pytest.mark.asyncio
    async def test_save_remote_events_with_prefix(self):
        """远程事件保存时 ID 应带区域前缀（防环路）"""
        from backend.federation.core import Federation
        from backend.storage.database import get_repository
        fed = Federation(SAMPLE_FED_CONFIG)

        await fed._save_remote_events("shanghai", [
            {"id": "evt-remote-001", "title": "远程告警", "severity": "高危"},
        ])

        async with get_repository() as repo:
            row = await repo.fetch_one(
                "SELECT id, title FROM events WHERE id LIKE ?",
                ("fed-shanghai-%",),
            )
            assert row is not None, "远程事件应写入数据库"
            assert row["id"].startswith("fed-shanghai-"), f"ID 应有区域前缀: {row['id']}"

    @pytest.mark.asyncio
    async def test_loop_filtering_prevention(self):
        """防环路：本地事件不应包含 'fed-' 前缀"""
        from backend.federation.core import Federation
        from backend.storage.database import get_repository
        fed = Federation(SAMPLE_FED_CONFIG)

        # 写入一条本地事件
        async with get_repository() as repo:
            await repo.execute(
                "INSERT OR IGNORE INTO events (id, title, severity, status, source_ip, description, created_at) "
                "VALUES (?, ?, ?, 'open', ?, ?, ?)",
                ("local-evt-001", "本地告警", "高危", "10.0.0.1", "本地事件", "2026-07-08T00:00:00Z"),
            )

        # 拉取时应能正确过滤
        async with get_repository() as repo:
            rows = await repo.fetch_all(
                "SELECT id FROM events WHERE id NOT LIKE ?",
                ("fed-%",),
            )
            ids = [r["id"] for r in rows]
            assert "local-evt-001" in ids
            # fed- 前缀的事件不应出现在 NOT LIKE 'fed-%' 中
            fed_ids = [r["id"] for r in rows if r["id"].startswith("fed-")]
            assert len(fed_ids) == 0, f"环路过滤失败: {fed_ids}"


class TestFederationConflictResolution:
    """冲突裁决测试（LWW + 统一时间戳）"""

    def test_normalize_ts_iso(self):
        from backend.federation.core import Federation
        fed = Federation(SAMPLE_FED_CONFIG)

        result = fed._normalize_ts("2026-07-08T10:00:00+00:00")
        assert result == "2026-07-08T10:00:00.000Z"

    def test_normalize_ts_simple(self):
        from backend.federation.core import Federation
        fed = Federation(SAMPLE_FED_CONFIG)

        result = fed._normalize_ts("2026-07-08 10:00:00")
        assert "T10:00:00.000Z" in result

    def test_normalize_ts_empty(self):
        from backend.federation.core import Federation
        fed = Federation(SAMPLE_FED_CONFIG)
        assert fed._normalize_ts("") == ""

    def test_normalize_ts_comparison(self):
        """验证标准化后的时间戳可字典序比较"""
        from backend.federation.core import Federation
        fed = Federation(SAMPLE_FED_CONFIG)

        earlier = fed._normalize_ts("2026-07-08T09:00:00Z")
        later = fed._normalize_ts("2026-07-08T10:00:00Z")
        assert earlier < later


class TestPeerRegion:
    """对端区域管理测试"""

    @pytest.mark.asyncio
    async def test_health_check_unreachable(self):
        from backend.federation.core import PeerRegion
        peer = PeerRegion({
            "region_id": "shanghai",
            "region_name": "上海",
            "api_url": "http://localhost:19999",  # 不存在的端口
            "api_token": "tok",
        })
        healthy = await peer.health_check()
        assert healthy is False
        assert peer.is_healthy is False

    def test_backoff_retry(self):
        from backend.federation.core import PeerRegion
        peer = PeerRegion(SAMPLE_FED_CONFIG["peers"][0])
        assert peer.retry_delay == 1.0

        peer.backoff_retry()
        assert peer.retry_delay == 2.0

        peer.backoff_retry()
        assert peer.retry_delay == 4.0

        # 上限 120s
        for _ in range(10):
            peer.backoff_retry()
        assert peer.retry_delay == 120.0

    def test_reset_retry(self):
        from backend.federation.core import PeerRegion
        peer = PeerRegion(SAMPLE_FED_CONFIG["peers"][0])
        peer.retry_delay = 64.0
        peer.reset_retry()
        assert peer.retry_delay == 1.0
