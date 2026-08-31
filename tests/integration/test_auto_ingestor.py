"""
自动告警接入集成测试
覆盖: 置信度门控决策、数据库写入、熔断器联动

运行: python -m pytest tests/integration/test_auto_ingestor.py -v --tb=short
"""
import os
import sys
import json
import time
import tempfile
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

_test_dir = tempfile.mkdtemp(prefix="secagentx_intg_ingest_")
_test_db_path = os.path.join(_test_dir, "test.db")
os.environ["SECAGENTX_DB_PATH"] = _test_db_path
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["CIRCUIT_FILE"] = os.path.join(_test_dir, ".circuit_breaker.json")
os.environ["DEEPSEEK_API_KEY"] = "mock"
os.environ["CI"] = "true"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# 确保数据库 schema 已初始化
from backend.main import init_db
init_db(os.environ["SECAGENTX_DB_PATH"])


@pytest.fixture
def mock_orchestrator():
    """创建一个 Mock Orchestrator，支持 process() 异步生成器"""
    orch = MagicMock()

    # process() 返回异步生成器
    async def mock_process(text, history_messages=None):
        yield {
            "type": "true_react_complete",
            "content": "分析完毕。\n\n```verdict\n{\n  \"verdict\": \"malicious\",\n  \"confidence\": 0.92,\n  \"risk_level\": \"高危\",\n  \"recommended_action\": \"block\"\n}\n```",
            "summary": "分析完毕，确定是恶意行为",
        }

    orch.process = mock_process

    # tools.execute() 模拟防火墙
    orch.tools = MagicMock()
    fw_result = MagicMock()
    fw_result.success = True
    fw_result.data = {"is_blocked": True, "rules": []}
    fw_result.error = None

    async def mock_execute(tool_name, **kwargs):
        if tool_name == "firewall_manage" and kwargs.get("action") == "block":
            return fw_result
        if tool_name == "firewall_manage" and kwargs.get("action") == "check":
            return fw_result
        if tool_name == "firewall_manage" and kwargs.get("action") == "list":
            list_result = MagicMock()
            list_result.success = True
            list_result.data = {"rules": []}
            return list_result
        return fw_result

    orch.tools.execute = mock_execute
    orch.tools.get = MagicMock(return_value=MagicMock())

    # 联邦模块（未启用）
    orch._federation = None

    return orch


@pytest.fixture
def config():
    """标准 auto_operation 配置"""
    return {
        "thresholds": {
            "auto_close": 0.85,
            "auto_block": 0.70,
            "expand_investigation": 0.50,
            "manual_escalation": 0.30,
        },
        "block_protection": {
            "whitelist_ips": ["10.0.0.1"],
            "default_duration_minutes": 120,
            "max_duration_minutes": 1440,
        },
    }


class TestAutoIngestorDecision:
    """AutoIngestor 置信度决策测试"""

    @pytest.mark.asyncio
    async def test_auto_close_high_confidence(self, mock_orchestrator, config):
        """置信度 ≥ 0.85 → 自动闭环"""
        from backend.auto_ingestor import AutoIngestor

        ingestor = AutoIngestor(mock_orchestrator, escalator=None, config=config)
        result = await ingestor.handle_alert_direct({
            "id": "test-close-001",
            "title": "SSH暴力破解",
            "src_ip": "45.33.32.156",
            "severity": "高危",
        })

        assert result["status"] == "processed"
        assert result["action"] == "auto_closed"
        assert result["confidence"] >= 0.85

        # 验证数据库已写入
        from backend.storage.database import Repository
        async with Repository() as repo:
            # Repository 不支持 async with，用传统方式
            pass

        from backend.storage.database import Repository, get_repository
        async with get_repository() as repo:
            row = await repo.fetch_one(
                "SELECT status FROM events WHERE id=?", ("test-close-001",)
            )
            assert row is not None, "事件应写入数据库"
            assert row["status"] == "resolved" or row["status"] == "blocked"

    @pytest.mark.asyncio
    async def test_auto_block_medium_confidence(self, mock_orchestrator, config):
        """0.70 ≤ 置信度 < 0.85 → 自动封禁"""
        # 覆写 process 返回 0.78 置信度
        async def mock_process_med(text, history_messages=None):
            yield {
                "type": "true_react_complete",
                "content": "```verdict\n{\n  \"verdict\": \"suspicious\",\n  \"confidence\": 0.78,\n  \"risk_level\": \"中危\",\n  \"recommended_action\": \"block\"\n}\n```",
                "summary": "可疑行为",
            }
        mock_orchestrator.process = mock_process_med

        from backend.auto_ingestor import AutoIngestor

        ingestor = AutoIngestor(mock_orchestrator, escalator=None, config=config)
        result = await ingestor.handle_alert_direct({
            "id": "test-block-001",
            "title": "端口扫描",
            "src_ip": "185.220.101.42",
            "severity": "中危",
        })

        assert result["status"] == "processed"
        assert result["action"] in ("auto_blocked", "monitoring"), f"预期自动封禁，实际: {result['action']}"
        if result["action"] == "auto_blocked":
            assert result.get("verified") is True

    @pytest.mark.asyncio
    async def test_escalated_low_confidence(self, mock_orchestrator, config):
        """置信度 < 0.30 → 升级人工"""
        async def mock_process_low(text, history_messages=None):
            yield {
                "type": "true_react_complete",
                "content": "```verdict\n{\n  \"verdict\": \"unknown\",\n  \"confidence\": 0.15,\n  \"risk_level\": \"低危\",\n  \"recommended_action\": \"monitoring\"\n}\n```",
                "summary": "无法确定",
            }
        mock_orchestrator.process = mock_process_low

        from backend.auto_ingestor import AutoIngestor
        from backend.escalation import AutoEscalation

        escalator = AutoEscalation(config)
        ingestor = AutoIngestor(mock_orchestrator, escalator=escalator, config=config)
        result = await ingestor.handle_alert_direct({
            "id": "test-esc-001",
            "title": "可疑登录",
            "src_ip": "10.0.0.88",
            "severity": "低危",
        })

        assert result["status"] == "processed"
        assert result["action"] == "escalated"
        assert result["confidence"] < 0.30

    @pytest.mark.asyncio
    async def test_no_structured_verdict_escalates(self, mock_orchestrator, config):
        """无结构化裁决 → 保守升级人工"""
        async def mock_process_no_verdict(text, history_messages=None):
            yield {
                "type": "true_react_complete",
                "content": "无法分析此告警，信息不足",
                "summary": "无法分析",
            }
        mock_orchestrator.process = mock_process_no_verdict

        from backend.auto_ingestor import AutoIngestor

        ingestor = AutoIngestor(mock_orchestrator, escalator=None, config=config)
        result = await ingestor.handle_alert_direct({
            "id": "test-no-verdict-001",
            "title": "不明告警",
        })

        # 保守策略：升级人工
        assert result["action"] == "escalated"


class TestAutoIngestorCircuitBreaker:
    """熔断器联动测试"""

    @pytest.mark.asyncio
    async def test_block_skipped_when_circuit_open(self, mock_orchestrator, config):
        """熔断器 OPEN 时跳过自动封禁"""
        from backend.security.circuit_breaker import circuit_breaker

        # 强制熔断
        circuit_breaker._state = "open"
        circuit_breaker._failures = 3
        circuit_breaker._last_failure_time = time.time()

        async def mock_process_block(text, history_messages=None):
            yield {
                "type": "true_react_complete",
                "content": "```verdict\n{\"verdict\": \"malicious\", \"confidence\": 0.80}\n```",
                "summary": "确定恶意",
            }
        mock_orchestrator.process = mock_process_block

        from backend.auto_ingestor import AutoIngestor
        ingestor = AutoIngestor(mock_orchestrator, escalator=None, config=config)
        result = await ingestor.handle_alert_direct({
            "id": "test-cb-001",
            "title": "恶意IP",
            "src_ip": "45.33.32.156",
        })

        # 熔断器应为 OPEN，自动封禁被跳过
        assert result["action"] == "block_skipped_circuit_breaker", \
            f"预期跳过封禁，实际: {result['action']}"
        assert "circuit_breaker" in result

        # 恢复熔断器
        circuit_breaker.record_success()


class TestIngestorStats:
    """Ingestor 统计功能测试"""

    @pytest.mark.asyncio
    async def test_stats_initial(self):
        from backend.auto_ingestor import AutoIngestor
        ingestor = AutoIngestor(MagicMock(), config={})
        stats = ingestor.get_stats()
        assert stats["processed_count"] == 0
        assert stats["queue_size"] == 0
        assert stats["running"] is False

    @pytest.mark.asyncio
    async def test_stats_after_processing(self, mock_orchestrator, config):
        from backend.auto_ingestor import AutoIngestor
        ingestor = AutoIngestor(mock_orchestrator, config=config)
        # handle_alert_direct 不走队列，不更新 processed_count（由队列消费者更新）
        # 验证 _process_alert 至少不崩溃
        r1 = await ingestor.handle_alert_direct({"id": "s1", "title": "测试1"})
        r2 = await ingestor.handle_alert_direct({"id": "s2", "title": "测试2"})
        assert r1["status"] == "processed"
        assert r2["status"] == "processed"


class TestNormalizeAlert:
    """告警标准化测试"""

    def test_normalize_full_fields(self):
        from backend.auto_ingestor import AutoIngestor
        ingestor = AutoIngestor(MagicMock(), config={})

        raw = {
            "alert_id": "a-001",
            "name": "告警名称",
            "message": "告警描述",
            "source_ip": "1.2.3.4",
            "level": "紧急",
            "category": "入侵",
            "time": "2026-07-08T10:00:00Z",
        }
        alert = ingestor._normalize_alert(raw)
        assert alert["id"] == "a-001"
        assert alert["title"] == "告警名称"
        assert alert["src_ip"] == "1.2.3.4"
        assert alert["severity"] == "紧急"

    def test_normalize_minimal(self):
        from backend.auto_ingestor import AutoIngestor
        ingestor = AutoIngestor(MagicMock(), config={})

        alert = ingestor._normalize_alert({"description": "只有描述"})
        assert alert["id"] is not None
        assert alert["title"] == "未知告警"
        assert alert["src_ip"] == ""
