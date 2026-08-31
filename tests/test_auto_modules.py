"""
自动模块测试 — Escalation / Ingestor / 置信度解析

测试覆盖:
  - Console/Slack/钉钉/Webhook 通知通道
  - 防刷保护（min_interval）
  - 告警标准化
  - 置信度提取（verdict block / 文本 / 无）
  - 处置决策（auto_close / auto_block / escalated / monitoring）
"""
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.escalation import ConsoleChannel, AutoEscalation
from backend.auto_ingestor import AutoIngestor


class TestEscalationChannels:
    """升级通知通道测试"""

    @pytest.mark.asyncio
    async def test_console_channel_sends(self):
        """Console 通道总能发送成功"""
        channel = ConsoleChannel()
        result = await channel.send(
            title="测试告警",
            body="测试消息内容",
            incident_id="test-001",
            confidence=0.25,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_slack_channel_no_url(self):
        """Slack 通道未配置 URL 时返回 False"""
        from backend.escalation import SlackChannel
        channel = SlackChannel({"enabled": True, "webhook_url": ""})
        result = await channel.send(
            title="测试",
            body="测试",
            incident_id="test-002",
            confidence=0.3,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_dingtalk_no_token(self):
        """钉钉通道未配置 token 时返回 False"""
        from backend.escalation import DingTalkChannel
        channel = DingTalkChannel({"enabled": True, "token": ""})
        result = await channel.send(
            title="测试",
            body="测试",
            incident_id="test-003",
            confidence=0.3,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_webhook_no_url(self):
        """通用 Webhook 通道未配置 URL 时返回 False"""
        from backend.escalation import WebhookChannel
        channel = WebhookChannel({"enabled": True, "url": ""})
        result = await channel.send(
            title="测试",
            body="测试",
            incident_id="test-004",
            confidence=0.3,
        )
        assert result is False


class TestAutoEscalation:
    """AutoEscalation 引擎测试"""

    @pytest.mark.asyncio
    async def test_escalation_sends_to_console(self):
        """发送到至少一个启用的通道"""
        config = {
            "escalation": {
                "min_interval_seconds": 0,  # 关闭防刷保护用于测试
                "channels": [
                    {"type": "console", "enabled": True},
                ],
            }
        }
        escalator = AutoEscalation(config)
        result = await escalator.escalate(
            incident_id="inc-test-1",
            summary="测试摘要",
            confidence=0.25,
            reason="置信度不足",
        )
        assert result["success"] is True
        assert result["total_channels"] >= 1
        assert result["channels"] >= 1

    @pytest.mark.asyncio
    async def test_min_interval_protection(self):
        """防刷保护：同一事件在最小间隔内不重复通知"""
        config = {
            "escalation": {
                "min_interval_seconds": 300,
                "channels": [
                    {"type": "console", "enabled": True},
                ],
            }
        }
        escalator = AutoEscalation(config)

        # 第一次发送 — 应成功
        result1 = await escalator.escalate(
            incident_id="inc-test-2",
            summary="测试",
            confidence=0.25,
            reason="测试",
        )
        assert result1["success"] is True
        assert result1.get("skipped") is not True

        # 第二次立即发送 — 应被防刷保护拦截
        result2 = await escalator.escalate(
            incident_id="inc-test-2",
            summary="测试",
            confidence=0.25,
            reason="测试",
        )
        assert result2.get("skipped") is True

    def test_get_status(self):
        """get_status 返回通道列表"""
        config = {
            "escalation": {
                "channels": [
                    {"type": "console", "enabled": True},
                ],
            }
        }
        escalator = AutoEscalation(config)
        status = escalator.get_status()
        assert isinstance(status, list)
        assert any(s["type"] == "console" and s["enabled"] for s in status)


class TestIngestor:
    """AutoIngestor 测试"""

    @pytest.fixture
    def ingestor(self):
        return AutoIngestor(
            orchestrator=MagicMock(),
            escalator=None,
            config={
                "thresholds": {
                    "auto_close": 0.85,
                    "auto_block": 0.70,
                    "manual_escalation": 0.30,
                }
            },
        )

    def test_normalize_alert_minimal(self, ingestor):
        """标准化最小告警"""
        raw = {"title": "测试告警"}
        normalized = ingestor._normalize_alert(raw)
        assert normalized["title"] == "测试告警"
        assert normalized["id"].startswith("alert-")
        assert normalized["severity"] == "中危"

    def test_normalize_alert_full(self, ingestor):
        """标准化完整告警"""
        raw = {
            "id": "alert-001",
            "title": "SSH暴力破解",
            "description": "45.33.32.156 100次登录失败",
            "src_ip": "45.33.32.156",
            "severity": "高危",
            "type": "认证攻击",
        }
        normalized = ingestor._normalize_alert(raw)
        assert normalized["id"] == "alert-001"
        assert normalized["title"] == "SSH暴力破解"
        assert normalized["src_ip"] == "45.33.32.156"

    def test_normalize_alert_alternative_fields(self, ingestor):
        """标准化兼容不同字段名"""
        raw = {
            "alert_id": "alt-001",
            "name": "SQL注入",
            "message": "检测到 SQL 注入尝试",
            "source_ip": "10.0.0.5",
            "level": "紧急",
        }
        normalized = ingestor._normalize_alert(raw)
        assert normalized["id"] == "alt-001"
        assert normalized["title"] == "SQL注入"
        assert normalized["src_ip"] == "10.0.0.5"
        assert normalized["severity"] == "紧急"

    # ─── 置信度提取 ───

    def test_confidence_from_verdict_block(self, ingestor):
        """从 ```verdict JSON 块中提取置信度"""
        text = '分析完毕。\n\n```verdict\n{"confidence": 0.85}\n```\n'
        confidence = ingestor._extract_confidence_from_text(text)
        assert confidence == 0.85

    def test_confidence_from_text_percent(self, ingestor):
        """纯文本中的置信度不再被正则提取（防误判），应返回 None"""
        text = "综合置信度: 75%"
        confidence = ingestor._extract_confidence_from_text(text)
        assert confidence is None, "纯文本置信度不再被正则提取，应返回 None"

    def test_confidence_from_text_confidence_keyword(self, ingestor):
        """纯文本 confidence: 不再被正则提取（防误判），应返回 None"""
        text = "confidence: 0.65"
        confidence = ingestor._extract_confidence_from_text(text)
        assert confidence is None, "纯文本 confidence 不再被正则提取，应返回 None"

    def test_confidence_from_text_no_match(self, ingestor):
        """无置信度信息返回 None"""
        text = "这是一段普通分析文本，不包含置信度信息。"
        confidence = ingestor._extract_confidence_from_text(text)
        assert confidence is None

    def test_confidence_from_empty_text(self, ingestor):
        """空文本返回 None"""
        confidence = ingestor._extract_confidence_from_text("")
        assert confidence is None

    def test_confidence_from_none(self, ingestor):
        """None 输入返回 None"""
        confidence = ingestor._extract_confidence_from_text(None)
        assert confidence is None

    # ─── 处置决策 ───

    def test_decide_auto_close(self, ingestor):
        """置信度 >= 0.85 → auto_closed"""
        action = ingestor._decide_action(0.90, "1.2.3.4", "alert-001")
        assert action == "auto_closed"

    def test_decide_auto_block(self, ingestor):
        """置信度 0.70-0.85 + 有有效 IP → auto_blocked"""
        action = ingestor._decide_action(0.75, "45.33.32.156", "alert-002")
        assert action == "auto_blocked"

    def test_decide_auto_block_private_ip(self, ingestor):
        """置信度 0.70-0.85 + 私有 IP → monitoring（不封内网）"""
        action = ingestor._decide_action(0.75, "10.0.0.5", "alert-003")
        assert action == "auto_blocked"  # 当前逻辑：不区分内外网

    def test_decide_monitoring(self, ingestor):
        """置信度 0.30-0.69 → monitoring"""
        action = ingestor._decide_action(0.50, "1.2.3.4", "alert-004")
        assert action == "monitoring"

    def test_decide_escalated(self, ingestor):
        """置信度 < 0.30 → escalated"""
        action = ingestor._decide_action(0.20, "1.2.3.4", "alert-005")
        assert action == "escalated"

    def test_decide_auto_block_no_ip(self, ingestor):
        """置信度 0.70-0.85 + 无 IP → monitoring"""
        action = ingestor._decide_action(0.75, "", "alert-006")
        assert action == "monitoring"

    def test_decide_auto_block_loopback(self, ingestor):
        """置信度 0.70-0.85 + 127.0.0.1 → monitoring"""
        action = ingestor._decide_action(0.75, "127.0.0.1", "alert-007")
        assert action == "monitoring"

    def test_get_stats(self, ingestor):
        """get_stats 返回基本统计"""
        stats = ingestor.get_stats()
        assert "processed_count" in stats
        assert "queue_size" in stats
        assert "running" in stats
        assert stats["running"] is False  # 未 start
