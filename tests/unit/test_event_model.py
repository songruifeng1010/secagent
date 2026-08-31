"""
测试 SecurityEvent / Alert / IoCEntry 数据模型
"""
import pytest
from backend.models.event import SecurityEvent, Alert, IoCEntry


class TestSecurityEvent:
    def test_default_fields(self):
        e = SecurityEvent()
        assert e.event_id and len(e.event_id) == 12
        assert e.title == ""
        assert e.severity == "低危"
        assert e.status == "open"
        assert e.source_ip == ""
        assert e.resolved_at is None

    def test_to_dict(self):
        e = SecurityEvent(title="测试事件", severity="高危", source_ip="10.0.0.1")
        d = e.to_dict()
        assert d["title"] == "测试事件"
        assert d["severity"] == "高危"
        assert d["source_ip"] == "10.0.0.1"
        assert d["event_id"] == e.event_id
        assert "created_at" in d

    def test_is_high_risk_high(self):
        e = SecurityEvent(severity="高危")
        assert e.is_high_risk() is True

    def test_is_high_risk_emergency(self):
        e = SecurityEvent(severity="紧急")
        assert e.is_high_risk() is True

    def test_is_high_risk_low(self):
        e = SecurityEvent(severity="低危")
        assert e.is_high_risk() is False

    def test_is_high_risk_medium(self):
        e = SecurityEvent(severity="中危")
        assert e.is_high_risk() is False

    def test_full_constructor(self):
        e = SecurityEvent(
            title="SQL注入", severity="紧急", status="open",
            source_ip="1.2.3.4", alert_type="sql_injection",
            mitre_tactic_id="TA0001", mitre_technique_id="T1190",
            description="检测到SQL注入payload",
            resolution="已封禁", resolved_by="admin",
            raw_data={"payload": "1' OR 1=1"},
        )
        assert e.alert_type == "sql_injection"
        assert e.mitre_tactic_id == "TA0001"
        assert e.raw_data["payload"] == "1' OR 1=1"

    def test_resolved_at_default_none(self):
        e = SecurityEvent()
        assert e.resolved_at is None

    def test_unique_event_ids(self):
        ids = {SecurityEvent().event_id for _ in range(100)}
        assert len(ids) == 100


class TestAlert:
    def test_default_fields(self):
        a = Alert()
        assert a.alert_id and len(a.alert_id) == 12
        assert a.source_ip == "0.0.0.0"
        assert a.is_false_positive is False
        assert a.severity == "低危"

    def test_to_dict(self):
        a = Alert(title="端口扫描", severity="中危", source_ip="10.0.0.5")
        d = a.to_dict()
        assert d["title"] == "端口扫描"
        assert d["severity"] == "中危"

    def test_false_positive_flag(self):
        a = Alert(is_false_positive=True, filter_reason="白名单IP")
        assert a.is_false_positive is True
        assert a.filter_reason == "白名单IP"

    def test_custom_alert_type(self):
        a = Alert(alert_type="brute_force", severity="高危")
        assert a.alert_type == "brute_force"


class TestIoCEntry:
    def test_default_fields(self):
        ioc = IoCEntry()
        assert ioc.ioc_id and len(ioc.ioc_id) == 12
        assert ioc.confidence == 0.0
        assert ioc.tags == []

    def test_to_dict(self):
        ioc = IoCEntry(
            ioc_type="ip", ioc_value="45.33.32.156",
            threat_type="c2", confidence=0.95, source="vt",
            tags=["malicious", "c2"],
        )
        d = ioc.to_dict()
        assert d["ioc_type"] == "ip"
        assert d["ioc_value"] == "45.33.32.156"
        assert d["confidence"] == 0.95

    def test_empty_tags(self):
        ioc = IoCEntry(ioc_type="domain", ioc_value="evil.com")
        assert ioc.tags == []

    def test_all_ioc_types(self):
        for t in ("ip", "domain", "hash", "url"):
            ioc = IoCEntry(ioc_type=t, ioc_value=f"test_{t}")
            assert ioc.ioc_type == t
