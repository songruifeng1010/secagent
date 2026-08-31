"""
测试工具结果信任检查器 — TrustChecker
"""
import pytest
from backend.tools.trust_checker import TrustChecker


class TestCheckThreatIntel:
    def test_trustworthy_no_errors_full_sources(self):
        result = {"errors": [], "total_sources": 3}
        check = TrustChecker.check_threat_intel(result)
        assert check["trustworthy"] is True
        assert check["warnings"] == []
        assert check["score"] == 1.0

    def test_errors_present(self):
        result = {"errors": ["VirusTotal 超时"], "total_sources": 3}
        check = TrustChecker.check_threat_intel(result)
        assert check["trustworthy"] is False
        assert len(check["warnings"]) == 1
        assert "VirusTotal" in check["warnings"][0]

    def test_insufficient_sources(self):
        result = {"errors": [], "total_sources": 2}
        check = TrustChecker.check_threat_intel(result)
        assert check["trustworthy"] is False
        assert any("仅 2/3" in w for w in check["warnings"])

    def test_score_calculation_no_warnings(self):
        result = {"errors": [], "total_sources": 3}
        check = TrustChecker.check_threat_intel(result)
        assert check["score"] == 1.0

    def test_score_calculation_with_warnings(self):
        result = {"errors": ["源A失败", "源B失败"], "total_sources": 1}
        check = TrustChecker.check_threat_intel(result)
        assert check["trustworthy"] is False
        assert check["score"] < 1.0

    def test_empty_result(self):
        result = {"errors": [], "total_sources": 0}
        check = TrustChecker.check_threat_intel(result)
        assert check["trustworthy"] is False

    def test_missing_fields(self):
        result = {}
        check = TrustChecker.check_threat_intel(result)
        # missing fields should not crash
        assert "trustworthy" in check


class TestCheckFirewall:
    def test_block_valid_duration(self):
        result = {"action": "blocked", "duration_minutes": 120}
        check = TrustChecker.check_firewall(result)
        assert check["trustworthy"] is True

    def test_block_zero_duration(self):
        result = {"action": "blocked", "duration_minutes": 0}
        check = TrustChecker.check_firewall(result)
        assert check["trustworthy"] is False
        assert any("0 分钟" in w for w in check["warnings"])

    def test_list_normal(self):
        result = {"action": "list", "total": 10}
        check = TrustChecker.check_firewall(result)
        assert check["trustworthy"] is True

    def test_list_negative_total(self):
        result = {"action": "list", "total": -1}
        check = TrustChecker.check_firewall(result)
        assert check["trustworthy"] is False

    def test_unknown_action(self):
        result = {"action": "unknown"}
        check = TrustChecker.check_firewall(result)
        assert check["trustworthy"] is True

    def test_missing_fields(self):
        result = {}
        check = TrustChecker.check_firewall(result)
        assert check["trustworthy"] is True


class TestCheckAll:
    def test_route_to_threat_intel(self):
        result = {"errors": [], "total_sources": 3}
        check = TrustChecker.check_all("intel-001", result)
        assert check["trustworthy"] is True

    def test_route_to_firewall(self):
        result = {"action": "blocked", "duration_minutes": 120}
        check = TrustChecker.check_all("responder-001", result)
        assert check["trustworthy"] is True

    def test_route_to_unknown_agent(self):
        result = {"some": "data"}
        check = TrustChecker.check_all("unknown-agent", result)
        assert check["trustworthy"] is True
        assert check["warnings"] == []
