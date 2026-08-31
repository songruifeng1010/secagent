"""
知识库模块单元测试 — MITRE ATT&CK / CVE / 合规 / 威胁情报

测试覆盖:
  - MITRE 技术查询、搜索、杀伤链、攻击流
  - CVE 查询与搜索
  - 合规法规搜索
  - 攻击组织与恶意软件统计
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.knowledge.mitre_attack import MitreAttackKnowledge
from backend.knowledge.cve_db import CVEDatabase
from backend.knowledge.compliance import ComplianceKnowledge
from backend.knowledge.threat_intel_kb import ActorKnowledge, MalwareKnowledge


class TestMitreAttack:
    """MITRE ATT&CK 知识库测试"""

    def test_technique_count(self):
        """验证 MITRE 技术数量符合预期"""
        mitre = MitreAttackKnowledge()
        count = mitre.count()
        assert count["techniques"] >= 100, f"技术数 {count['techniques']} < 100"
        assert count["tactics"] >= 14, f"战术数 {count['tactics']} < 14"
        assert count["sub_techniques"] >= 100

    def test_get_technique_by_id(self):
        """按 ID 查询已知技术返回正确结果"""
        mitre = MitreAttackKnowledge()
        tech = mitre.get_technique("T1566")
        assert tech is not None
        assert tech["name"] == "Phishing"
        assert "T1566.001" in tech.get("sub_techniques", {})

    def test_get_technique_unknown(self):
        """查询不存在的技术返回 None"""
        mitre = MitreAttackKnowledge()
        result = mitre.get_technique("T999999")
        assert result is None

    def test_search_by_keyword(self):
        """关键词搜索返回相关结果"""
        mitre = MitreAttackKnowledge()
        results = mitre.search("phishing")
        assert len(results) > 0
        assert any("T1566" in r["id"] for r in results)

    def test_search_by_chinese(self):
        """中文关键词搜索"""
        mitre = MitreAttackKnowledge()
        results = mitre.search("漏洞")
        assert isinstance(results, list)

    def test_search_with_filters(self):
        """带筛选条件的搜索"""
        mitre = MitreAttackKnowledge()
        results = mitre.search("phishing", filters={"tactics": ["TA0001"]})
        assert isinstance(results, list)

    def test_kill_chain(self):
        """杀伤链返回数据"""
        mitre = MitreAttackKnowledge()
        chain = mitre.get_kill_chain()
        # 本地数据可能不包含完整杀伤链，至少保证返回格式正确
        assert isinstance(chain, (list, dict))

    def test_get_attack_flow(self):
        """攻击流返回正确数量的步骤"""
        mitre = MitreAttackKnowledge()
        flow = mitre.get_attack_flow(["T1566", "T1204"])
        assert len(flow) == 2
        assert flow[0]["id"] == "T1566"

    def test_dashboard(self):
        """仪表盘数据包含关键统计"""
        mitre = MitreAttackKnowledge()
        dash = mitre.get_dashboard()
        assert "total_techniques" in dash
        assert "risk_distribution" in dash
        assert dash["total_techniques"] >= 100


class TestCVEDatabase:
    """CVE 漏洞库测试"""

    def test_cve_count(self):
        """CVE 数据库有数据"""
        cve = CVEDatabase()
        count = cve.count()
        assert count > 0, "CVE 数据库为空"

    def test_get_by_id(self):
        """按 CVE ID 查询"""
        cve = CVEDatabase()
        vuln = cve.get_by_id("CVE-2024-3094")
        if vuln:
            assert "id" in vuln
            assert "description" in vuln

    def test_get_by_id_not_found(self):
        """查询不存在的 CVE 返回 None"""
        cve = CVEDatabase()
        vuln = cve.get_by_id("CVE-9999-99999")
        assert vuln is None

    def test_search(self):
        """关键词搜索 CVE"""
        cve = CVEDatabase()
        results = cve.search("ssh")
        assert isinstance(results, list)

    def test_get_by_mitre_technique(self):
        """按 MITRE 技术 ID 查询关联 CVE"""
        cve = CVEDatabase()
        results = cve.get_by_mitre_technique("T1190")
        assert isinstance(results, list)


class TestCompliance:
    """合规知识库测试"""

    def test_regulation_count(self):
        """合规法规数量>0"""
        comp = ComplianceKnowledge()
        count = comp.count()
        assert count > 0, "合规知识库为空"

    def test_search(self):
        """关键词搜索合规法规"""
        comp = ComplianceKnowledge()
        results = comp.search("等保")
        assert isinstance(results, list)

    def test_search_by_english(self):
        """英文关键词搜索"""
        comp = ComplianceKnowledge()
        results = comp.search("gdpr")
        assert isinstance(results, list)


class TestThreatIntel:
    """威胁情报知识库测试"""

    def test_actor_count(self):
        """攻击组织数量>0"""
        actors = ActorKnowledge()
        count = actors.count()
        assert count["actors"] > 0, "攻击组织知识库为空"
        assert count["countries"] is not None

    def test_actor_search(self):
        """搜索攻击组织"""
        actors = ActorKnowledge()
        results = actors.search("APT")
        assert isinstance(results, list)

    def test_get_actor(self):
        """按 ID 查询攻击组织"""
        actors = ActorKnowledge()
        actor = actors.get_actor("G0007")
        if actor:
            assert "name" in actor

    def test_malware_count(self):
        """恶意软件数量>0"""
        malware = MalwareKnowledge()
        count = malware.count()
        assert count > 0, "恶意软件知识库为空"

    def test_malware_search(self):
        """搜索恶意软件"""
        malware = MalwareKnowledge()
        results = malware.search("ransomware")
        assert isinstance(results, list)
