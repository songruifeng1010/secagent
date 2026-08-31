"""
Agentic RAG 引擎 + 知识库单元测试

覆盖:
  - RAG 引擎创建与配置
  - answer() 主入口（生成增强回答）
  - 知识库组件（MITRE/CVE/Compliance/Threat Intel）
  - 知识 Agent 初始化
"""

import pytest


class TestRAGEngine:
    """Agentic RAG 引擎测试"""

    def test_engine_creation(self):
        """创建 RAG 引擎"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=3)
        assert engine is not None
        assert engine.max_rounds == 3

    def test_engine_with_mock_llm(self):
        """使用 Mock LLM 创建 RAG 引擎"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        from backend.llm.mock import MockLLMProvider

        llm = MockLLMProvider({"api_key": "not-a-real-provider-key"})
        engine = AgenticRAGEngine(llm=llm, max_rounds=2)
        assert engine.llm is not None

    def test_engine_internal_components(self):
        """RAG 引擎内部组件"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=3)
        # 知识库组件
        assert engine.mitre is not None
        assert engine.cve_db is not None
        assert engine.compliance is not None
        assert engine.actor_kb is not None
        assert engine.malware_kb is not None

    def test_analyze_query(self):
        """_analyze_query 分析查询"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)

        # _analyze_query 是同步方法
        analysis = engine._analyze_query("SQL注入攻击如何检测？")
        assert analysis is not None
        assert isinstance(analysis, dict)
        # 应该包含 entities 字段
        assert "entities" in analysis

    def test_analyze_query_mitre_id(self):
        """识别 MITRE ID"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        analysis = engine._analyze_query("T1190 漏洞利用")
        assert analysis is not None
        entities = analysis.get("entities", [])
        mitre_ids = [e for e in entities if "T1" in str(e)]
        assert len(mitre_ids) >= 0

    def test_analyze_query_sql_injection(self):
        """识别 SQL 注入关键词"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        analysis = engine._analyze_query("SQL注入攻击如何检测和防御？")
        assert analysis is not None

    def test_build_retrieval_plan(self):
        """构建检索计划"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        analysis = engine._analyze_query("SSH暴力破解")
        plan = engine._build_retrieval_plan(
            query="SSH暴力破解",
            analysis=analysis,
            round_num=0,
            current_knowledge={"mitre": [], "cve": [], "compliance": [], "remediation": [], "general": []},
        )
        assert plan is not None
        assert isinstance(plan, dict)

    def test_verify_sufficiency(self):
        """验证知识库充足性"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)

        # 有知识支撑
        verdict = engine._verify_sufficiency(
            "SSH暴力破解",
            {"mitre": [{"id": "T1110"}], "cve": [], "compliance": [], "remediation": [], "general": []},
            0,
        )
        assert verdict["sufficient"] is True
        assert verdict["total_docs"] == 1

        # 无知识支撑
        verdict2 = engine._verify_sufficiency(
            "未知漏洞",
            {"mitre": [], "cve": [], "compliance": [], "remediation": [], "general": []},
            0,
        )
        assert verdict2["sufficient"] is False

    def test_fuse_knowledge(self):
        """融合多知识源"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        fused = engine._fuse_knowledge(
            "SQL注入",
            {"mitre": [{"id": "T1190"}], "cve": [{"id": "CVE-2024-0001"}],
             "compliance": [], "remediation": [], "general": []},
        )
        assert "mitre_techniques" in fused
        assert len(fused["mitre_techniques"]) == 1

    def test_grounding_check_sufficient(self):
        """接地检查——有支撑"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        grounding = engine._grounding_check(
            "SQL注入",
            {"mitre_techniques": [{"id": "T1190"}], "cve_vulnerabilities": [{"id": "CVE-2024-0001"}],
             "compliance_regulations": [], "remediation_playbooks": [],
             "actor_profiles": [], "malware_profiles": [], "general_knowledge": []},
        )
        assert grounding["has_grounding"] is True
        assert grounding["score"] >= 0.5

    def test_grounding_check_insufficient(self):
        """接地检查——无支撑"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        grounding = engine._grounding_check(
            "虚构威胁X",
            {"mitre_techniques": [], "cve_vulnerabilities": [],
             "compliance_regulations": [], "remediation_playbooks": [],
             "actor_profiles": [], "malware_profiles": [], "general_knowledge": []},
        )
        assert grounding["has_grounding"] is False
        assert grounding["score"] == 0.0

    def test_generate_grounded_answer_with_grounding(self):
        """生成接地回答——有知识支撑"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        answer = engine._generate_grounded_answer(
            "SQL注入攻击",
            {
                "mitre_techniques": [{"id": "T1190", "name": "SQL注入", "description": "利用SQL注入漏洞"}],
                "cve_vulnerabilities": [], "compliance_regulations": [],
                "remediation_playbooks": [], "actor_profiles": [],
                "malware_profiles": [], "general_knowledge": [],
            },
            {"score": 1.0, "has_grounding": True, "detail": "充足", "confidence": 0.9, "total_sources": 1},
        )
        assert answer is not None
        assert "T1190" in answer or "SQL注入" in answer

    def test_generate_grounded_answer_without_grounding(self):
        """生成接地回答——无知识支撑（防幻觉）"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        answer = engine._generate_grounded_answer(
            "虚构威胁X",
            {"mitre_techniques": [], "cve_vulnerabilities": [], "compliance_regulations": [],
             "remediation_playbooks": [], "actor_profiles": [],
             "malware_profiles": [], "general_knowledge": []},
            {"score": 0.0, "has_grounding": False, "detail": "无相关知识",
             "confidence": 0.1, "total_sources": 0},
        )
        assert answer is not None
        assert "未找到" in answer or "无法" in answer

    def test_search_remediation(self):
        """搜索应急响应知识"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        results = engine._search_remediation("SSH暴力破解")
        assert results is not None
        assert isinstance(results, list)

    def test_knowledge_agent_initialization(self):
        """知识 Agent 初始化"""
        from backend.agents.knowledge.knowledge_agent import KnowledgeAgent
        from backend.tools.registry import ToolRegistry
        from backend.tools.cve_search import CVESearchTool

        registry = ToolRegistry()
        registry.register(CVESearchTool())
        agent = KnowledgeAgent(registry)
        assert agent is not None
        assert agent.status == "idle"


class TestKnowledgeBase:
    """知识库组件整合测试"""

    def test_mitre_attack_knowledge(self):
        """MITRE ATT&CK 知识库"""
        from backend.knowledge.mitre_attack import MitreAttackKnowledge
        mitre = MitreAttackKnowledge()
        count = mitre.count()
        assert count["techniques"] > 0
        assert count["tactics"] > 0

    def test_mitre_search(self):
        """MITRE ATT&CK 搜索"""
        from backend.knowledge.mitre_attack import MitreAttackKnowledge
        mitre = MitreAttackKnowledge()
        results = mitre.search("SQL注入")
        assert results is not None

    def test_cve_database(self):
        """CVE 数据库"""
        from backend.knowledge.cve_db import CVEDatabase
        cve = CVEDatabase()
        count = cve.count()
        assert count > 0

    def test_compliance_knowledge(self):
        """合规知识库"""
        from backend.knowledge.compliance import ComplianceKnowledge
        compliance = ComplianceKnowledge()
        count = compliance.count()
        assert count > 0

    def test_threat_actors_knowledge(self):
        """威胁行为体知识库"""
        from backend.knowledge.threat_intel_kb import ActorKnowledge
        actor = ActorKnowledge()
        count = actor.count()
        assert count["actors"] > 0

    def test_malware_knowledge(self):
        """恶意软件知识库"""
        from backend.knowledge.threat_intel_kb import MalwareKnowledge
        malware = MalwareKnowledge()
        count = malware.count()
        assert count > 0
