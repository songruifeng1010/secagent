"""
RAG 结构化来源（v2.4 M2）单元测试

覆盖:
  - _build_structured_sources: mitre/cve/compliance/remediation/actor/malware 六类
  - fallback_answer: 复用主路径检索管线，产出结构化来源 + grounding
  - answer(): structured_sources 字段存在（有 LLM 主路径）
  - answer(): progress_cb 阶段事件
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, AsyncMock

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
    )
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TestStructuredSources:
    def test_build_structured_sources_mitre(self):
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        fused = {
        "mitre_techniques": [
        {"id": "T1190", "name": "Exploit Public-Facing Application",
        "description": "利用公网应用漏洞"},
        ],
        "cve_vulnerabilities": [],
        "compliance_regulations": [],
        "remediation_playbooks": [],
        "actor_profiles": [],
        "malware_profiles": [],
        }
        src = engine._build_structured_sources(fused)
        assert len(src) == 1
        assert src[0]["source_type"] == "mitre"
        assert src[0]["id"] == "T1190"
        assert src[0]["score"] == 1.0
        # v2.7: title 不再重复拼接 id（前端已单独显示 id），消除 "T1174T1174" 冗余
        assert src[0]["title"] == "Exploit Public-Facing Application"
        assert "T1190" not in src[0]["title"]

    def test_build_structured_sources_all_types(self):
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        fused = {
        "mitre_techniques": [{"id": "T1110", "name": "暴力破解"}],
        "cve_vulnerabilities": [{"id": "CVE-2024-3094", "severity": "CRITICAL",
        "description": "XZ供应链后门", "_cve_name": "XZ Utils供应链后门"}],
        "compliance_regulations": [{"abbr": "等保2.0", "name": "网络安全等级保护"}],
        "remediation_playbooks": [{"scenario": "SSH暴力破解"}],
        "actor_profiles": [{"id": "G0016", "name": "APT29", "country": "Russia"}],
        "malware_profiles": [{"id": "S0029", "name": "Zebrocy", "type": "trojan"}],
        }
        src = engine._build_structured_sources(fused)
        types = {s["source_type"] for s in src}
        assert types == {"mitre", "cve", "compliance", "remediation", "actor", "malware"}
        assert len(src) == 6

    def test_build_structured_sources_cve_title_uses_name(self):
        """v2.7: CVE 来源 title 用 _cve_name，不再用 'CRITICAL 长描述'"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        fused = {
        "mitre_techniques": [],
        "cve_vulnerabilities": [{"id": "CVE-2024-3094", "severity": "CRITICAL",
        "description": "XZ供应链后门：liblzma库被植入恶意代码",
        "_cve_name": "XZ Utils供应链后门"}],
        "compliance_regulations": [], "remediation_playbooks": [],
        "actor_profiles": [], "malware_profiles": [],
        }
        src = engine._build_structured_sources(fused)
        assert len(src) == 1
        assert src[0]["source_type"] == "cve"
        assert src[0]["id"] == "CVE-2024-3094"
        assert src[0]["title"] == "XZ Utils供应链后门"

    def test_build_structured_sources_empty(self):
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        src = engine._build_structured_sources({})
        assert src == []

    def test_sources_capped_at_20(self):
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(max_rounds=1)
        fused = {
        "mitre_techniques": [{"id": f"T11{i:02d}", "name": f"Tech{i}"} for i in range(25)],
        "cve_vulnerabilities": [], "compliance_regulations": [],
        "remediation_playbooks": [], "actor_profiles": [], "malware_profiles": [],
        }
        src = engine._build_structured_sources(fused)
        assert len(src) <= 20


class TestFallbackAnswer:
    @pytest.mark.asyncio
    async def test_fallback_answer_structured_sources(self):
        """无 LLM -> fallback 复用检索管线，产出结构化来源。"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(llm=None, max_rounds=2)
        result = await engine.answer("T1190 漏洞利用怎么防御？")
        assert "structured_sources" in result
        # T1190 是官方 MITRE 技术，应有来源
        mitre = [s for s in result["structured_sources"] if s["source_type"] == "mitre"]
        assert mitre
        assert mitre[0]["id"] == "T1190"
        assert "grounding_score" in result
        assert "has_grounding" in result

    @pytest.mark.asyncio
    async def test_fallback_answer_cve(self):
        """CVE 查询在 fallback 下也能命中 CISA KEV 记录。"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        engine = AgenticRAGEngine(llm=None, max_rounds=2)
        result = await engine.answer("CVE-2021-44228")
        cve = [s for s in result["structured_sources"] if s["source_type"] == "cve"]
        assert cve
        assert cve[0]["id"] == "CVE-2021-44228"


class TestAnswerWithLLM:
    @pytest.mark.asyncio
    async def test_answer_includes_structured_sources(self):
        """有 LLM 的主路径也输出 structured_sources + retrieval_log。"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        llm = MagicMock()
        engine = AgenticRAGEngine(llm=llm, max_rounds=2)
        result = await engine.answer("什么是T1110？")
        assert "structured_sources" in result
        assert "retrieval_log" in result
        assert isinstance(result["structured_sources"], list)

    @pytest.mark.asyncio
    async def test_answer_progress_cb_phases(self):
        """progress_cb 收到 analyze/retrieve/verify/fuse/grounding 阶段事件。"""
        from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
        llm = MagicMock()
        engine = AgenticRAGEngine(llm=llm, max_rounds=1)
        phases = []
        async def cb(ev):
            phases.append(ev["phase"])
            await engine.answer("T1110 是什么？", progress_cb=cb)
            assert "analyze" in phases
            assert "retrieve" in phases
            assert "verify" in phases
            assert "fuse" in phases
            assert "grounding" in phases
