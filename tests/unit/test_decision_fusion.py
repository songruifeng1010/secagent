"""
Decision Fusion 决策融合测试 — backend/decision_fusion/

覆盖:
  - DS 引擎：一致恶意收敛 / 冲突检测 / unknown 主导 / 全失败兜底
  - 可替换引擎：factory 注册与切换、weighted_average 引擎
  - 证据包构造：build_evidence_package 容错
  - FusionResult 结构完整性（decision_path / evidence_masses / conflicts）
"""
import pytest

from backend.decision_fusion import (
    FusionEngineFactory, EvidencePackage, Finding,
    build_evidence_package, build_fusion_result,
)


def _pkg(agent_id, name, lean, conf, findings=None, coverage=None, degraded=False):
    return EvidencePackage(
        agent_id=agent_id, agent_name=name, leaning=lean,
        leaning_confidence=conf, evidence_confidence=conf,
        findings=findings or [], coverage=coverage, degraded=degraded,
    )


class TestEvidencePackage:
    def test_build_from_agent_result_dict(self):
        ep = build_evidence_package({
            "agent_id": "analyst-001",
            "findings": [{"type": "malicious_behavior", "fact": "SSH暴力破解",
                          "evidence_confidence": 0.9}],
            "leaning": "malicious", "leaning_confidence": 0.85,
            "coverage": 0.8, "missing_sources": ["VT"],
        })
        assert ep is not None
        assert ep.agent_id == "analyst-001"
        assert ep.leaning.value == "malicious"
        assert ep.findings[0].fact == "SSH暴力破解"
        assert ep.coverage == 0.8

    def test_build_from_garbage(self):
        assert build_evidence_package(None) is None
        assert build_evidence_package("not dict") is None


class TestDempsterShafer:
    def setup_method(self):
        self.eng = FusionEngineFactory.get_engine("dempster_shafer")

    def test_consistent_malicious_converges(self):
        """一致恶意 → 高恶意信念"""
        pkgs = [
            _pkg("analyst-001", "分析师", "malicious", 0.9,
                 [Finding(type="malicious_behavior", fact="暴力破解", evidence_confidence=0.9)]),
            _pkg("intel-001", "情报员", "malicious", 0.8, coverage=1.0),
        ]
        r = self.eng.fuse(pkgs)
        assert r.verdict.verdict.value == "malicious"
        assert r.verdict.confidence > 0.9
        assert r.verdict.needs_human is False

    def test_conflict_detected(self):
        """恶意 vs 良性 → 冲突系数升高 + needs_human"""
        pkgs = [
            _pkg("analyst-001", "分析师", "malicious", 0.9),
            _pkg("intel-001", "情报员", "benign", 0.9, coverage=1.0),
        ]
        r = self.eng.fuse(pkgs)
        assert len(r.conflicts) >= 1
        assert r.conflict_coefficient > 0.5
        assert r.verdict.needs_human is True

    def test_unknown_dominant(self):
        """全部 unknown（情报缺失）→ unknown + needs_human"""
        pkgs = [
            _pkg("analyst-001", "分析师", "unknown", 0.5),
            _pkg("intel-001", "情报员", "unknown", 0.5, coverage=0.2),
        ]
        r = self.eng.fuse(pkgs)
        assert r.verdict.verdict.value == "unknown"
        assert r.verdict.needs_human is True
        assert r.verdict.confidence <= 0.3  # 强制低置信度

    def test_all_failed(self):
        """全部失败 → 未知 + 需人工"""
        r = self.eng.fuse([
            EvidencePackage(agent_id="analyst-001", failed=True),
            EvidencePackage(agent_id="intel-001", failed=True),
        ])
        assert r.verdict.verdict.value == "unknown"
        assert r.verdict.needs_human is True

    def test_empty_packages(self):
        r = self.eng.fuse([])
        assert r.verdict.verdict.value == "unknown"
        assert r.verdict.needs_human is True

    def test_decision_path_present(self):
        pkgs = [_pkg("analyst-001", "分析师", "malicious", 0.9)]
        r = self.eng.fuse(pkgs)
        assert len(r.decision_path) >= 2
        assert r.decision_path[-1]["tag"] == "decision"

    def test_evidence_masses_auditable(self):
        pkgs = [
            _pkg("analyst-001", "分析师", "malicious", 0.9),
            _pkg("intel-001", "情报员", "malicious", 0.8, coverage=1.0),
        ]
        r = self.eng.fuse(pkgs)
        assert len(r.evidence_masses) == 2
        weights = [m.weight for m in r.evidence_masses]
        assert sum(weights) == pytest.approx(1.0, abs=0.05)  # 归一化

    def test_degraded_halves_weight(self):
        pkgs = [
            _pkg("analyst-001", "分析师", "malicious", 0.9),
            _pkg("intel-001", "情报员", "malicious", 0.8, coverage=1.0, degraded=True),
        ]
        r = self.eng.fuse(pkgs)
        w_analyst = next(m.weight for m in r.evidence_masses if m.agent_id == "analyst-001")
        w_intel = next(m.weight for m in r.evidence_masses if m.agent_id == "intel-001")
        assert w_analyst > w_intel  # 降级情报权重更低

    def test_json_serializable(self):
        import json
        pkgs = [_pkg("analyst-001", "分析师", "malicious", 0.9)]
        d = self.eng.fuse(pkgs).model_dump(mode="json")
        json.dumps(d)


class TestFusionEngineFactory:
    def test_available_engines(self):
        assert "dempster_shafer" in FusionEngineFactory.available()
        assert "weighted_average" in FusionEngineFactory.available()

    def test_get_unknown_engine_raises(self):
        with pytest.raises(ValueError):
            FusionEngineFactory.get_engine("nonexistent_engine")

    def test_weighted_average_engine(self):
        eng = FusionEngineFactory.get_engine("weighted_average")
        pkgs = [
            _pkg("analyst-001", "分析师", "malicious", 0.9),
            _pkg("intel-001", "情报员", "malicious", 0.8, coverage=1.0),
        ]
        r = eng.fuse(pkgs)
        assert r.verdict.verdict.value == "malicious"
        assert r.engine == "weighted_average"

    def test_custom_engine_registration(self):
        from backend.decision_fusion.base import DecisionFusionEngine

        class MyEngine(DecisionFusionEngine):
            name = "my_test_engine"

            def fuse(self, evidence_packages):
                return build_fusion_result(
                    engine=self.name, method=self.name, status="completed",
                    verdict={"verdict": "unknown", "confidence": 0.5},
                    risk_score=0, agent_count=0, evidence_count=0,
                )

        FusionEngineFactory.register("my_test_engine", MyEngine)
        eng = FusionEngineFactory.get_engine("my_test_engine")
        r = eng.fuse([])
        assert r.engine == "my_test_engine"


class TestFusionResultSchema:
    def test_build_fusion_result(self):
        r = build_fusion_result(
            engine="dempster_shafer", method="dempster_shafer",
            status="completed",
            verdict={"verdict": "malicious", "confidence": 0.9},
            conflicts=[{"between": "a vs b", "coefficient": 0.5}],
            decision_path=[{"step": 1, "desc": "x", "tag": "evidence"}],
        )
        assert r.verdict.verdict.value == "malicious"
        assert r.conflicts[0].coefficient == 0.5
        assert len(r.decision_path) == 1
