"""
结构化输出模型测试 — backend/models/output.py

覆盖:
  - AgentResult 容错 coercion（英文/百分比/垃圾输入）
  - FinalResult 组装 + score 取 risk_score
  - repair_json_object 修复 LLM 格式漂移
  - result_to_text / final_to_markdown 确定性渲染
"""
import json
import pytest


class TestParseAgentResult:
    def test_coerce_english_and_percent(self):
        from backend.models.output import parse_agent_result
        raw = {
            "verdict": "MALICIOUS",
            "confidence": "85%",
            "risk_level": "high",
            "recommended_action": "ban",
            "summary_text": "检测到暴力破解",
        }
        r = parse_agent_result(raw)
        assert r["verdict"] == "malicious"
        assert r["confidence"] == 0.85
        assert r["risk_level"] == "高危"
        assert r["recommended_action"] == "block"

    def test_partial_fields_defaults(self):
        from backend.models.output import parse_agent_result
        r = parse_agent_result({"verdict": "suspicious"})
        assert r["verdict"] == "suspicious"
        assert r["confidence"] == 0.5  # 默认值
        assert r["risk_level"] == "中危"
        assert r["technique_ids"] == []

    def test_garbage_verdict_falls_back_unknown(self):
        from backend.models.output import parse_agent_result
        r = parse_agent_result({"verdict": "random_garbage"})
        assert r["verdict"] == "unknown"

    def test_non_dict_input(self):
        from backend.models.output import parse_agent_result
        r = parse_agent_result(None)
        assert r["verdict"] == "unknown"
        r2 = parse_agent_result("not a dict")
        assert r2["verdict"] == "unknown"

    def test_confidence_clamped(self):
        from backend.models.output import parse_agent_result
        assert parse_agent_result({"confidence": 1.7})["confidence"] == 1.0
        assert parse_agent_result({"confidence": -0.3})["confidence"] == 0.0
        assert parse_agent_result({"confidence": "65%"})["confidence"] == 0.65

    def test_json_safe_serializable(self):
        from backend.models.output import parse_agent_result
        r = parse_agent_result({"verdict": "malicious", "confidence": 0.8})
        json.dumps(r)  # 不抛异常


class TestFinalResult:
    def test_score_from_risk_scorecard(self):
        from backend.models.output import build_final_result
        fr = build_final_result(
            status="completed",
            conversation_id="abc",
            risk_scorecard={"risk_score": 85, "risk_level": "高危"},
            confidence_aggregate={"confidence": 0.8, "verdict": "malicious"},
            agent_results=[],
        )
        assert fr.score == 85

    def test_verdict_from_deterministic_agg(self):
        from backend.models.output import build_final_result, FinalVerdict
        fr = build_final_result(
            status="completed",
            verdict=FinalVerdict(verdict="malicious", confidence=0.8,
                                 risk_level="高危", recommended_action="block"),
            risk_scorecard={"risk_score": 85, "risk_level": "高危"},
            agent_results=[],
        )
        assert fr.verdict.verdict == "malicious"
        assert fr.verdict.recommended_action == "block"

    def test_agent_results_coerced(self):
        from backend.models.output import build_final_result
        fr = build_final_result(
            agent_results=[
                {"agent_id": "analyst-001", "verdict": "malicious", "confidence": 0.85},
                "garbage",
                None,
            ],
            risk_scorecard={"risk_score": 10, "risk_level": "低危"},
        )
        assert len(fr.agent_results) == 3
        assert fr.agent_results[0].verdict == "malicious"
        assert fr.agent_results[1].verdict == "unknown"  # 兜底默认

    def test_json_dump_safe(self):
        from backend.models.output import build_final_result
        fr = build_final_result(
            agent_results=[{"agent_id": "a", "verdict": "suspicious", "confidence": 0.5}],
            risk_scorecard={"risk_score": 30, "risk_level": "中危"},
        )
        d = fr.model_dump(mode="json")
        json.dumps(d)
        assert d["agent_results"][0]["verdict"] == "suspicious"


class TestRepairJson:
    def test_fence_stripping(self):
        from backend.models.output import repair_json_object
        text = "```json\n{\"verdict\": \"malicious\"}\n```"
        r = repair_json_object(text)
        assert r == {"verdict": "malicious"}

    def test_surrounding_text(self):
        from backend.models.output import repair_json_object
        text = "分析结果如下：\n{\"confidence\": 0.8}\n以上。"
        r = repair_json_object(text)
        assert r["confidence"] == 0.8

    def test_trailing_comma(self):
        from backend.models.output import repair_json_object
        text = '{"verdict": "malicious", "key_evidence": ["a", "b",]}'
        r = repair_json_object(text)
        assert r["verdict"] == "malicious"
        assert r["key_evidence"] == ["a", "b"]

    def test_single_quotes(self):
        from backend.models.output import repair_json_object
        text = "{'verdict': 'benign'}"
        r = repair_json_object(text)
        assert r["verdict"] == "benign"

    def test_invalid_returns_none(self):
        from backend.models.output import repair_json_object
        assert repair_json_object("完全不是 JSON") is None
        assert repair_json_object("") is None
        assert repair_json_object(None) is None


class TestRenderers:
    def test_result_to_text(self):
        from backend.models.output import result_to_text
        text = result_to_text({
            "verdict": "malicious",
            "confidence": 0.85,
            "risk_level": "高危",
            "key_evidence": ["SSH暴力破解"],
            "summary_text": "检测到暴力破解",
        })
        assert "检测到暴力破解" in text
        assert "malicious" in text

    def test_final_to_markdown(self):
        from backend.models.output import build_final_result, final_to_markdown
        fr = build_final_result(
            status="completed",
            summary_text="总结",
            verdict={"verdict": "malicious", "confidence": 0.8,
                     "risk_level": "高危", "recommended_action": "block"},
            confidence_aggregate={"confidence": 0.8, "verdict": "malicious", "details": []},
            risk_scorecard={"risk_score": 85, "risk_level": "高危", "dimensions": []},
            agent_results=[],
        )
        md = final_to_markdown(fr)
        assert "85" in md
        assert "总结" in md
        assert "综合" in md
