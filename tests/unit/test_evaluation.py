"""
评估测试:
 - _extract_confidence / _extract_verdict 解析
 - AgentMetrics: per_agent_metrics / tool_metrics / route_correction / decision_consistency
 - AgentEvaluator: 评分卡维度 / 总分 / 等级 / issues
 - 空数据兜底
"""
import os
import sys
import json
import pytest

os.environ["KNOWLEDGE_BASE_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_data",
)
os.environ["CI"] = "true"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.evaluation.metrics import (
    AgentMetrics, _extract_confidence, _extract_verdict,
)
from backend.evaluation.evaluator import AgentEvaluator


# ═══════════════════════ 输出解析 ═══════════════════════

class TestOutputParsing:
    def test_extract_confidence_decimal(self):
        assert _extract_confidence("verdict=malicious, confidence=0.85, risk=高危") == 0.85

    def test_extract_confidence_percent(self):
        assert _extract_confidence("confidence=85%, risk=高危") == 0.85

    def test_extract_confidence_none(self):
        assert _extract_confidence("") is None
        assert _extract_confidence("no confidence here") is None

    def test_extract_verdict(self):
        assert _extract_verdict("verdict=malicious, confidence=0.85") == "malicious"
        assert _extract_verdict("") is None


# ═══════════════════════ 指标计算 ═══════════════════════

def _make_db_with_trajectories():
    """构造带轨迹数据的 SQLite 数据库。"""
    import sqlite3
    from backend.storage.database import Database
    from backend.storage.models import SCHEMA_SQL
    db = Database(":memory:")
    conn = db.connect()
    conn.executescript(SCHEMA_SQL)
    conn.commit()

    # 写入轨迹
    traj = [
        {"step_id": "1", "phase": "think", "actor": "LLM", "success": True, "duration_ms": 100},
        {"step_id": "2", "phase": "agent", "actor": "analyst-001",
         "output": "verdict=malicious, confidence=0.9, risk=高危",
         "success": True, "duration_ms": 800},
        {"step_id": "3", "phase": "tool", "actor": "threat_intel", "success": True, "duration_ms": 120},
        {"step_id": "4", "phase": "agent", "actor": "intel-001",
         "output": "verdict=suspicious, confidence=0.6, risk=中危",
         "success": True, "duration_ms": 500},
        {"step_id": "5", "phase": "route_correction", "actor": "analyst-001",
         "input": "任务", "output": "analyst-001 -> intel-001", "success": True, "duration_ms": 0},
    ]
    action_data = json.dumps({"steps": traj, "total_duration_ms": 1500}, ensure_ascii=False)
    cur = conn.execute(
        "INSERT INTO agent_logs (id, conversation_id, agent_id, action_type, action_data, duration_ms, created_at) "
        "VALUES (?, ?, ?, 'trajectory', ?, 1500, '2026-01-01T00:00:00Z')",
        ("traj-1", "conv-1", "orchestrator", action_data),
    )
    conn.commit()
    return db


@pytest.fixture
def db():
    return _make_db_with_trajectories()


class TestAgentMetrics:
    @pytest.mark.asyncio
    async def test_per_agent_metrics(self, db):
        metrics = AgentMetrics(db)
        agents = await metrics.per_agent_metrics()
        # analyst-001 和 intel-001
        by_id = {a["agent_id"]: a for a in agents}
        assert "analyst-001" in by_id
        assert "intel-001" in by_id
        assert by_id["analyst-001"]["tasks"] == 1
        assert by_id["analyst-001"]["failures"] == 0
        assert by_id["analyst-001"]["avg_confidence"] == pytest.approx(0.9)
        assert by_id["intel-001"]["avg_confidence"] == pytest.approx(0.6)
        # intel-001 无工具调用
        assert by_id["intel-001"]["tool_success_rate"] is None

    @pytest.mark.asyncio
    async def test_tool_metrics(self, db):
        metrics = AgentMetrics(db)
        tools = await metrics.tool_metrics()
        by_name = {t["tool"]: t for t in tools}
        assert "threat_intel" in by_name
        assert by_name["threat_intel"]["calls"] == 1
        assert by_name["threat_intel"]["success_rate"] == 1.0

    @pytest.mark.asyncio
    async def test_route_correction_metrics(self, db):
        metrics = AgentMetrics(db)
        route = await metrics.route_correction_metrics()
        assert route["corrections"] == 1
        assert route["total_routes"] == 2
        assert route["correction_rate"] == pytest.approx(0.5)

    @pytest.mark.asyncio
    async def test_decision_consistency(self, db):
        metrics = AgentMetrics(db)
        cons = await metrics.decision_consistency()
        # 2 个 agent 组，各 1 个裁决 -> 一致
        assert cons["groups"] == 2
        assert cons["consistency_rate"] == 1.0

    @pytest.mark.asyncio
    async def test_empty_db(self):
        import sqlite3
        from backend.storage.database import Database
        from backend.storage.models import SCHEMA_SQL
        db = Database(":memory:")
        conn = db.connect()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        metrics = AgentMetrics(db)
        assert await metrics.per_agent_metrics() == []
        assert await metrics.tool_metrics() == []
        route = await metrics.route_correction_metrics()
        assert route["corrections"] == 0
        cons = await metrics.decision_consistency()
        assert cons["consistency_rate"] == 1.0  # 空数据默认一致
        db.close()


# ═══════════════════════ 评分卡 ═══════════════════════

class TestAgentEvaluator:
    @pytest.mark.asyncio
    async def test_evaluate_all_structure(self, db):
        from backend.evaluation import AgentEvaluator
        result = await AgentEvaluator.evaluate_all(AgentMetrics(db))
        assert "agents" in result
        assert "system" in result
        assert "tool_metrics" in result
        assert "route" in result
        assert "consistency" in result
        assert len(result["agents"]) == 2

    @pytest.mark.asyncio
    async def test_agent_scorecard_fields(self, db):
        from backend.evaluation import AgentEvaluator
        result = await AgentEvaluator.evaluate_all(AgentMetrics(db))
        a = result["agents"][0]
        assert 0 <= a["score"] <= 100
        assert a["grade"] in ("A", "B", "C", "D", "F")
        assert "availability" in a["dimensions"]
        assert "efficiency" in a["dimensions"]
        assert "reliability" in a["dimensions"]
        assert "precision" in a["dimensions"]
        assert "tool_efficacy" in a["dimensions"]
        assert isinstance(a["issues"], list)

    def test_grade_mapping(self):
        assert AgentEvaluator._grade(95) == "A"
        assert AgentEvaluator._grade(80) == "B"
        assert AgentEvaluator._grade(65) == "C"
        assert AgentEvaluator._grade(45) == "D"
        assert AgentEvaluator._grade(10) == "F"

    def test_linear_score_invert(self):
        # invert=True: 失败率 0 -> 100, 失败率 50% -> 0
        assert AgentEvaluator._linear_score(0, 0.5, invert=True) == 100
        assert AgentEvaluator._linear_score(0.5, 0.5, invert=True) == 0
        assert AgentEvaluator._linear_score(0.25, 0.5, invert=True) == 50

    def test_linear_score_normal(self):
        # 成功率: bad_at=0.5（低于50%得0分）, 1.0 -> 100, 0.75 -> 50
        assert AgentEvaluator._linear_score(1.0, 0.5, invert=False) == 100
        assert AgentEvaluator._linear_score(0.75, 0.5, invert=False) == 50
        assert AgentEvaluator._linear_score(0.5, 0.5, invert=False) == 0
        # ok_at 覆盖: 达到 0.9 即满分
        assert AgentEvaluator._linear_score(0.9, 0.5, invert=False, ok_at=0.9) == 100

    def test_system_score_route_penalty(self):
        # 无 agent -> 0
        sys_s = AgentEvaluator._score_system([], {"correction_rate": 0}, {"consistency_rate": 1.0})
        assert sys_s["score"] == 0
        # 平均 80, 无修正, 一致 -> 80
        sys_s2 = AgentEvaluator._score_system(
            [{"score": 80}, {"score": 80}], {"correction_rate": 0}, {"consistency_rate": 1.0},
        )
        assert sys_s2["score"] == 80
