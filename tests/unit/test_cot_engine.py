"""
CoT (Chain-of-Thought) 思维链推理引擎单元测试

覆盖:
  - ReasoningStep / ReasoningChain 数据模型
  - CoTEngine 创建与配置
  - create_chain / reason_step / chain_to_json
  - 威胁分析场景使用
"""

import pytest


class TestReasoningModels:
    """推理数据模型测试"""

    def test_reasoning_step_creation(self):
        """创建推理步骤"""
        from backend.agents.cot_engine import ReasoningStep
        step = ReasoningStep(
            step_id="step-001",
            step_number=1,
            phase="观察",
            title="初始告警分析",
            observation="检测到来自10.0.0.5的SSH暴力破解",
            analysis="30分钟内100次登录失败，符合暴力破解特征",
            conclusion="确认SSH暴力破解攻击正在进行",
            evidence=[{"type": "log", "content": "Failed password for root from 10.0.0.5"}],
            confidence=0.85,
            next_question="攻击来源是否在其他系统也有活动？",
        )
        assert step.step_id == "step-001"
        assert step.step_number == 1
        assert step.phase == "观察"
        assert step.confidence == 0.85
        assert step.status == "completed"

    def test_reasoning_step_different_statuses(self):
        """不同状态的推理步骤"""
        from backend.agents.cot_engine import ReasoningStep

        for status in ["completed", "in_progress", "failed", "skipped"]:
            step = ReasoningStep(
                step_id=f"step-{status}",
                step_number=1, phase="分析", title="Test",
                observation="obs", analysis="analysis",
                conclusion="conclusion", evidence=[],
                confidence=0.5, next_question="?", status=status,
            )
            assert step.status == status

    def test_reasoning_chain_creation(self):
        """创建推理链"""
        from backend.agents.cot_engine import ReasoningChain, ReasoningStep

        chain = ReasoningChain(
            chain_id="chain-001",
            incident_type="SSH暴力破解",
            start_time="2026-07-22T10:00:00Z",
        )
        assert chain.chain_id == "chain-001"
        assert chain.incident_type == "SSH暴力破解"
        assert chain.is_complete is False

        step = ReasoningStep(
            step_id="step-001", step_number=1, phase="观察",
            title="分析", observation="o", analysis="a",
            conclusion="c", evidence=[], confidence=0.8, next_question="?",
        )
        chain.steps.append(step)
        assert len(chain.steps) == 1

        chain.final_conclusion = "确认攻击"
        chain.final_confidence = 0.9
        chain.is_complete = True
        assert chain.is_complete is True

    def test_reasoning_chain_hypotheses(self):
        """推理链中的假设"""
        from backend.agents.cot_engine import ReasoningChain

        chain = ReasoningChain(
            chain_id="chain-002",
            incident_type="恶意软件",
            start_time="2026-07-22T12:00:00Z",
        )
        chain.hypotheses = [
            {"id": "h1", "description": "已知恶意软件变种", "confidence": 0.8},
            {"id": "h2", "description": "新出现的未知恶意软件", "confidence": 0.3},
        ]
        assert len(chain.hypotheses) == 2


class TestCoTEngine:
    """CoT 思维链引擎测试"""

    def test_engine_creation(self):
        """创建 CoT 引擎"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()
        assert engine is not None

    def test_create_chain(self):
        """创建推理链"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        chain = engine.create_chain(incident_type="external_attack")
        assert chain is not None
        assert chain.incident_type == "external_attack"
        assert chain.chain_id is not None
        assert len(engine.active_chains) == 1

    def test_create_multiple_chains(self):
        """创建多个推理链"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        engine.create_chain("insider_threat")
        engine.create_chain("external_attack")
        assert len(engine.active_chains) == 2

    @pytest.mark.asyncio
    async def test_reason_step(self):
        """推理步骤"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        chain = engine.create_chain("insider_threat")
        step = await engine.reason_step(
            chain=chain,
            phase_index=0,
            context={
                "observation": "检测到异常登录行为",
                "source_ip": "10.0.0.5",
                "event_type": "multiple_login_failures",
            },
        )
        assert step is not None
        assert step.step_number == 1
        assert step.phase is not None

    @pytest.mark.asyncio
    async def test_reason_step_multiple(self):
        """多步推理"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        chain = engine.create_chain("external_attack")
        step1 = await engine.reason_step(chain, 0, {"observation": "扫描发现"})
        step2 = await engine.reason_step(chain, 1, {"observation": "漏洞利用"})
        assert step1.step_number == 1
        assert step2.step_number == 2
        assert len(chain.steps) == 2

    @pytest.mark.asyncio
    async def test_chain_to_json(self):
        """推理链转 JSON"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        chain = engine.create_chain("malware_analysis")
        await engine.reason_step(chain, 0, {"observation": "检测到恶意软件"})
        await engine.reason_step(chain, 1, {"observation": "分析恶意行为"})

        json_data = engine.chain_to_json(chain)
        assert json_data is not None
        assert isinstance(json_data, dict)
        assert json_data["incident_type"] == "malware_analysis"
        assert len(json_data["steps"]) == 2

    @pytest.mark.asyncio
    async def test_get_chain_summary(self):
        """获取推理链摘要"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        chain = engine.create_chain("insider_threat")
        await engine.reason_step(chain, 0, {"observation": "初始发现"})
        summary = engine.get_chain_summary(chain)
        assert summary is not None
        assert len(summary) > 0

    def test_get_template(self):
        """获取推理模板"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        template = engine.get_template("insider_threat")
        assert template is not None
        assert isinstance(template, dict)

    def test_get_template_default(self):
        """默认推理模板"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        template = engine.get_template("unknown_type")
        assert template is not None
        assert isinstance(template, dict)


class TestCoTWithThreatAnalysis:
    """CoT 在威胁分析场景中的使用"""

    @pytest.mark.asyncio
    async def test_full_attack_analysis_flow(self):
        """完整的攻击分析推理流程"""
        from backend.agents.cot_engine import CoTEngine
        engine = CoTEngine()

        # 1. 创建推理链
        chain = engine.create_chain("external_attack")

        # 2. 侦查阶段
        await engine.reason_step(chain, 0, {
            "observation": "外部IP 203.0.113.1 发起大规模端口扫描",
            "scan_ports": "22,443,8080",
        })

        # 3. 漏洞利用阶段
        await engine.reason_step(chain, 1, {
            "observation": "检测到SQL注入尝试",
            "target": "Web登录接口",
            "payload": "union select",
        })

        # 4. 权限提升阶段
        await engine.reason_step(chain, 2, {
            "observation": "检测到异常提权行为",
            "method": "xp_cmdshell",
        })

        assert len(chain.steps) == 3
        assert chain.incident_type == "external_attack"

        # 验证 JSON 输出
        json_data = engine.chain_to_json(chain)
        assert len(json_data["steps"]) == 3
