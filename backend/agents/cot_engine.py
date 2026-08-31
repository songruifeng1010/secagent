"""
Chain-of-Thought (CoT) 思维链推理引擎

用于复杂攻击事件的逐步推理展示，核心能力：
1. 将复杂事件拆解为推理步骤
2. 每步展示：当前状态 → 分析 → 结论 → 下一跳
3. 支持分支推理（多条线索并行）
4. 推理过程可追溯、可验证
5. 输出结构化思维链供前端展示
"""

import json
import time
import re
import uuid
from typing import Optional, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ReasoningStep:
    """推理步骤"""
    step_id: str
    step_number: int
    phase: str          # 推理阶段：观察 / 分析 / 关联 / 判定 / 行动
    title: str
    observation: str    # 当前观察到的事实
    analysis: str       # 分析过程
    conclusion: str     # 该步的结论
    evidence: list      # 支撑证据
    confidence: float   # 该步置信度 0-1
    next_question: str  # 下一步需要回答的问题
    status: str = "completed"  # completed / in_progress / failed / skipped


@dataclass
class ReasoningChain:
    """完整的推理链"""
    chain_id: str
    incident_type: str
    start_time: str
    end_time: Optional[str] = None
    steps: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)  # 假设列表
    final_conclusion: str = ""
    final_confidence: float = 0.0
    is_complete: bool = False


# ================ 攻击事件推理模板 ================

INCIDENT_REASONING_TEMPLATES = {
    "insider_threat": {
        "name": "内部威胁检测",
        "phases": [
            {
                "phase": "观察",
                "title": "异常行为发现",
                "description": "从流量/日志/告警中发现初始异常信号",
                "prompt_template": """分析以下初始异常信号，总结关键观察点：
信号来源: {signal_source}
异常描述: {signal_description}
严重级别: {severity}
时间: {timestamp}

请输出json格式：
{{
  "observations": ["列出3-5个关键观察点"],
  "initial_assessment": "初步判断是什么类型的事件",
  "key_indicators": ["关键指标列表"],
  "next_question": "下一步需要调查什么"
}}"""
            },
            {
                "phase": "分析",
                "title": "终端进程关联",
                "description": "关联异常流量对应的终端进程、网络连接、文件操作",
                "prompt_template": """基于以下终端数据关联分析异常行为：
源IP: {source_ip}
目标IP: {dest_ip}
协议/端口: {protocol}
异常进程: {processes}
文件操作: {file_ops}
网络连接: {connections}

请输出json格式：
{{
  "linked_processes": ["关联到的可疑进程"],
  "process_analysis": "进程行为分析",
  "file_operations": ["异常文件操作"],
  "network_connections": [{{"local": "", "remote": "", "pid": 0}}],
  "suspicious_score": 0.0-1.0,
  "next_question": "下一步需要调查什么"
}}"""
            },
            {
                "phase": "关联",
                "title": "用户身份定位",
                "description": "将异常行为关联到具体的用户身份和权限",
                "prompt_template": """将以下异常行为关联到用户身份：
进程归属用户: {users}
登录时间/IP: {login_info}
权限级别: {privileges}
历史基线: {baseline}
最近操作: {recent_actions}

请输出json格式：
{{
  "identified_users": [{{"username": "", "department": "", "privilege": ""}}],
  "user_behavior_analysis": "与基线的偏离分析",
  "auth_anomalies": ["认证异常列表"],
  "privilege_escalation": "是否有权限提升迹象",
  "confidence": 0.0-1.0,
  "next_question": "下一步需要调查什么"
}}"""
            },
            {
                "phase": "判定",
                "title": "行为意图判定",
                "description": "综合所有证据判定是否为恶意行为及意图",
                "prompt_template": """综合以下所有证据链判定行为意图：
{evidence_summary}

请输出json格式：
{{
  "verdict": "internal_threat|external_attack|false_positive|suspicious",
  "intent": "数据窃取|权限滥用|破坏|横向移动|未知",
  "confidence": 0.0-1.0,
  "key_evidence": ["支撑判定的关键证据"],
  "risk_level": "低危|中危|高危|紧急",
  "recommendation": "建议处置措施"
}}"""
            },
            {
                "phase": "行动",
                "title": "处置建议",
                "description": "基于判定结果给出分步处置建议",
                "prompt_template": """基于判定结果生成处置方案：
判定结果: {verdict}
风险等级: {risk_level}
涉及用户: {users}
涉及资产: {assets}

请输出json格式：
{{
  "immediate_actions": ["立即执行的措施"],
  "investigation_actions": ["进一步调查措施"],
  "remediation_actions": ["修复加固措施"],
  "monitoring_suggestions": ["后续监控建议"],
  "report_summary": "事件总结"
}}"""
            }
        ]
    },
    
    "ransomware": {
        "name": "勒索软件攻击",
        "phases": [
            {
                "phase": "观察",
                "title": "异常行为发现",
                "description": "发现加密行为、勒索信息等初始信号"
            },
            {
                "phase": "分析",
                "title": "感染链追溯",
                "description": "追溯勒索软件的初始入侵途径"
            },
            {
                "phase": "关联",
                "title": "影响范围评估",
                "description": "评估受影响的主机、文件、服务范围"
            },
            {
                "phase": "判定",
                "title": "勒索家族判定",
                "description": "根据行为特征判定勒索软件家族"
            },
            {
                "phase": "行动",
                "title": "应急响应",
                "description": "隔离、取证、恢复步骤"
            }
        ]
    },
    
    "apt_attack": {
        "name": "APT高级持续威胁",
        "phases": [
            {
                "phase": "观察",
                "title": "可疑信号发现",
                "description": "发现异常外连、C2通信等APT初始信号"
            },
            {
                "phase": "分析",
                "title": "入侵链重构",
                "description": "重构完整的攻击链杀伤链"
            },
            {
                "phase": "关联",
                "title": "威胁情报关联",
                "description": "关联已知APT团伙TTPs和IOCs"
            },
            {
                "phase": "判定",
                "title": "攻击者画像",
                "description": "判定攻击者身份、动机和能力"
            },
            {
                "phase": "行动",
                "title": "清除与加固",
                "description": "清除后门、修复漏洞、加固建议"
            }
        ]
    }
}


class CoTEngine:
    """
    思维链推理引擎
    
    核心功能：
    - 将复杂事件拆解为逐步推理过程
    - 每步展示：观察→分析→结论→下一步
    - 支持多类型攻击事件模板
    - 推理过程可追溯
    """

    def __init__(self, llm=None):
        self.llm = llm
        self.active_chains: dict[str, ReasoningChain] = {}

    def create_chain(self, incident_type: str = "insider_threat") -> ReasoningChain:
        """创建新的推理链"""
        chain = ReasoningChain(
            chain_id=f"cot-{uuid.uuid4().hex[:8]}",
            incident_type=incident_type,
            start_time=datetime.now(timezone.utc).isoformat(),
        )
        self.active_chains[chain.chain_id] = chain
        return chain

    def get_template(self, incident_type: str) -> dict:
        """获取攻击事件推理模板"""
        return INCIDENT_REASONING_TEMPLATES.get(
            incident_type,
            INCIDENT_REASONING_TEMPLATES["insider_threat"]
        )

    async def reason_step(self, chain: ReasoningChain, phase_index: int,
                          context: dict) -> ReasoningStep:
        """
        执行单步推理
        
        参数:
            chain: 推理链
            phase_index: 当前推理阶段索引
            context: 上下文数据（来自告警/日志/用户输入）
        
        返回:
            ReasoningStep: 推理步骤
        """
        template = self.get_template(chain.incident_type)
        phases = template["phases"]

        if phase_index >= len(phases):
            return ReasoningStep(
                step_id=f"{chain.chain_id}-step-{phase_index + 1}",
                step_number=phase_index + 1,
                phase="completed",
                title="推理完成",
                observation="",
                analysis="",
                conclusion="推理链已完成所有步骤",
                evidence=[],
                confidence=chain.final_confidence or 0.0,
                next_question="",
                status="completed",
            )

        phase = phases[phase_index]
        step = ReasoningStep(
            step_id=f"{chain.chain_id}-step-{phase_index + 1}",
            step_number=phase_index + 1,
            phase=phase["phase"],
            title=phase["title"],
            observation=context.get("observation", ""),
            analysis="",
            conclusion="",
            evidence=[],
            confidence=0.0,
            next_question="",
            status="in_progress",
        )

        # 如果有LLM，调用LLM进行推理
        if self.llm and "prompt_template" in phase:
            prompt = phase["prompt_template"].format(**context)
            try:
                result = await self.llm.structured_output(
                    [{"role": "user", "content": prompt}], None
                )
                if isinstance(result, dict):
                    step.analysis = result.get("process_analysis") or \
                                    result.get("user_behavior_analysis") or \
                                    result.get("verdict") or ""
                    step.conclusion = result.get("initial_assessment") or \
                                      result.get("verdict", "") or \
                                      result.get("suspicious_score", "")
                    step.evidence = result.get("key_indicators") or \
                                    result.get("key_evidence", [])
                    step.confidence = result.get("confidence", 0.5) or \
                                      result.get("suspicious_score", 0.5)
                    step.next_question = result.get("next_question", "")
            except Exception:
                # LLM失败时使用基于规则的推理
                pass

        # 如果没有LLM或LLM失败，使用基于规则的推理
        if not step.analysis:
            step = self._rule_based_reasoning(chain, phase_index, context, step)

        step.status = "completed"
        chain.steps.append(step)

        # 更新假设列表
        if step.confidence > 0.6 and step.conclusion:
            chain.hypotheses.append({
                "step": step.step_number,
                "phase": step.phase,
                "hypothesis": step.conclusion,
                "confidence": step.confidence,
            })

        return step

    def _rule_based_reasoning(self, chain: ReasoningChain, phase_index: int,
                              context: dict, step: ReasoningStep) -> ReasoningStep:
        """基于规则的降级推理（无LLM时使用）"""
        
        if chain.incident_type == "insider_threat":
            step = self._reason_insider_threat(chain, phase_index, context, step)
        elif chain.incident_type == "ransomware":
            step = self._reason_ransomware(chain, phase_index, context, step)
        elif chain.incident_type == "apt_attack":
            step = self._reason_apt(chain, phase_index, context, step)
        else:
            step.conclusion = f"已完成{step.title}阶段的推理（规则模式）"
            step.confidence = 0.5

        return step

    def _reason_insider_threat(self, chain: ReasoningChain, phase_index: int,
                               context: dict, step: ReasoningStep) -> ReasoningStep:
        """内部威胁场景规则推理"""
        
        source_ip = context.get("source_ip", "")
        dest_ip = context.get("dest_ip", "")
        users = context.get("users", "")
        processes = context.get("processes", "")
        file_ops = context.get("file_ops", "")

        if phase_index == 0:  # 观察
            step.analysis = f"检测到来自 {source_ip} 的异常流量"
            if "内部" in context.get("signal_source", "") or source_ip.startswith(("10.", "172.", "192.168")):
                step.analysis += "\n→ 源IP为内网地址，排除外部攻击可能性"
                step.analysis += "\n→ 重点关注内部人员行为"
            if "非工作时间" in context.get("signal_description", ""):
                step.analysis += "\n→ 非工作时间活动，增加可疑度"
            step.conclusion = f"发现来自内网 {source_ip} 的可疑行为"
            step.evidence = [f"源IP: {source_ip}", f"目标: {dest_ip}"]
            step.confidence = 0.5
            step.next_question = f"需要调查 {source_ip} 上的进程和登录用户"

        elif phase_index == 1:  # 分析 - 终端进程关联
            analysis_lines = ["进程与网络连接关联分析:"]
            if processes:
                analysis_lines.append(f"→ 发现进程: {processes}")
            if "未知" in processes or "可疑" in processes:
                analysis_lines.append("→  存在未知/可疑进程")
            if file_ops:
                analysis_lines.append(f"→ 文件操作: {file_ops}")
                if "大量" in file_ops or "批量" in file_ops:
                    analysis_lines.append("→  批量文件操作，可能正在收集数据")
                if "USB" in file_ops or "移动" in file_ops:
                    analysis_lines.append("→  涉及移动存储设备")
            step.analysis = "\n".join(analysis_lines)
            step.conclusion = f"进程分析与网络连接关联完成"
            step.evidence = [processes, file_ops]
            step.confidence = 0.6
            step.next_question = f"需要确认进程归属的用户身份"

        elif phase_index == 2:  # 关联 - 用户身份
            analysis_lines = ["用户行为关联分析:"]
            if users:
                analysis_lines.append(f"→ 关联用户: {users}")
            analysis_lines.append("→ 比对用户行为基线")
            if "非工作时间" in context.get("login_info", ""):
                analysis_lines.append("→  非工作时间登录")
            if "管理员" in context.get("privileges", ""):
                analysis_lines.append("→  具有管理员权限，风险更高")
            analysis_lines.append("→ 检查近期异常操作记录")
            step.analysis = "\n".join(analysis_lines)
            step.conclusion = f"已将异常行为关联到用户"
            step.evidence = [f"用户: {users}", f"权限: {context.get('privileges', '')}"]
            step.confidence = 0.65
            step.next_question = "综合所有证据做出最终判定"

        elif phase_index == 3:  # 判定
            evidence_list = []
            for s in chain.steps:
                evidence_list.extend(s.evidence)

            score = 0
            risk_factors = []
            
            # 基于证据综合评分
            if "非工作时间" in str(evidence_list):
                score += 0.2
                risk_factors.append("非工作时间活动")
            if "管理员" in str(evidence_list):
                score += 0.2
                risk_factors.append("管理员权限")
            if "批量" in str(evidence_list) or "大量" in str(evidence_list):
                score += 0.2
                risk_factors.append("批量数据操作")
            if "USB" in str(evidence_list) or "移动" in str(evidence_list):
                score += 0.2
                risk_factors.append("移动存储设备使用")
            if "异常外传" in str(evidence_list) or "外连" in str(evidence_list):
                score += 0.2
                risk_factors.append("异常外连行为")
            
            score = min(score, 1.0)
            
            step.analysis = f"""综合评分分析:
证据数量: {len(evidence_list)} 条
风险因素: {', '.join(risk_factors) if risk_factors else '未发现明显风险因素'}
综合评分: {score:.1%}"""

            if score >= 0.8:
                verdict = "internal_threat"
                intent = "数据窃取"
                risk = "紧急"
            elif score >= 0.5:
                verdict = "suspicious"
                intent = "待确认"
                risk = "高危"
            elif score >= 0.3:
                verdict = "suspicious"
                intent = "需进一步调查"
                risk = "中危"
            else:
                verdict = "false_positive"
                intent = "误报"
                risk = "低危"

            step.conclusion = f"判定: {verdict} | 意图: {intent} | 风险: {risk}"
            step.evidence = risk_factors
            step.confidence = score
            step.next_question = "生成处置建议"

        elif phase_index == 4:  # 行动
            verdict = "内部威胁" if step.confidence > 0.5 else "待确认事件"
            step.conclusion = f"""
## 处置方案

### 立即执行
1. 隔离涉及的主机和账户
2. 保留所有日志和内存取证
3. 通知安全主管

### 调查措施
1. 全面审查涉及用户的近期操作日志
2. 检查是否有数据外传记录
3. 审查用户权限和访问记录

### 后续加固
1. 实施UEBA用户行为分析
2. 加强内部审计
3. 完善权限管理体系

### 事件评级: {verdict}""".strip()
            step.confidence = 0.8
            step.analysis = "基于完整推理链生成处置方案"

        return step

    def _reason_ransomware(self, chain: ReasoningChain, phase_index: int,
                           context: dict, step: ReasoningStep) -> ReasoningStep:
        """勒索软件场景规则推理"""
        step.conclusion = f"勒索软件分析 - {step.title}阶段完成"
        step.confidence = 0.6
        return step

    def _reason_apt(self, chain: ReasoningChain, phase_index: int,
                    context: dict, step: ReasoningStep) -> ReasoningStep:
        """APT场景规则推理"""
        step.conclusion = f"APT攻击分析 - {step.title}阶段完成"
        step.confidence = 0.6
        return step

    def get_chain_summary(self, chain: ReasoningChain) -> str:
        """生成推理链汇总报告"""
        parts = []
        parts.append(f"##  思维链推理报告\n")
        parts.append(f"**事件类型**: {INCIDENT_REASONING_TEMPLATES.get(chain.incident_type, {}).get('name', chain.incident_type)}")
        parts.append(f"**推理链ID**: {chain.chain_id}")
        parts.append(f"**推理步骤**: {len(chain.steps)} 步")
        parts.append(f"**最终置信度**: {chain.final_confidence:.1%}")
        parts.append("")

        for i, step in enumerate(chain.steps, 1):
            emoji_map = {"观察": "", "分析": "", "关联": "", "判定": "", "行动": ""}
            emoji = emoji_map.get(step.phase, "")

            parts.append(f"---")
            parts.append(f"### {emoji} 第{i}步：{step.title} ({step.phase}阶段)")
            parts.append(f"**置信度**: {step.confidence:.1%}")
            if step.observation:
                parts.append(f"\n**观察**: {step.observation}")
            if step.analysis:
                parts.append(f"\n**分析过程**:\n{step.analysis}")
            if step.conclusion:
                parts.append(f"\n**结论**: {step.conclusion}")
            if step.evidence:
                parts.append(f"\n**证据**:")
                for e in step.evidence:
                    parts.append(f"- {e}")
            if step.next_question:
                parts.append(f"\n**下一步**: {step.next_question}")
            parts.append("")

        # 假设列表
        if chain.hypotheses:
            parts.append("---")
            parts.append("###  推理过程中形成的假设")
            for h in chain.hypotheses:
                parts.append(f"- 第{h['step']}步({h['phase']}): {h['hypothesis']} (置信度: {h['confidence']:.1%})")
            parts.append("")

        return "\n".join(parts)

    def chain_to_markdown(self, chain: ReasoningChain) -> str:
        """将推理链转为Markdown格式（供前端展示）"""
        return self.get_chain_summary(chain)

    def chain_to_json(self, chain: ReasoningChain) -> dict:
        """将推理链转为JSON格式（供API传输）"""
        return {
            "chain_id": chain.chain_id,
            "incident_type": chain.incident_type,
            "start_time": chain.start_time,
            "end_time": chain.end_time,
            "total_steps": len(chain.steps),
            "steps": [
                {
                    "step_number": s.step_number,
                    "phase": s.phase,
                    "title": s.title,
                    "observation": s.observation,
                    "analysis": s.analysis,
                    "conclusion": s.conclusion,
                    "evidence": s.evidence,
                    "confidence": s.confidence,
                    "next_question": s.next_question,
                }
                for s in chain.steps
            ],
            "hypotheses": chain.hypotheses,
            "final_conclusion": chain.final_conclusion,
            "final_confidence": chain.final_confidence,
            "is_complete": chain.is_complete,
        }

