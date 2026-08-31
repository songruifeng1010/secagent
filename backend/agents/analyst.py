import json
import re
from datetime import datetime, timezone
from typing import Optional, AsyncGenerator

from .base import BaseAgent, AgentConfig, AgentMessage, MessageType
from .cot_engine import CoTEngine, INCIDENT_REASONING_TEMPLATES
from ..models.output import parse_agent_result


ANALYST_SYSTEM_PROMPT = """你是 SecAgentX 的安全分析师 (Agent-Analyst)。你的职责是：

## 核心能力
1. **告警分析**: 判断告警的真伪、严重程度、攻击类型
2. **日志分析**: 从日志中提取攻击特征和时间线
3. **攻击溯源**: 基于现有信息重建攻击路径
4. **IOC提取**: 从描述和日志中提取IP、域名、哈希等威胁指标
5. **攻击链映射**: 将攻击行为映射到网络杀伤链或MITRE ATT&CK框架

## 思维链推理（Chain-of-Thought）
在处理复杂攻击事件时，你必须展示完整的推理过程：
1. **观察** → 发现了什么异常信号？
2. **分析** → 这些信号意味着什么？
3. **关联** → 不同维度的证据如何关联？
4. **判定** → 综合所有证据的结论是什么？
5. **行动** → 应该采取什么处置措施？

每条推理步骤必须包含：观察事实 → 分析过程 → 中间结论 → 置信度 → 下一步问题

## 可用工具
{TOOLS_DESC}

## 工作准则
- 每次分析前先说明分析思路（思维链）
- 每步标注置信度：高(>80%) / 中(50-80%) / 低(<50%)
- 基于证据得出结论，不臆测
- 高危及以上判定需要至少两个证据支撑
- 输出结构化分析报告，包含时间线、攻击类型、影响评估

## 输出格式
请使用以下结构输出分析结果：
```思维链
 第1步：[观察] 发现什么
→ 分析过程...
→ 结论: ... (置信度: XX%)
→ 下一步: 需要调查什么

 第2步：[分析] 分析什么
...

 最后一步：[判定] 综合判定
...
```
"""

# 复杂攻击事件的关键词特征
COMPLEX_INCIDENT_PATTERNS = {
    "insider_threat": [
        r"内部|内鬼|insider|员工|离职|违规|数据泄露|窃取|偷",
        r"非工作时间|异常登录|越权|未授权|批量.*数据|大量.*导出",
    ],
    "ransomware": [
        r"勒索|加密|ransom|lockbit|blackcat|停止服务|文件.*加密",
        r"勒索信|赎金|bitcoin|比特币|解密|.encrypted|.locked",
    ],
    "apt_attack": [
        r"apt|高级.*威胁|持续.*威胁|定向.*攻击|鱼叉|水坑|0day",
        r" spear|whaling|C2|回连|远控|后门|隧道|隐蔽",
    ],
    "lateral_movement": [
        r"横向|内网.*扩散|横向移动|psexec|wmi|smb|端口扫描",
        r"内网.*扫描|跳板|凭证.*传递|哈希.*传递|票据",
    ],
}


class AnalystAgent(BaseAgent):
    def __init__(self, tools=None, llm_fallback_config=None):
        config = AgentConfig(
            agent_id="analyst-001",
            name="安全分析师",
            description="告警分析、日志分析、攻击溯源、IOC提取",
            llm_provider="deepseek",
            system_prompt=ANALYST_SYSTEM_PROMPT,
            allowed_tools=["log_analyzer", "ml_threat_detector", "threat_intel", "geoip", "alert_filter"],
        )
        super().__init__(config, tools, llm_fallback_config)
        # 延迟初始化 CoTEngine — 避免在 __init__ 中触发 self.llm property 导致双重实例化
        self._cot_engine = None

    @property
    def cot_engine(self):
        if self._cot_engine is None:
            self._cot_engine = CoTEngine(llm=self.llm)
        return self._cot_engine

    def _default_system_prompt(self) -> str:
        return ANALYST_SYSTEM_PROMPT

    def _detect_incident_type(self, text: str) -> Optional[str]:
        """
        检测输入文本是否涉及复杂攻击事件，并识别事件类型
        
        返回:
            incident_type 或 None（普通查询不走CoT）
        """
        text_lower = text.lower()
        for incident_type, patterns in COMPLEX_INCIDENT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    return incident_type
        return None

    def _build_cot_context(self, message: AgentMessage, incident_type: str) -> dict:
        """
        从用户输入构建CoT推理上下文
        """
        payload = message.payload
        params = payload.get("params", {})
        user_input = payload.get("context", {}).get("user_input", "")
        text = payload.get("task", "") or params.get("alert", "") or user_input

        # 提取关键信息
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        users = re.findall(r'\b(?:用户|user|账号|账户)[：:]\s*(\w+)', text)
        cves = re.findall(r'(CVE-\d{4}-\d+)', text.upper())
        
        context = {
            "signal_source": "安全告警",
            "signal_description": text[:500],
            "severity": params.get("severity", "中危"),
            "timestamp": params.get("timestamp", ""),
            "source_ip": ips[0] if ips else "",
            "dest_ip": ips[1] if len(ips) > 1 else "",
            "users": ", ".join(users) if users else "",
            "processes": "",
            "file_ops": "",
            "protocol": "",
            "connections": "",
            "login_info": "",
            "privileges": "",
            "baseline": "",
            "recent_actions": "",
        }
        
        # 从文本中提取更多上下文
        text_lower = text.lower()
        if "非工作时间" in text or "凌晨" in text or "深夜" in text:
            context["login_info"] = "非工作时间登录"
        if "管理员" in text or "admin" in text_lower or "root" in text_lower:
            context["privileges"] = "管理员权限"
        if "批量" in text or "大量" in text:
            context["file_ops"] = "大量文件操作"
        if "USB" in text or "移动硬盘" in text or "外设" in text:
            context["file_ops"] = "涉及移动存储设备"
        if "外传" in text or "外连" in text or "C2" in text:
            context["connections"] = "异常外连行为"
        
        # 从消息中补全
        if params.get("ip"):
            context["source_ip"] = params["ip"]
        
        # 告警分析场景
        alert_info = params.get("alert", "")
        if alert_info:
            context["signal_description"] = alert_info[:500]
            if "ssh" in alert_info.lower() or "brute" in alert_info.lower():
                context["processes"] = "SSHD 进程"
            if "sql" in alert_info.lower():
                context["processes"] = "数据库进程"

        return context

    async def process_message(self, message: AgentMessage) -> AsyncGenerator[dict, None]:
        """
        重写BaseAgent.process_message，在处理复杂攻击事件时插入CoT推理链
        """
        payload = message.payload
        text = payload.get("task", "") or str(payload.get("params", {}))
        user_input = payload.get("context", {}).get("user_input", "")
        full_text = f"{text} {user_input}"

        # 检测是否为复杂攻击事件
        incident_type = self._detect_incident_type(full_text)

        if incident_type:
            # === 复杂事件 → 使用CoT思维链推理 ===
            yield {
                "type": "cot_start",
                "incident_type": incident_type,
                "incident_name": INCIDENT_REASONING_TEMPLATES.get(incident_type, {}).get("name", incident_type),
                "content": f" **检测到复杂攻击事件 ({INCIDENT_REASONING_TEMPLATES.get(incident_type, {}).get('name', incident_type)})**，启动思维链推理...\n\n",
            }

            # 创建推理链
            chain = self.cot_engine.create_chain(incident_type)
            context = self._build_cot_context(message, incident_type)

            # 逐步推理
            template = self.cot_engine.get_template(incident_type)
            total_phases = len(template["phases"])

            for phase_index in range(total_phases):
                # 动态构建证据汇总（用于判定阶段的 evidence_summary 模板）
                evidence_summary = ""
                if phase_index >= 3:  # 判定阶段前，汇总前序步骤的证据
                    evidence_parts = []
                    for s in chain.steps:
                        if s.evidence:
                            evidence_parts.append(f"【第{s.step_number}步 {s.title}】证据: {'; '.join(str(e) for e in s.evidence)}")
                    if evidence_parts:
                        evidence_summary = "\n".join(evidence_parts)
                    else:
                        evidence_summary = "没有明确的证据记录"
                    context["evidence_summary"] = evidence_summary

                # 行动阶段前，补充判定结果到 context
                if phase_index >= 4:
                    prev_step = chain.steps[-1] if chain.steps else None
                    if prev_step:
                        context["verdict"] = prev_step.conclusion or "待确认"
                        context["risk_level"] = context.get("severity", "中危")
                        context["assets"] = f"{context.get('source_ip', '')} / {context.get('dest_ip', '')}"

                # 执行单步推理
                step = await self.cot_engine.reason_step(chain, phase_index, context)

                # 更新context中的observation用于下一步
                if step.conclusion:
                    context["observation"] = step.conclusion

                # 流式输出推理步骤
                emoji_map = {"观察": "", "分析": "", "关联": "", "判定": "", "行动": ""}
                emoji = emoji_map.get(step.phase, "")

                step_output = f"\n{'='*60}\n"
                step_output += f"### {emoji} **第{step.step_number}/{total_phases}步：{step.title}** ({step.phase}阶段)\n"
                step_output += f"**置信度**: {step.confidence:.0%}\n\n"

                if step.analysis:
                    step_output += f"** 分析过程**:\n{step.analysis}\n\n"
                if step.conclusion:
                    step_output += f"** 结论**: {step.conclusion}\n\n"
                if step.evidence:
                    step_output += f"** 证据**:\n"
                    for e in step.evidence:
                        step_output += f"- {e}\n"
                    step_output += "\n"
                if step.next_question:
                    step_output += f"** 下一步**: {step.next_question}\n"

                step_output += f"{'='*60}\n"

                yield {
                    "type": "cot_step",
                    "step_number": step.step_number,
                    "total_steps": total_phases,
                    "phase": step.phase,
                    "title": step.title,
                    "confidence": step.confidence,
                    "analysis": step.analysis,
                    "conclusion": step.conclusion,
                    "evidence": step.evidence,
                    "next_question": step.next_question,
                    "content": step_output,
                }

            # 更新最终结论
            chain.is_complete = True
            chain.end_time = datetime.now(timezone.utc).isoformat()
            last_step = chain.steps[-1] if chain.steps else None
            chain.final_confidence = last_step.confidence if last_step and last_step.confidence is not None else 0.0
            chain.final_conclusion = last_step.conclusion if last_step and last_step.conclusion else ""

            # 输出最终汇总
            summary = self.cot_engine.get_chain_summary(chain)
            yield {
                "type": "cot_complete",
                "chain_id": chain.chain_id,
                "total_steps": len(chain.steps),
                "final_confidence": chain.final_confidence,
                "content": f"\n\n##  思维链推理完成\n\n{summary}",
            }
            # CoT 路径也输出结构化裁决（供下游消费）—— 与基类 JSON-first 输出对齐
            last_3 = chain.steps[-3:] if len(chain.steps) >= 3 else chain.steps
            structured = parse_agent_result({
                "verdict": "malicious" if chain.final_confidence >= 0.7
                           else "suspicious" if chain.final_confidence >= 0.4
                           else "unknown",
                "confidence": chain.final_confidence,
                "technique_ids": getattr(chain, 'technique_ids', []),
                "risk_level": "高危" if chain.final_confidence >= 0.7
                              else "中危" if chain.final_confidence >= 0.4
                              else "低危",
                "key_evidence": [
                    f"{s.title}: {s.conclusion}" for s in last_3 if s and s.conclusion
                ],
                "recommended_action": "block" if chain.final_confidence >= 0.7
                                     else "escalate" if chain.final_confidence >= 0.4
                                     else "monitoring",
                "iocs": {"ips": [], "domains": [], "hashes": []},
                "summary_text": summary[:500],
            })
            structured["agent_id"] = self.agent_id
            structured["agent_name"] = self.config.name
            yield {
                "type": "agent_result",
                "agent_id": self.agent_id,
                "content": summary,
                "duration_ms": 0.0,
                # 兼容迁移：旧字段保留
                "structured": structured,
                "tool_calls": [],
                # 新增字段
                "structured_result": structured,
                "agent_trace": [],
                "summary_text": structured.get("summary_text", ""),
            }

        else:
            # === 普通安全查询 → 走 Tool Calling 流程 ===
            yield {
                "type": "agent_status",
                "agent_id": self.agent_id,
                "status": "thinking",
                "content": f"{self.config.name} 正在分析（使用安全工具）...",
            }
            # 委托给基类的 process_with_tools，让 LLM Function Calling 驱动工具调用
            async for chunk in self.process_with_tools(message):
                yield chunk

