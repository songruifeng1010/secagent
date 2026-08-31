"""
Summary Agent（报告生成员）— v2.5

职责：汇总所有专业 Agent 的结构化分析结果 + 用户原始问题，
生成一份模板化的最终综合报告（JSON 结构化输出）。

链路位置：Commander → Analyst → Knowledge → Responder → **Summary Agent** → 输出

输出字段（SummaryResult）:
  - risk_summary:      风险摘要（≤200 字，置于最前）
  - summary_text:      一句话总述
  - core_findings:     核心发现（2-5 条）
  - recommended_actions: 推荐动作（按优先级排序）
  - detail:            详细分析（长文本，供前端折叠展示）
  - template_type:     事件模板分类（漏洞分析/攻击检测/安全配置/威胁情报/应急响应）
  - table:             表格化证据/步骤
  - suggested_action:  block|monitoring|escalate|none
  - needs_human_reason: 需人工介入的原因
"""
import json
import logging
import time
from typing import AsyncGenerator, Optional

from .base import BaseAgent, AgentConfig
from .registry import AgentMeta, register_agent
from ..models.message import AgentMessage, MessageType
from ..models.output import (
    parse_agent_result, parse_summary_result, SummaryResult,
)
from ..llm.provider import LLMFactory

logger = logging.getLogger("secagentx.agent.summary")

SUMMARY_SYSTEM_PROMPT = """你是 SecAgentX 的报告生成员 (Agent-Summary)。你的职责是：

## 核心能力
1. **汇总综合**: 接收所有专业 Agent（分析师/情报员/应急响应/知识）的结构化分析结果
2. **模板化报告**: 按事件类型生成结构化最终报告，不丢失任何关键信息
3. **优先级排序**: 推荐动作按 P0/P1/P2 优先级排列
4. **长文本保留**: 详细分析完整放入 detail 字段，不截断、不删除

## 输入
你会收到一个 JSON 数组，每项是一个专业 Agent 的结构化结果（含 verdict/confidence/
risk_level/key_evidence/risk_summary/detail/table 等字段），以及用户的原始问题。

## 工作准则
- 综合所有 Agent 的结论，不遗漏任何 Agent 的核心发现
- 若各 Agent 结论冲突，如实说明冲突点，并在 needs_human_reason 中标注
- 置信度/风险等级数值必须引用 Agent 提供的数值，不得编造
- 最终报告必须模板化：风险摘要在前，核心发现居中，推荐动作按优先级，详细分析放 detail
- 报告要面向运维人员，可直接执行

## 精炼输出规则（简化输出，严格遵守）
1. **risk_summary ≤ 120 字**：一句话讲清"是什么问题 + 什么风险 + 怎么办"，不展开。
2. **核心发现 ≤ 3 条**：只保留最重要的 3 条，每条一句话（≤50 字）。
3. **推荐动作 ≤ 3 条**：按 P0/P1/P2 各最多 1 条，每条一句话（≤50 字）。
4. **详细内容全部放 detail**：表、完整分析、背景信息写进 detail 字段，不进摘要区。
5. **禁止重复**：同一事实不得在 risk_summary / core_findings / detail 中重复表述。
"""


@register_agent(AgentMeta(
    agent_id="summary-001",
    name="报告生成员",
    description="汇总所有专业Agent分析结果，生成模板化最终综合报告",
    capabilities=["汇总", "报告", "总结", "模板化"],
    llm_provider="deepseek",
))
class SummaryAgent(BaseAgent):
    """报告生成员：把多 Agent 结构化结果汇总为模板化最终报告（JSON）。"""

    def __init__(self, tools=None, llm_fallback_config=None):
        config = AgentConfig(
            agent_id="summary-001",
            name="报告生成员",
            description="汇总所有专业Agent分析结果，生成模板化最终综合报告",
            llm_provider="deepseek",
            system_prompt=SUMMARY_SYSTEM_PROMPT,
            allowed_tools=[],   # 汇总型 Agent 不调用工具
        )
        super().__init__(config, tools, llm_fallback_config)

    def _default_system_prompt(self) -> str:
        return SUMMARY_SYSTEM_PROMPT

    def build_system_prompt(self, context: Optional[dict] = None) -> str:
        return self.config.system_prompt or SUMMARY_SYSTEM_PROMPT

    async def process_message(self, message: AgentMessage) -> AsyncGenerator[dict, None]:
        """
        汇总所有 Agent 结果 → 生成最终报告（纯结构化，不走工具）。

        message.payload 期望:
          - task: 用户原始问题
          - agent_results: [AgentResult dict, ...]
          - fusion_verdict: {verdict, confidence, risk_level, recommended_action}
          - risk_scorecard: {risk_score, risk_level, dimensions, summarized}
          - template_type: 事件模板分类（Classifier Agent 判定）
        """
        self.status = "busy"
        start = time.time()
        try:
            task = message.payload.get("task", "")
            agent_results = message.payload.get("agent_results", []) or []
            fusion = message.payload.get("fusion_verdict", {}) or {}
            scorecard = message.payload.get("risk_scorecard", {}) or {}
            template_type = message.payload.get("template_type", "") or ""

            # 构造输入：序列化所有 Agent 结果（压缩 detail 避免超长）
            agent_summaries = []
            for r in agent_results:
                d = parse_agent_result(r)
                compact = {
                    "agent_id": d.get("agent_id", ""),
                    "agent_name": d.get("agent_name", ""),
                    "verdict": d.get("verdict", "unknown"),
                    "confidence": d.get("confidence", 0.0),
                    "risk_level": d.get("risk_level", "中危"),
                    "risk_summary": (d.get("risk_summary") or "")[:300],
                    "key_evidence": (d.get("key_evidence") or [])[:5],
                    "recommended_action": d.get("recommended_action", "monitoring"),
                    "technique_ids": d.get("technique_ids") or [],
                    "detail": (d.get("detail") or "")[:1000],
                }
                agent_summaries.append(compact)

            prompt_content = {
                "task": task,
                "template_type": template_type,
                "agent_results": agent_summaries,
                "fusion_verdict": fusion,
                "risk_scorecard": {
                    "risk_score": scorecard.get("risk_score", 0),
                    "risk_level": scorecard.get("risk_level", "低危"),
                    "dimensions": scorecard.get("dimensions", [])[:8],
                },
            }

            # 按模板分类引导输出结构（第六步：不同模板）
            tpl_guide = {
                "漏洞分析": "以「漏洞清单」为核心：table 每行 = 漏洞ID/影响版本/风险/修复建议；detail 含漏洞利用影响分析",
                "攻击检测": "以「攻击证据链」为核心：table 每行 = 攻击阶段/证据/来源；detail 含攻击时间线与影响评估",
                "安全配置": "以「配置加固项」为核心：table 每行 = 配置项/当前风险/加固建议；detail 含加固优先级与实施步骤",
                "威胁情报": "以「情报命中」为核心：table 每行 = IOC/情报源/关联威胁；detail 含溯源分析与 APT 关联",
                "应急响应": "以「处置步骤」为核心：table 每行 = 步骤/动作/优先级；detail 含应急预案与恢复建议",
            }.get(template_type, "以核心发现与推荐动作组织报告")

            # 确定性权威数值：融合裁决 + 风险评分卡
            _fv = fusion or {}
            _fv_v = _fv.get("verdict", "unknown")
            _fv_c = _fv.get("confidence", 0)
            _fv_r = _fv.get("risk_level", "低危")
            _sc = scorecard or {}
            _sc_score = _sc.get("risk_score", 0)
            authority = (
                f"【确定性权威数值 - 不可修改】最终判定: {_fv_v} | "
                f"置信度: {float(_fv_c or 0):.0%} | 风险等级: {_fv_r} | "
                f"风险评分: {_sc_score}"
            )

            messages = [
                {"role": "system", "content": self.build_system_prompt()},
                {"role": "user", "content": (
                    "请汇总以下专业 Agent 的分析结果，输出模板化最终综合报告（纯 JSON）。\n\n"
                    + authority + "\n\n"
                    + json.dumps(prompt_content, ensure_ascii=False)
                    + f"\n\n事件模板分类为「{template_type}」，请按该模板组织报告：{tpl_guide}"
                      "\n\n输出字段必须包含: risk_summary(≤120字风险摘要), "
                      "summary_text(一句话总述), core_findings(核心发现≤3条,每条≤50字), "
                      "recommended_actions(推荐动作≤3条,按P0/P1/P2排序,每条≤50字), "
                      "detail(详细分析,完整保留长文本), "
                      "template_type(事件模板分类), table(表格), "
                      "suggested_action(block/monitoring/escalate/none), "
                      "needs_human_reason(如需人工介入的原因)。"
                      "重要：risk_summary 中提到的判定/置信度/风险等级，"
                      "**必须引用上方「确定性权威数值」，不得自行编造或使用 Agent 的单独置信度**；"
                      "单个 Agent 置信度高不代表整体结论置信度高，二者不得混用。"
                )},
            ]

            # 强制结构化输出 JSON
            try:
                raw = await self.llm.structured_output(messages, SummaryResult)
                if raw and not raw.get("parse_error") and not raw.get("error"):
                    summary = parse_summary_result(raw)
                else:
                    summary = parse_summary_result({})
            except Exception as e:
                logger.warning("SummaryAgent structured_output 失败: %s", e)
                summary = parse_summary_result({})

            summary["agent_id"] = self.agent_id
            summary["agent_name"] = self.config.name

            yield {
                "type": "agent_result",
                "agent_id": self.agent_id,
                "content": summary.get("summary_text") or summary.get("risk_summary", ""),
                "duration_ms": (time.time() - start) * 1000,
                "structured": summary,
                "tool_calls": [],
                "structured_result": summary,
                "agent_trace": [],
                "summary_text": summary.get("summary_text", ""),
            }
        except Exception as e:
            self.stats["tasks_failed"] += 1
            logger.exception("SummaryAgent 处理失败", exc_info=True)
            yield {
                "type": "agent_error",
                "agent_id": self.agent_id,
                "error": f"内部错误: {e}",
                "code": "UNKNOWN",
                "recoverable": False,
            }
        finally:
            self.status = "idle"

