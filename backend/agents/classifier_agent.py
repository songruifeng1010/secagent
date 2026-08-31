"""
Classifier Agent（事件分类器）— v2.5

职责：判断用户输入的安全事件属于哪一类模板，
输出 template_type（漏洞分析 / 攻击检测 / 安全配置 / 威胁情报 / 应急响应），
供后续 Agent 与 Summary Agent 使用对应的输出模板。

实现：
  - 关键词预判兜底（classify_template）—— 快速、不依赖 LLM
  - LLM structured_output 精准判断 —— 关键词不明确时兜底，且永不阻断主链路
"""
import json
import logging
import time
from typing import AsyncGenerator, Optional

from .base import BaseAgent, AgentConfig
from .registry import AgentMeta, register_agent
from ..models.message import AgentMessage, MessageType
from ..models.output import (
    classify_template, parse_classifier_result, ClassifierResult,
)

logger = logging.getLogger("secagentx.agent.classifier")

CLASSIFIER_SYSTEM_PROMPT = """你是 SecAgentX 的事件分类器 (Agent-Classifier)。你的职责是：

## 核心能力
判断用户输入的安全问题属于哪一类意图，输出意图分类 + 风险基线。

## 意图分类标准（v2.6 Intent Classifier 层）
1. **安全知识**: 纯知识性咨询（"什么是SQLite"、"TCP是什么"、"介绍X"），**不是安全事件**，
   此类问题不要当作安全配置/攻击去分析，按知识问答处理，风险基线 50 分。
2. **漏洞分析**: 涉及 CVE 漏洞、补丁、漏洞利用（exploit/POC）、远程代码执行等
3. **攻击检测**: 涉及攻击行为、暴力破解、恶意软件、入侵、告警研判等
4. **安全配置**: 涉及加固、基线、策略、权限、合规、最佳实践等
5. **威胁情报**: 涉及 IOC、恶意 IP/域名、APT、威胁溯源、情报关联等
6. **应急响应**: 涉及封禁、隔离、处置、止血、取证、事件响应等

## 输出
纯 JSON 对象：
{
  "template_type": "安全知识|漏洞分析|攻击检测|安全配置|威胁情报|应急响应",
  "category_reason": "简短说明分类依据",
  "priority": "高|中|低",
  "risk_baseline": 50,
  "is_knowledge_query": false
}

字段说明：
- risk_baseline: 意图风险评分基线（安全知识=50, 漏洞分析=60, 攻击检测=70, 安全配置=50, 威胁情报=60, 应急响应=80）
- is_knowledge_query: 是否为纯知识性问题（是 → true）
"""


@register_agent(AgentMeta(
    agent_id="classifier-001",
    name="事件分类器",
    description="判断安全事件模板分类（漏洞分析/攻击检测/安全配置/威胁情报/应急响应）",
    capabilities=["分类", "模板", "识别"],
    llm_provider="deepseek",
))
class ClassifierAgent(BaseAgent):
    """事件分类器：判断事件模板分类（关键词兜底 + LLM 精准）。"""

    def __init__(self, tools=None, llm_fallback_config=None):
        config = AgentConfig(
            agent_id="classifier-001",
            name="事件分类器",
            description="判断安全事件模板分类（漏洞分析/攻击检测/安全配置/威胁情报/应急响应）",
            llm_provider="deepseek",
            system_prompt=CLASSIFIER_SYSTEM_PROMPT,
            allowed_tools=[],   # 分类 Agent 不调用工具
        )
        super().__init__(config, tools, llm_fallback_config)

    def _default_system_prompt(self) -> str:
        return CLASSIFIER_SYSTEM_PROMPT

    def build_system_prompt(self, context: Optional[dict] = None) -> str:
        return self.config.system_prompt or CLASSIFIER_SYSTEM_PROMPT

    async def process_message(self, message: AgentMessage) -> AsyncGenerator[dict, None]:
        self.status = "busy"
        start = time.time()
        try:
            task = message.payload.get("task", "")
            # 关键词预判（快速兜底）
            kw_type = classify_template(task)

            result = {"template_type": kw_type, "category_reason": "关键词预判", "priority": "中"}
            try:
                messages = [
                    {"role": "system", "content": self.build_system_prompt()},
                    {"role": "user", "content": (
                        f"请判断以下安全问题的模板分类（纯 JSON）。\n\n用户问题: {task}\n\n"
                        f"提示：关键词预判结果为「{kw_type}」，若你认为更合适可调整。"
                        f"输出字段: template_type, category_reason, priority"
                    )},
                ]
                raw = await self.llm.structured_output(messages, ClassifierResult)
                if raw and not raw.get("parse_error") and not raw.get("error"):
                    result = parse_classifier_result(raw)
                    if not result.get("category_reason"):
                        result["category_reason"] = "LLM 判断"
            except Exception as e:
                logger.debug("ClassifierAgent LLM 判断失败，用关键词预判: %s", e)

            result["agent_id"] = self.agent_id
            result["agent_name"] = self.config.name
            yield {
                "type": "agent_result",
                "agent_id": self.agent_id,
                "content": f"事件分类: {result['template_type']}（{result['category_reason']}）",
                "duration_ms": (time.time() - start) * 1000,
                "structured": result,
                "tool_calls": [],
                "structured_result": result,
                "agent_trace": [],
                "summary_text": f"事件分类: {result['template_type']}",
            }
        except Exception as e:
            self.stats["tasks_failed"] += 1
            logger.exception("ClassifierAgent 处理失败", exc_info=True)
            yield {
                "type": "agent_error",
                "agent_id": self.agent_id,
                "error": f"内部错误: {e}",
                "code": "UNKNOWN",
                "recoverable": False,
            }
        finally:
            self.status = "idle"

