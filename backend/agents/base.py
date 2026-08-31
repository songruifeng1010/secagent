import time
import json
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, AsyncGenerator
from dataclasses import dataclass, field

from ..llm.provider import LLMFactory
from ..llm.base import LLMInterface
from ..tools.registry import ToolRegistry
from ..tools.calling import (
    build_tools_for_llm, parse_tool_calls, ToolCallHistory,
)
from ..tools.execution_engine import UnifiedToolCallEngine
from ..models.message import AgentMessage, MessageType
from ..models.output import AgentResult, parse_agent_result, result_to_text
from ..errors import AgentError, ToolError, LLMError


# 结构化裁决输出模板 — 所有 Agent 的 system prompt 末尾追加此内容
# v2.4 变更：从"文本内嵌 JSON 代码块"改为"纯 JSON 输出"，
# 由 LLM structured_output(response_format=json_object) 强制生成，文本正则仅作兜底。
# v2.5 变更：新增 risk_summary / detail / table / template_type 字段（模板化报告支撑）。
STRUCTURED_VERDICT_PROMPT = """

## 通用要求
- 回复中不要使用 emoji/表情符号，一律用文字描述。
- 最终回复必须是**纯 JSON 对象**（json 格式），**不要**使用 markdown 代码块围栏（```），
  不要输出任何非 JSON 的文本。若工具结果未提供足够信息，请如实给出 low confidence / unknown，不要臆测。

## 回答规则（严格遵守，用于控制输出长度与可读性）
1. **首先输出风险摘要**：risk_summary 字段必须放在所有内容最前，用一句话概括本次分析的核心结论与风险。
2. **摘要不超过 120 字**：risk_summary 必须精炼，控制在 120 字以内。
3. **详细解释放入 detail 字段**：所有展开性、过程性、长文本内容一律写入 detail 字段（JSON 字符串），
   不要写进 risk_summary 或 summary_text。
4. **禁止重复描述**：同一事实只出现一次，不得在 risk_summary / summary_text / key_evidence / detail 之间重复表述。
5. **使用表格**：多条目证据、漏洞清单、处置步骤等结构化信息，一律用 table 数组表达（每行一个对象）。
6. **key_evidence ≤ 3 条**：只保留最重要的证据，每条一句话。

## 结构化输出字段（json）
{
  "verdict": "malicious|benign|suspicious|unknown",
  "confidence": 0.0-1.0,
  "technique_ids": ["T1110"],
  "risk_level": "低危|中危|高危|紧急",
  "key_evidence": ["证据1", "证据2"],
  "recommended_action": "block|monitoring|escalate|none",
  "iocs": {"ips": ["1.2.3.4"], "domains": [], "hashes": []},
  "risk_summary": "（≤120字）本次分析的核心结论与风险摘要",
  "summary_text": "用一句话概括你的分析结论",
  "detail": "详细分析内容（长文本放这里）",
  "table": [{"项目": "CVE-2024-6387", "风险": "高危", "处置": "升级OpenSSH"}],
  "template_type": "漏洞分析|攻击检测|安全配置|威胁情报|应急响应"
}

字段说明：
- verdict: 判定结论（malicious=恶意, benign=正常/误报, suspicious=可疑, unknown=无法判定）
- confidence: 置信度 0.0~1.0
- technique_ids: MITRE ATT&CK 技术ID列表
- risk_level: 风险等级
- key_evidence: 关键证据列表（2-5条）
- recommended_action: 建议动作
- iocs: 提取到的威胁指标
- risk_summary: 风险摘要（≤120 字，必须最先输出）
- summary_text: 简短总结（供展示）
- detail: 详细分析（长文本，供前端折叠展示）
- table: 表格化证据/步骤（可选，多条目时使用）
- template_type: 事件模板分类（漏洞分析 / 攻击检测 / 安全配置 / 威胁情报 / 应急响应，按任务性质选一）
"""


@dataclass
class AgentConfig:
    agent_id: str = ""
    name: str = ""
    description: str = ""
    llm_provider: str = "deepseek"
    llm_config: dict = field(default_factory=dict)
    system_prompt: str = ""
    enabled: bool = True
    # 工具权限白名单：Agent 可调用的工具名列表。
    # None = 全部工具可用（兼容旧行为）；生产环境建议显式指定以最小化权限。
    allowed_tools: Optional[list] = None


class BaseAgent(ABC):
    def __init__(self, config: AgentConfig, tools: Optional[ToolRegistry] = None,
                 llm_fallback_config: Optional[dict] = None):
        self.config = config
        self.agent_id = config.agent_id or f"{self.__class__.__name__.lower()}-{uuid.uuid4().hex[:6]}"
        self.tools = tools or ToolRegistry()
        self._llm: Optional[LLMInterface] = None
        self._llm_fallback_config = llm_fallback_config
        self.status = "idle"
        self.conversation_history: list[dict] = []
        self.stats = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "total_duration_ms": 0,
            "total_tokens": 0,
            "last_duration_ms": 0,
            "last_tokens": 0,
        }
        # 统一工具调用引擎（仅暴露允许的工具，执行时也做权限校验）
        self.tool_engine = UnifiedToolCallEngine(self._get_allowed_tools())

    def _get_allowed_tools(self) -> ToolRegistry:
        """返回该 Agent 有权调用的工具子集。

        权限策略（最小权限原则）：
          - config.allowed_tools 为 None → 全部工具可用（兼容开发模式）
          - 显式指定 → 只保留白名单内的工具
        """
        if not self.config.allowed_tools:
            return self.tools
        sub = ToolRegistry()
        for name in self.config.allowed_tools:
            t = self.tools.get(name)
            if t is not None:
                sub.register(t)
        return sub

    @property
    def llm(self) -> LLMInterface:
        if self._llm is None:
            # 传入 fallback 配置：主 LLM 超时/失败时自动切换备用 LLM
            self._llm = LLMFactory.get_provider(
                self.config.llm_provider, self.config.llm_config,
                self._llm_fallback_config,
            )
        return self._llm

    def build_system_prompt(self, context: Optional[dict] = None) -> str:
        tools_desc = "\n".join(
            f"  - {t.name}: {t.description}"
            for t in self._get_allowed_tools().list_tools()
        )
        prompt = self.config.system_prompt or self._default_system_prompt()
        prompt = prompt.replace("{TOOLS_DESC}", tools_desc)
        prompt = prompt.replace("{AGENT_NAME}", self.config.name)
        prompt = prompt.replace("{AGENT_ID}", self.agent_id)
        # 追加结构化输出要求
        prompt += STRUCTURED_VERDICT_PROMPT
        return prompt

    @abstractmethod
    def _default_system_prompt(self) -> str:
        ...

    # ═══════════ 上下文管理（商用化关键：防 token 超限） ═══════════
    MAX_CONTEXT_MESSAGES = 30      # 最大消息条数
    MAX_CONTEXT_CHARS = 100_000    # 最大字符数

    def _compact_context(self, messages: list) -> list:
        """压缩对话上下文：保留 system + 最新消息，丢弃旧轮次。"""
        if not messages:
            return messages
        head = [m for m in messages if m.get("role") == "system"]
        body = [m for m in messages if m.get("role") != "system"]
        if not body:
            return head or messages

        total = sum(len(str(m.get("content", ""))) for m in head)
        kept = []
        for m in reversed(body):
            mlen = len(str(m.get("content", "")))
            if len(kept) >= self.MAX_CONTEXT_MESSAGES - len(head):
                break
            if total + mlen > self.MAX_CONTEXT_CHARS and kept:
                break
            total += mlen
            kept.append(m)
        kept.reverse()

        truncated = []
        for m in kept:
            content = m.get("content", "")
            if isinstance(content, str) and len(content) > 20_000:
                m = dict(m)
                m["content"] = content[:20_000] + "\n...(截断)"
            truncated.append(m)
        return head + truncated

    async def process_message(self, message: AgentMessage) -> AsyncGenerator[dict, None]:
        """
        处理消息（默认使用 Tool Calling，由 LLM 自主决定是否调工具）

        子类可重写此方法替换为纯文本流程或 CoT 推理流程。
        """
        # 默认使用 process_with_tools，让 LLM Function Calling 驱动
        async for chunk in self.process_with_tools(message):
            yield chunk

    def send_message(self, receiver: str, msg_type: MessageType,
                     payload: dict, context: Optional[dict] = None) -> AgentMessage:
        return AgentMessage(
            sender=self.agent_id,
            receiver=receiver,
            msg_type=msg_type,
            payload=payload,
            context=context or {},
        )

    def _parse_structured_verdict(self, text: str) -> dict:
        """
        从 LLM 输出文本中解析结构化裁决 JSON 块。
        Agent 应在回复末尾输出 ```verdict\n{...}\n``` 格式的结构化数据。

        解析结果会与默认值合并，确保所有字段都存在。
        """
        DEFAULT_VERDICT = {
            "verdict": "unknown",
            "confidence": 0.5,
            "technique_ids": [],
            "risk_level": "中危",
            "key_evidence": [],
            "recommended_action": "monitoring",
            "iocs": {"ips": [], "domains": [], "hashes": []},
        }
        # 依次尝试多种匹配模式（LLM 输出格式可能漂移）
        patterns = [
            r'```verdict\s*\n(.*?)\n```',   # 标准 verdict 代码块
            r'```json\s*\n(.*?verdict.*?)\n```',  # json 代码块中含 verdict
            r'(\{[^{}]*"verdict"[^{}]*\})',  # 任意含 verdict 键的 JSON 对象
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if not match:
                continue
            try:
                parsed = json.loads(match.group(1).strip())
                if isinstance(parsed, dict):
                    result = dict(DEFAULT_VERDICT)
                    result.update(parsed)
                    return result
            except (json.JSONDecodeError, ValueError, IndexError):
                continue
        return dict(DEFAULT_VERDICT)

    # ═══════════════ 结构化结果生成（JSON-first，文本正则兜底） ═══════════════

    async def _produce_structured_result(
        self, summary_messages: list, fallback_content: str = "",
    ) -> tuple[dict, str, bool]:
        """
        生成 Agent 结构化裁决结果（AgentResult JSON）。

        优先: LLM structured_output(response_format=json_object) → 容错校验
        降级: 文本流式 + _parse_structured_verdict 正则提取（保持主链路不阻断）

        返回:
            (structured_dict, fallback_text, used_fallback)
            - structured_dict: 规范化后的 AgentResult dict（JSON-safe）
            - fallback_text: 降级路径产生的原始文本（结构化路径为空字符串）
            - used_fallback: 是否走了文本降级
        """
        try:
            raw = await self.llm.structured_output(summary_messages, AgentResult)
            if raw and not raw.get("parse_error") and not raw.get("error"):
                structured = parse_agent_result(raw)
                # 补充 agent 元信息（LLM 不一定输出）
                structured["agent_id"] = self.agent_id
                structured["agent_name"] = self.config.name
                return structured, "", False
        except Exception as e:
            import logging
            logging.getLogger("secagentx.agent").debug(
                "Agent %s structured_output 失败，降级文本提取: %s", self.agent_id, e,
            )

        # 降级路径：流式文本 + 正则
        final = ""
        async for chunk in self.llm.chat_stream(summary_messages):
            final += chunk
        text = final or fallback_content or ""
        structured = parse_agent_result(self._parse_structured_verdict(text))
        structured["agent_id"] = self.agent_id
        structured["agent_name"] = self.config.name
        if not structured.get("summary_text"):
            structured["summary_text"] = text[:500]
        return structured, text, True

    @staticmethod
    def _build_agent_trace(results: list) -> list:
        """把工具执行结果整理为 agent_trace（含情报覆盖度，供确定性聚合）。"""
        trace = []
        for r in results:
            rdata = r.result if isinstance(r.result, dict) else {}
            trace.append({
                "tool": r.call.tool_name,
                "success": r.success,
                "duration_ms": r.duration_ms,
                "coverage": rdata.get("coverage"),
                "missing_sources": rdata.get("missing_sources", []),
            })
        return trace

    def _format_input(self, message: AgentMessage) -> str:
        if message.msg_type == MessageType.TASK_ASSIGN:
            parts = [f"## 任务: {message.payload.get('task', '')}"]
            if message.payload.get("params"):
                parts.append(f"\n参数: {json.dumps(message.payload['params'], ensure_ascii=False)}")
            if message.payload.get("context"):
                parts.append(f"\n上下文: {json.dumps(message.payload['context'], ensure_ascii=False)}")
            return "\n".join(parts)
        return message.payload.get("text", str(message.payload))

    # ═══════════════════════ 统一 Tool Calling ═══════════════════════

    async def process_with_tools(self, message: AgentMessage) -> AsyncGenerator[dict, None]:
        """
        使用 LLM Function Calling 处理消息（替代原 process_message 的纯文本方式）

        流程:
        1. 构建 system prompt + 用户消息
        2. 调用 LLM chat_with_tools() — LLM 决定是否调工具
        3. 有 tool_calls → 执行 → 注入 → LLM 最终回复
        4. 无 tool_calls → 直接返回文本
        """
        self.status = "busy"
        start = time.time()

        try:
            system_prompt = self.build_system_prompt(message.context)
            user_content = self._format_input(message)

            messages = [
                {"role": "system", "content": system_prompt},
                *self.conversation_history[-10:],
                {"role": "user", "content": user_content},
            ]
            # 上下文压缩（防 token 超限）
            messages = self._compact_context(messages)

            yield {
                "type": "agent_status",
                "agent_id": self.agent_id,
                "status": "thinking",
                "content": f"{self.config.name} 正在分析 (Tool Calling)...",
            }

            tools_def = build_tools_for_llm(self._get_allowed_tools().list_tools())
            has_tools = len(tools_def) > 0

            if not has_tools:
                full_response = ""
                async for chunk in self.llm.chat_stream(messages):
                    full_response += chunk
                    yield {"type": "stream", "agent_id": self.agent_id, "content": chunk}

                self._record_stats(full_response, start)
                structured = parse_agent_result(self._parse_structured_verdict(full_response))
                structured["agent_id"] = self.agent_id
                structured["agent_name"] = self.config.name
                yield {
                    "type": "agent_result",
                    "agent_id": self.agent_id,
                    "content": full_response,
                    "duration_ms": (time.time() - start) * 1000,
                    # 兼容迁移：旧字段保留
                    "structured": structured,
                    "tool_calls": [],
                    # 新增字段
                    "structured_result": structured,
                    "agent_trace": [],
                    "summary_text": structured.get("summary_text", ""),
                }
                return

            # 第一次 LLM 调用
            content, tool_calls_raw = await self.llm.chat_with_tools(
                messages, tools_def, tool_choice="auto",
            )

            if content:
                yield {
                    "type": "stream",
                    "agent_id": self.agent_id,
                    "content": content,
                }

            tool_calls = parse_tool_calls(
                {"choices": [{"message": {"tool_calls": tool_calls_raw}}]},
                source=f"agent:{self.agent_id}",
            )

            if tool_calls:
                for tc in tool_calls:
                    yield {
                        "type": "tool_call_start",
                        "agent_id": self.agent_id,
                        "tool_name": tc.tool_name,
                        "arguments": tc.arguments,
                        "content": (
                            f"  {self.config.name} 调用工具: **{tc.tool_name}**\n"
                            f"```json\n{json.dumps(tc.arguments, ensure_ascii=False, indent=2)}\n```\n"
                        ),
                    }

                results = await self.tool_engine.execute(tool_calls)

                for r in results:
                    icon = "[OK]" if r.success else "[FAIL]"
                    data_view = json.dumps(
                        r.result if r.success else {"error": r.error},
                        ensure_ascii=False, indent=2,
                    )[:500]
                    yield {
                        "type": "tool_call_result",
                        "agent_id": self.agent_id,
                        "tool_name": r.call.tool_name,
                        "success": r.success,
                        "content": (
                            f"  {icon} **{r.call.tool_name}** "
                            f"({'成功' if r.success else '失败'}) "
                            f"({r.duration_ms:.0f}ms)\n"
                            f"```json\n{data_view}\n```\n"
                        ),
                    }

                # 关键修复：OpenAI/DeepSeek 兼容 API 要求 role=tool 消息必须
                # 对应一条带 tool_calls 的 assistant 消息（且顺序在 tool 消息之前），
                # 否则返回 400 Bad Request。
                assistant_msg = {"role": "assistant", "content": content or ""}
                if tool_calls_raw:
                    assistant_msg["tool_calls"] = tool_calls_raw
                messages.append(assistant_msg)

                for r in results:
                    messages.append(r.to_llm_message())

                # 总结阶段：强制结构化 JSON 输出（structured_output），
                # 文本正则仅在 LLM 不配合时兜底 —— 输出格式由"文本内嵌 JSON"反转为"JSON 为主"。
                summary_messages = messages + [{
                    "role": "user",
                    "content": (
                        "基于以上工具结果，输出你的最终分析结论（json 格式，字段见系统提示）。"
                        "要求：不要调用任何工具，直接输出纯 JSON 对象。"
                    ),
                }]
                structured, fallback_text, used_fallback = await self._produce_structured_result(
                    summary_messages, fallback_content=content,
                )
                final_text = fallback_text or result_to_text(structured)
                # 向调用方输出渲染文本（老消费方展示不破坏）
                yield {"type": "stream", "agent_id": self.agent_id, "content": final_text}

                self._record_stats(final_text or content, start)
                agent_trace = self._build_agent_trace(results)
                structured["tool_calls"] = agent_trace

                yield {
                    "type": "agent_result",
                    "agent_id": self.agent_id,
                    "content": final_text,
                    "duration_ms": (time.time() - start) * 1000,
                    # 兼容迁移：旧字段保留
                    "structured": structured,
                    "tool_calls": agent_trace,
                    # 新增字段
                    "structured_result": structured,
                    "agent_trace": agent_trace,
                    "summary_text": structured.get("summary_text", ""),
                }
            else:
                # 无工具调用：同样强制结构化输出（LLM 可能已在首次回复给出裁决）
                summary_messages = messages + [{
                    "role": "user",
                    "content": (
                        "基于以上信息，输出你的最终分析结论（json 格式，字段见系统提示）。"
                        "要求：不要调用任何工具，直接输出纯 JSON 对象。"
                    ),
                }]
                structured, fallback_text, used_fallback = await self._produce_structured_result(
                    summary_messages, fallback_content=content,
                )
                final_text = fallback_text or result_to_text(structured)
                yield {"type": "stream", "agent_id": self.agent_id, "content": final_text}

                self._record_stats(final_text or content, start)
                yield {
                    "type": "agent_result",
                    "agent_id": self.agent_id,
                    "content": final_text,
                    "duration_ms": (time.time() - start) * 1000,
                    # 兼容迁移：旧字段保留
                    "structured": structured,
                    "tool_calls": [],
                    # 新增字段
                    "structured_result": structured,
                    "agent_trace": [],
                    "summary_text": structured.get("summary_text", ""),
                }

        except AgentError as e:
            self.stats["tasks_failed"] += 1
            yield {
                "type": "agent_error",
                "agent_id": self.agent_id,
                "error": str(e),
                "code": e.code,
                "recoverable": e.recoverable,
            }
        except Exception as e:
            self.stats["tasks_failed"] += 1
            # 记录完整堆栈，便于定位（此前只输出错误文本，无日志可查）
            import logging
            logging.getLogger("secagentx.agent").exception(
                "Agent %s 处理失败", self.agent_id,
                exc_info=True,
            )
            yield {
                "type": "agent_error",
                "agent_id": self.agent_id,
                "error": f"内部错误: {e}",
                "code": "UNKNOWN",
                "recoverable": False,
            }
        finally:
            self.status = "idle"

    def _record_stats(self, content: str, start: float):
        """记录完成统计

        Token 计算优先级:
          1. LLM API 返回的 total_tokens（最准确）
          2. LLM API 返回的 completion_tokens
          3. 降级：content 字符数 / 2（中英文混合场景比 UTF-8 字节/4 更准）
        """
        usage = getattr(self._llm, "last_usage", None)
        if usage is None:
            usage = {}
        real_tokens = 0
        if usage.get("total_tokens") is not None:
            real_tokens = int(usage["total_tokens"])
        elif usage.get("completion_tokens") is not None:
            real_tokens = int(usage["completion_tokens"])

        if real_tokens <= 0:
            # 降级：中英文混合场景，字符数/2 ≈ token 数
            # 英文约 1 token/4 字符，中文约 1 token/1.5 字符
            # 按安全场景中英文混合估算，使用 /2 作为折中
            real_tokens = max(len(content) // 2, 1)

        self.stats["total_tokens"] += real_tokens
        self.stats["last_tokens"] = real_tokens
        self.stats["tasks_completed"] += 1
        elapsed = (time.time() - start) * 1000
        self.stats["total_duration_ms"] += elapsed
        self.stats["last_duration_ms"] = int(elapsed)

