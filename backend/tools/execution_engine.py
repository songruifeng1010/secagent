"""
UnifiedToolCallEngine — 统一工具调用执行引擎

职责:
1. 接收 ToolCall 列表（来自 LLM function calling）
2. Schema 校验参数（检查必要参数/参数类型）
3. 并行执行无依赖工具
4. 格式化结果并记录审计历史
5. 提供高阶接口 execute_and_feed_to_llm() （执行+注入+返回答复）
"""
import time
import json
import asyncio
from typing import Optional

from .base import ToolResult
from .registry import ToolRegistry
from .calling import (
    ToolCall, ToolCallResult, ToolCallHistory,
    format_tool_result_for_llm,
)


class UnifiedToolCallEngine:
    """
    统一工具调用执行引擎

    使用方式:
        engine = UnifiedToolCallEngine(registry)

        # 执行工具
        results = await engine.execute(tool_calls)

        # 转成 LLM tool 消息
        tool_messages = [r.to_llm_message() for r in results]

        # 注入消息列表
        messages.extend(tool_messages)

        # 再调 LLM 获取最终回复
        final = await llm.chat(messages)
    """

    def __init__(self, tools: Optional[ToolRegistry] = None):
        self.tools = tools or ToolRegistry()
        self.history = ToolCallHistory()

    async def execute(self, tool_calls: list[ToolCall]) -> list[ToolCallResult]:
        """
        执行工具调用列表

        策略:
        - 所有工具并行执行（asyncio.gather）
        - 需要串行依赖？由调用方（Planner/Agent）分批次传入

        Args:
            tool_calls: 解析后的工具调用列表

        Returns:
            list[ToolCallResult]: 执行结果（顺序与输入一致）
        """
        if not tool_calls:
            return []

        # Step 1: Schema 校验
        validated = self._validate_all(tool_calls)

        # Step 2: 并行执行合法调用
        valid_tasks = [
            self._execute_single(tc)
            for tc, is_ok in validated
            if is_ok
        ]

        valid_results = await asyncio.gather(*valid_tasks)

        # Step 3: 合并非法调用（标记为失败）
        all_results = []
        vi = 0
        for tc, is_ok in validated:
            if is_ok:
                result = valid_results[vi]
                all_results.append(result)
                self.history.add(result)
                vi += 1
            else:
                tool = self.tools.get(tc.tool_name)
                if tool is None:
                    validation_error = f"工具不存在: {tc.tool_name}"
                else:
                    required = tool.parameters.get("required", [])
                    properties = tool.parameters.get("properties", {})
                    missing = [p for p in required if p not in tc.arguments]
                    unknown = [p for p in tc.arguments if p not in properties]
                    issues = []
                    if missing:
                        issues.append(f"缺少必填参数 {missing}")
                    if unknown:
                        issues.append(f"包含未声明参数 {unknown}")
                    validation_error = "，".join(issues) or "参数不符合工具 schema"
                result = ToolCallResult(
                    call=tc,
                    success=False,
                    error=f"参数校验失败: {validation_error}",
                    duration_ms=0,
                    formatted_for_llm=(
                        f"工具 [{tc.tool_name}] 调用被拒绝: "
                        f"{validation_error}。请检查参数后再试。"
                    ),
                )
                all_results.append(result)
                self.history.add(result)

        return all_results

    def _validate_all(self, tool_calls: list[ToolCall]) -> list[tuple]:
        """
        批量校验

        Returns:
            list[(ToolCall, is_valid)]
        """
        validated = []
        for tc in tool_calls:
            tool = self.tools.get(tc.tool_name)
            if tool is None:
                validated.append((tc, False))
                continue

            required = tool.parameters.get("required", [])
            properties = tool.parameters.get("properties", {})
            missing = [p for p in required if p not in tc.arguments]
            unknown = [p for p in tc.arguments if p not in properties]
            if missing or unknown:
                validated.append((tc, False))
                continue

            validated.append((tc, True))

        return validated

    async def _execute_single(self, tc: ToolCall) -> ToolCallResult:
        """执行单个工具调用"""
        start = time.time()

        try:
            result: ToolResult = await self.tools.execute(
                tc.tool_name, **tc.arguments
            )
            elapsed = (time.time() - start) * 1000

            formatted = format_tool_result_for_llm(tc.tool_name, result)

            return ToolCallResult(
                call=tc,
                success=result.success,
                result=result.data if result.success else None,
                error=result.error if not result.success else "",
                duration_ms=result.duration_ms or elapsed,
                formatted_for_llm=formatted,
            )

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return ToolCallResult(
                call=tc,
                success=False,
                error=str(e),
                duration_ms=elapsed,
                formatted_for_llm=f"工具 [{tc.tool_name}] 执行异常: {e}",
            )

    async def execute_and_feed_to_llm(
        self,
        tool_calls: list[ToolCall],
        llm,
        messages: list[dict],
    ) -> tuple[list[ToolCallResult], str]:
        """
        高阶接口: 执行工具 + 注入结果 + 获取 LLM 最终回复

        Args:
            tool_calls: 工具调用列表
            llm: LLMInterface 实例
            messages: 当前消息列表（会被追加 tool 消息）

        Returns:
            (results, final_text)
        """
        results = await self.execute(tool_calls)

        for r in results:
            messages.append(r.to_llm_message())

        response = await llm.chat(messages)
        return results, response.content

    def get_history(self) -> ToolCallHistory:
        return self.history

    def clear_history(self):
        self.history = ToolCallHistory()
