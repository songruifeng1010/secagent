"""
统一 Tool Calling 核心模块

标准化的 ToolCall 请求/响应数据模型，
以及 LLM Function Calling 格式 ↔ 内部工具系统的适配层。
"""
import json
import uuid
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from .base import BaseTool, ToolResult


# ═══════════════════════ 标准化数据模型 ═══════════════════════

@dataclass
class ToolCall:
    """
    一次工具调用的完整请求记录

    由 LLM 的 tool_calls 解析而来。
    """
    call_id: str = field(default="")       # 对应 LLM 返回的 tool_call_id
    tool_name: str = field(default="")     # 工具名（如 "threat_intel"）
    arguments: dict = field(default_factory=dict)  # 解析后的参数字典
    raw_arguments: str = ""               # LLM 返回的原始 JSON 字符串
    timestamp: float = 0.0                # 创建时间
    source: str = ""                      # 来源标识（"planner" / "agent:analyst" / "react"）
    round_number: int = 0                 # ReAct 轮次

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.call_id:
            self.call_id = f"tc_{uuid.uuid4().hex[:12]}"


@dataclass
class ToolCallResult:
    """一次工具调用的完整结果记录"""
    call: ToolCall
    success: bool = False
    result: Any = None
    error: str = ""
    duration_ms: float = 0.0
    formatted_for_llm: str = ""

    def to_llm_message(self) -> dict:
        """转换为 OpenAI 兼容的 tool 角色消息"""
        content = self.formatted_for_llm or json.dumps(
            {"success": self.success, "result": self.result, "error": self.error},
            ensure_ascii=False,
        )
        return {
            "role": "tool",
            "tool_call_id": self.call.call_id,
            "content": content,
        }


@dataclass
class ToolCallHistory:
    """完整工具调用历史（可用于审计和回放）"""
    MAX_HISTORY = 5000  # 最多保留 5000 条，防止 OOM
    calls: list[ToolCallResult] = field(default_factory=list)

    def add(self, result: ToolCallResult):
        self.calls.append(result)
        if len(self.calls) > self.MAX_HISTORY:
            # 保留最新的 80%
            self.calls = self.calls[-self.MAX_HISTORY:]

    def to_dict(self) -> list[dict]:
        return [
            {
                "call_id": r.call.call_id,
                "tool": r.call.tool_name,
                "arguments": r.call.arguments,
                "success": r.success,
                "duration_ms": r.duration_ms,
                "source": r.call.source,
                "round": r.call.round_number,
            }
            for r in self.calls
        ]

    @property
    def total_calls(self) -> int:
        return len(self.calls)

    @property
    def failed_calls(self) -> list[ToolCallResult]:
        return [r for r in self.calls if not r.success]


# ═══════════════════════ LLM 适配函数 ═══════════════════════

def build_tools_for_llm(tools: list[BaseTool]) -> list[dict]:
    """
    将内部工具列表转换为 OpenAI 兼容的 tools 参数格式

    输出示例:
    [{
        "type": "function",
        "function": {
            "name": "threat_intel",
            "description": "查询IP/域名/哈希的威胁情报",
            "parameters": {"type": "object", "properties": {...}, "required": [...]}
        }
    }]
    """
    return [t.to_openai_function() for t in tools]


def parse_tool_calls(
    llm_response: dict,
    source: str = "",
    round_number: int = 0,
) -> list[ToolCall]:
    """
    从 LLM 响应中解析 tool_calls

    兼容:
    - OpenAI 标准格式: choices[0].message.tool_calls[]
    - DeepSeek 格式: 同上（兼容 OpenAI）
    - Function_call 旧格式: choices[0].message.function_call（兼容遗留）

    Args:
        llm_response: LLM API 返回的完整 JSON 响应
        source: 来源标识
        round_number: ReAct 轮次

    Returns:
        list[ToolCall]: 解析后的调用列表（可能为空）
    """
    raw_calls = []

    try:
        message = llm_response["choices"][0]["message"]

        # 标准 OpenAI 格式
        if "tool_calls" in message and message["tool_calls"]:
            raw_calls = message["tool_calls"]
        # 兼容旧版 function_call（部分 provider 仍返回这个）
        elif "function_call" in message and message["function_call"]:
            fc = message["function_call"]
            raw_calls = [{
                "id": f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {
                    "name": fc.get("name", ""),
                    "arguments": fc.get("arguments", "{}"),
                },
            }]
    except (KeyError, IndexError, TypeError):
        return []

    tool_calls = []
    for tc in raw_calls:
        try:
            raw_args = tc.get("function", {}).get("arguments", "{}")
            if isinstance(raw_args, str):
                arguments = json.loads(raw_args)
            else:
                arguments = raw_args

            tool_calls.append(ToolCall(
                call_id=tc.get("id", f"tc_{uuid.uuid4().hex[:12]}"),
                tool_name=tc.get("function", {}).get("name", ""),
                arguments=arguments,
                raw_arguments=raw_args if isinstance(raw_args, str)
                              else json.dumps(raw_args, ensure_ascii=False),
                source=source,
                round_number=round_number,
            ))
        except (json.JSONDecodeError, KeyError, TypeError):
            # 参数解析失败——保留记录但 arguments 为空
            tool_calls.append(ToolCall(
                call_id=tc.get("id", f"tc_{uuid.uuid4().hex[:12]}"),
                tool_name=tc.get("function", {}).get("name", ""),
                arguments={},
                raw_arguments=str(tc.get("function", {}).get("arguments", "{}")),
                source=source,
                round_number=round_number,
            ))

    return tool_calls


def format_tool_result_for_llm(tool_name: str, result: ToolResult) -> str:
    """
    将工具执行结果格式化为 LLM 可读的文本

    规则:
    - 成功: 结构化展示关键字段，超过 3000 字符截断
    - 失败: 清晰说明错误原因
    """
    if result.success:
        data = result.data or {}
        data_str = json.dumps(data, ensure_ascii=False, indent=2)
        if len(data_str) > 3000:
            data_str = data_str[:3000] + f"\n... (truncated, {len(data_str)} total)"
        return f"工具 [{tool_name}] 执行成功 ({result.duration_ms:.0f}ms):\n{data_str}"
    else:
        return f"工具 [{tool_name}] 执行失败: {result.error}"

