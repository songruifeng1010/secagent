from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, AsyncGenerator


@dataclass
class LLMConfig:
    api_base: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout_seconds: float = 30.0  # 请求超时（秒）


@dataclass
class LLMResponse:
    content: str = ""
    usage: dict = field(default_factory=dict)
    model: str = ""
    finish_reason: str = ""


class LLMInterface(ABC):
    config: LLMConfig
    _last_usage: dict = {}

    @property
    def last_usage(self) -> dict:
        """最后一次调用的 token 使用统计"""
        return self._last_usage or {}

    @abstractmethod
    async def chat(self, messages: list[dict], stream: bool = False) -> LLMResponse:
        ...

    @abstractmethod
    async def chat_stream(self, messages: list[dict]) -> AsyncGenerator[str, None]:
        ...

    @abstractmethod
    async def structured_output(self, messages: list[dict], response_model: type) -> dict:
        ...

    @abstractmethod
    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> tuple[str, list[dict]]:
        """
        带工具调用的对话

        Args:
            messages: 对话消息列表
            tools: OpenAI 兼容的工具定义（由 build_tools_for_llm 生成）
            tool_choice: "auto" / "none" / "required"

        Returns:
            (content, tool_calls_raw)
            - content: 文本回复（可能为空）
            - tool_calls_raw: 原始 tool_calls 列表（message["tool_calls"]）
        """
        ...

    async def chat_with_tools_stream(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> AsyncGenerator[dict, None]:
        """
        流式版本

        Yields:
            {"type": "text", "content": "..."}
            {"type": "tool_calls", "tool_calls": [...]}
        """
        yield  # pragma: no cover

