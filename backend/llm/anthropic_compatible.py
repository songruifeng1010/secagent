"""Anthropic Messages API 兼容 Provider。"""

from __future__ import annotations

import json
from typing import AsyncGenerator, Optional

import httpx

from .base import LLMConfig, LLMInterface, LLMResponse


class AnthropicCompatibleProvider(LLMInterface):
    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.config = LLMConfig(
            api_base=str(cfg.get("api_base", "https://api.anthropic.com/v1")).rstrip("/"),
            api_key=cfg.get("api_key", ""),
            model=cfg.get("model", ""),
            temperature=float(cfg.get("temperature", 0.1)),
            max_tokens=int(cfg.get("max_tokens", 4096)),
            timeout_seconds=float(cfg.get("timeout_seconds", 60)),
        )
        if not self.config.model:
            raise ValueError("Anthropic 兼容 Provider 缺少 model")
        self._http_client: Optional[httpx.AsyncClient] = None
        self._last_usage = {}

    @property
    def client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=self.config.api_base,
                timeout=self.config.timeout_seconds,
                headers={
                    "x-api-key": self.config.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
            )
        return self._http_client

    @staticmethod
    def _convert_messages(messages: list[dict]) -> tuple[str, list[dict]]:
        systems: list[str] = []
        converted: list[dict] = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "") or ""
            if role == "system":
                systems.append(content)
                continue
            if role == "tool":
                converted.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": message.get("tool_call_id", ""),
                        "content": content,
                    }],
                })
                continue
            blocks: list[dict] = []
            if content:
                blocks.append({"type": "text", "text": content})
            for call in message.get("tool_calls", []) or []:
                function = call.get("function", {})
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {"raw": function.get("arguments", "")}
                blocks.append({
                    "type": "tool_use",
                    "id": call.get("id", ""),
                    "name": function.get("name", ""),
                    "input": arguments,
                })
            converted.append({"role": role if role in ("user", "assistant") else "user", "content": blocks or " "})
        return "\n\n".join(systems), converted

    def _payload(self, messages: list[dict], *, stream: bool = False, tools: Optional[list[dict]] = None) -> dict:
        system, converted = self._convert_messages(messages)
        payload = {
            "model": self.config.model,
            "messages": converted,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": stream,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [
                {
                    "name": item.get("function", {}).get("name", ""),
                    "description": item.get("function", {}).get("description", ""),
                    "input_schema": item.get("function", {}).get("parameters", {"type": "object"}),
                }
                for item in tools
            ]
        return payload

    @staticmethod
    def _parse_response(data: dict) -> tuple[str, list[dict]]:
        texts: list[str] = []
        tool_calls: list[dict] = []
        for block in data.get("content", []) or []:
            if block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append({
                    "id": block.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": block.get("name", ""),
                        "arguments": json.dumps(block.get("input", {}), ensure_ascii=False),
                    },
                })
        return "".join(texts), tool_calls

    async def chat(self, messages: list[dict], stream: bool = False) -> LLMResponse:
        response = await self.client.post("/messages", json=self._payload(messages, stream=False))
        response.raise_for_status()
        data = response.json()
        content, _ = self._parse_response(data)
        self._last_usage = data.get("usage", {})
        return LLMResponse(
            content=content,
            usage=self._last_usage,
            model=data.get("model", self.config.model),
            finish_reason=data.get("stop_reason", ""),
        )

    async def chat_stream(self, messages: list[dict]) -> AsyncGenerator[str, None]:
        async with self.client.stream("POST", "/messages", json=self._payload(messages, stream=True)) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                try:
                    event = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "content_block_delta":
                    delta = event.get("delta", {})
                    if delta.get("type") == "text_delta" and delta.get("text"):
                        yield delta["text"]
                elif event.get("type") == "message_delta" and event.get("usage"):
                    self._last_usage = event["usage"]

    async def structured_output(self, messages: list[dict], response_model: type) -> dict:
        request = list(messages) + [{
            "role": "user",
            "content": "只返回一个合法 JSON 对象，不要使用 Markdown 代码围栏。",
        }]
        response = await self.chat(request)
        try:
            parsed = json.loads(response.content)
        except json.JSONDecodeError:
            from ..models.output import repair_json_object
            parsed = repair_json_object(response.content) or {"raw": response.content, "error": "failed_to_parse"}
        if response_model and hasattr(response_model, "model_validate"):
            try:
                return response_model.model_validate(parsed).model_dump()
            except Exception:
                return parsed
        return parsed

    async def chat_with_tools(self, messages: list[dict], tools: list[dict], tool_choice: str = "auto") -> tuple[str, list[dict]]:
        payload = self._payload(messages, tools=tools)
        if tool_choice == "none":
            payload.pop("tools", None)
        elif tool_choice == "required":
            payload["tool_choice"] = {"type": "any"}
        response = await self.client.post("/messages", json=payload)
        response.raise_for_status()
        data = response.json()
        self._last_usage = data.get("usage", {})
        return self._parse_response(data)

    async def chat_with_tools_stream(self, messages: list[dict], tools: list[dict], tool_choice: str = "auto") -> AsyncGenerator[dict, None]:
        content, calls = await self.chat_with_tools(messages, tools, tool_choice)
        if content:
            yield {"type": "text", "content": content}
        if calls:
            yield {"type": "tool_calls", "tool_calls": calls}

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
