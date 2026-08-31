import json
import httpx
from typing import AsyncGenerator, Optional
from .base import LLMInterface, LLMConfig, LLMResponse


class QwenProvider(LLMInterface):
    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.config = LLMConfig(
            api_base=cfg.get("api_base", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
            api_key=cfg.get("api_key", ""),
            model=cfg.get("model", "qwen2.5-72b-instruct"),
            temperature=cfg.get("temperature", 0.3),
            max_tokens=cfg.get("max_tokens", 4096),
        )
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=self.config.api_base,
                timeout=self.config.timeout_seconds,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._http_client

    async def chat(self, messages: list[dict], stream: bool = False) -> LLMResponse:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": stream,
        }
        resp = await self.client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]
        return LLMResponse(
            content=choice["message"]["content"],
            usage=data.get("usage", {}),
            model=data.get("model", self.config.model),
            finish_reason=choice.get("finish_reason", ""),
        )

    async def chat_stream(self, messages: list[dict]) -> AsyncGenerator[str, None]:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }
        self._last_usage = {}
        async with self.client.stream("POST", "/chat/completions", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:]
                if chunk == "[DONE]":
                    break
                try:
                    data = json.loads(chunk)
                    if "usage" in data and data["usage"]:
                        self._last_usage = data["usage"]
                    delta = data["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        yield content
                except json.JSONDecodeError:
                    continue

    async def structured_output(self, messages: list[dict], response_model: type = None) -> dict:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": self.config.max_tokens,
            "response_format": {"type": "json_object"},
        }
        resp = await self.client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]

        json_start = content.find("{")
        json_end = content.rfind("}")
        if json_start != -1 and json_end != -1:
            try:
                return json.loads(content[json_start : json_end + 1])
            except json.JSONDecodeError:
                pass

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # 容错修复：剥围栏/去尾逗号等，仍失败才返回失败标记
            from ..models.output import repair_json_object
            repaired = repair_json_object(content)
            if repaired:
                return repaired
            return {"raw": content, "parse_error": True}

    # ═══════════════════════ Function Calling ═══════════════════════

    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> tuple[str, list[dict]]:
        """
        Qwen Function Calling

        通义千问 DashScope 兼容模式支持 OpenAI 格式的 tools 参数。
        """
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "tools": tools,
            "tool_choice": tool_choice,
        }

        resp = await self.client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()

        message = data["choices"][0].get("message", {})
        content = message.get("content", "") or ""
        tool_calls = message.get("tool_calls", [])

        if "usage" in data:
            self._last_usage = data["usage"]

        return content, tool_calls

    async def chat_with_tools_stream(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> AsyncGenerator[dict, None]:
        """
        Qwen 流式 Function Calling
        """
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "tools": tools,
            "tool_choice": tool_choice,
            "stream": True,
        }

        self._last_usage = {}
        tool_calls_acc: dict[int, dict] = {}

        async with self.client.stream(
            "POST", "/chat/completions", json=payload
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:]
                if chunk == "[DONE]":
                    break
                try:
                    data = json.loads(chunk)
                    if "usage" in data and data["usage"]:
                        self._last_usage = data["usage"]

                    delta = data["choices"][0].get("delta", {})

                    content = delta.get("content", "")
                    if content:
                        yield {"type": "text", "content": content}

                    for tc in delta.get("tool_calls", []):
                        idx = tc.get("index", 0)
                        if idx not in tool_calls_acc:
                            tool_calls_acc[idx] = {
                                "id": tc.get("id", ""),
                                "type": "function",
                                "function": {"name": "", "arguments": ""},
                            }
                        if tc.get("id"):
                            tool_calls_acc[idx]["id"] = tc["id"]
                        if "function" in tc:
                            fn = tc["function"]
                            if fn.get("name"):
                                tool_calls_acc[idx]["function"]["name"] += fn["name"]
                            if fn.get("arguments"):
                                tool_calls_acc[idx]["function"]["arguments"] += fn["arguments"]

                except json.JSONDecodeError:
                    continue

        if tool_calls_acc:
            sorted_calls = [
                tool_calls_acc[i] for i in sorted(tool_calls_acc.keys())
            ]
            yield {"type": "tool_calls", "tool_calls": sorted_calls}

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

