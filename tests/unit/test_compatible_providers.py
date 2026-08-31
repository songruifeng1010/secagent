import json

import httpx
import pytest

from backend.llm.anthropic_compatible import AnthropicCompatibleProvider
from backend.llm.openai_compatible import OpenAICompatibleProvider


@pytest.mark.asyncio
async def test_openai_compatible_chat_uses_configured_endpoint_and_auth():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["payload"] = json.loads(request.content)
        return httpx.Response(200, json={
            "model": "corp-model",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 3},
        })

    provider = OpenAICompatibleProvider({
        "api_base": "https://gateway.example/v1",
        "api_key": "secret",
        "model": "corp-model",
    })
    provider._http_client = httpx.AsyncClient(
        base_url=provider.config.api_base,
        headers={"Authorization": "Bearer secret"},
        transport=httpx.MockTransport(handler),
    )
    try:
        response = await provider.chat([{"role": "user", "content": "ping"}])
    finally:
        await provider.close()

    assert response.content == "ok"
    assert seen == {
        "path": "/v1/chat/completions",
        "auth": "Bearer secret",
        "payload": {
            "model": "corp-model",
            "messages": [{"role": "user", "content": "ping"}],
            "temperature": 0.1,
            "max_tokens": 4096,
            "stream": False,
        },
    }


@pytest.mark.asyncio
async def test_anthropic_converts_system_and_tool_calls():
    seen = {}

    def handler(request):
        seen["payload"] = json.loads(request.content)
        seen["key"] = request.headers.get("x-api-key")
        return httpx.Response(200, json={
            "model": "claude-test",
            "content": [
                {"type": "text", "text": "checking"},
                {"type": "tool_use", "id": "tool-1", "name": "lookup", "input": {"ip": "8.8.8.8"}},
            ],
            "usage": {"input_tokens": 5, "output_tokens": 2},
            "stop_reason": "tool_use",
        })

    provider = AnthropicCompatibleProvider({
        "api_base": "https://anthropic.example/v1",
        "api_key": "anthropic-secret",
        "model": "claude-test",
    })
    provider._http_client = httpx.AsyncClient(
        base_url=provider.config.api_base,
        headers={"x-api-key": "anthropic-secret"},
        transport=httpx.MockTransport(handler),
    )
    tools = [{"type": "function", "function": {
        "name": "lookup", "description": "lookup ip",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}},
    }}]
    try:
        content, calls = await provider.chat_with_tools([
            {"role": "system", "content": "secure"},
            {"role": "user", "content": "check"},
        ], tools)
    finally:
        await provider.close()

    assert content == "checking"
    assert calls[0]["function"]["name"] == "lookup"
    assert seen["key"] == "anthropic-secret"
    assert seen["payload"]["system"] == "secure"
    assert seen["payload"]["tools"][0]["input_schema"]["type"] == "object"
