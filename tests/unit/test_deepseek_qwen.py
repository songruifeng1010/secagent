"""
DeepSeek & Qwen LLM Provider 单元测试

覆盖:
  - Provider 创建与配置
  - chat / chat_stream / structured_output / chat_with_tools
  - HTTP Mock 模拟真实 API 调用
  - 错误处理与超时
"""

import json
import pytest
import httpx


class TestDeepSeekProvider:
    """DeepSeek Provider 单元测试"""

    def test_provider_creation(self):
        """创建 DeepSeek Provider"""
        from backend.llm.deepseek import DeepSeekProvider
        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        assert provider is not None
        assert provider.config.model == "deepseek-chat"
        assert provider.config.api_base == "https://api.deepseek.com/v1"

    def test_provider_custom_config(self):
        """自定义配置"""
        from backend.llm.deepseek import DeepSeekProvider
        provider = DeepSeekProvider({
            "api_key": "sk-custom",
            "api_base": "https://custom.api.com/v1",
            "model": "custom-model",
            "temperature": 0.5,
            "max_tokens": 2048,
        })
        assert provider.config.api_base == "https://custom.api.com/v1"
        assert provider.config.model == "custom-model"
        assert provider.config.temperature == 0.5
        assert provider.config.max_tokens == 2048

    @pytest.mark.asyncio
    async def test_chat_success(self, monkeypatch):
        """chat 成功返回"""
        from backend.llm.deepseek import DeepSeekProvider

        async def mock_post(self, path, **kwargs):
            return _make_response(200, {
                "choices": [{"message": {"content": "这是DeepSeek的回复"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                "model": "deepseek-chat",
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        result = await provider.chat([{"role": "user", "content": "你好"}])
        assert result.content == "这是DeepSeek的回复"
        assert result.usage["total_tokens"] == 30
        assert result.model == "deepseek-chat"

    @pytest.mark.asyncio
    async def test_chat_stream(self, monkeypatch):
        """chat_stream 流式返回"""
        from backend.llm.deepseek import DeepSeekProvider

        class MockStreamClient:
            """Mock httpx.AsyncClient"""

            def stream(self, method, url, **kwargs):
                """httpx.AsyncClient.stream 是同步函数，返回上下文管理器"""
                class MockResp:
                    async def __aenter__(s):
                        return s
                    async def __aexit__(s, *args):
                        pass
                    def raise_for_status(self):
                        pass
                    async def aiter_lines(self):
                        yield 'data: {"choices":[{"delta":{"content":"你好"}}]}'
                        yield 'data: {"choices":[{"delta":{"content":"世界"}}]}'
                        yield 'data: {"choices":[{"delta":{}}], "usage": {"total_tokens": 5}}'
                        yield 'data: [DONE]'
                return MockResp()

            async def post(self, path, **kwargs):
                return _make_response(200, {})

            async def aclose(self):
                pass

        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        provider._http_client = MockStreamClient()
        chunks = []
        async for chunk in provider.chat_stream([{"role": "user", "content": "hello"}]):
            chunks.append(chunk)
        assert len(chunks) >= 2
        assert "你好" in chunks[0]

    @pytest.mark.asyncio
    async def test_chat_api_error(self, monkeypatch):
        """API 错误时抛出异常"""
        from backend.llm.deepseek import DeepSeekProvider

        async def mock_post(self, path, **kwargs):
            request = httpx.Request("POST", "http://test")
            raise httpx.HTTPStatusError(
                "401 Unauthorized",
                request=request,
                response=httpx.Response(401, request=request),
            )

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        provider = DeepSeekProvider({"api_key": "sk-wrong-key"})
        with pytest.raises(httpx.HTTPStatusError):
            await provider.chat([{"role": "user", "content": "test"}])

    @pytest.mark.asyncio
    async def test_structured_output(self, monkeypatch):
        """结构化输出"""
        from backend.llm.deepseek import DeepSeekProvider
        from pydantic import BaseModel

        class TestResponse(BaseModel):
            name: str
            score: int

        async def mock_post(self, path, **kwargs):
            return _make_response(200, {
                "choices": [{"message": {"content": '{"name": "test", "score": 95}'}, "finish_reason": "stop"}],
                "usage": {},
                "model": "deepseek-chat",
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        result = await provider.structured_output(
            [{"role": "user", "content": "analyze"}],
            TestResponse,
        )
        assert result["name"] == "test"
        assert result["score"] == 95

    @pytest.mark.asyncio
    async def test_chat_with_tools(self, monkeypatch):
        """工具调用"""
        from backend.llm.deepseek import DeepSeekProvider

        async def mock_post(self, path, **kwargs):
            return _make_response(200, {
                "choices": [{
                    "message": {
                        "content": "",
                        "tool_calls": [{
                            "id": "call_001",
                            "type": "function",
                            "function": {"name": "test_tool", "arguments": '{"ip": "8.8.8.8"}'},
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
                "usage": {},
                "model": "deepseek-chat",
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        content, tool_calls = await provider.chat_with_tools(
            [{"role": "user", "content": "查询IP"}],
            [{"type": "function", "function": {"name": "test_tool", "parameters": {}}}],
        )
        assert content == ""
        assert len(tool_calls) == 1
        assert tool_calls[0]["function"]["name"] == "test_tool"

    @pytest.mark.asyncio
    async def test_chat_with_tools_stream(self, monkeypatch):
        """流式工具调用"""
        from backend.llm.deepseek import DeepSeekProvider

        # stream 必须是同步函数（httpx.AsyncClient.stream 是同步的）
        class MockStreamClient:
            def stream(self, method, url, **kwargs):
                class MockResp:
                    async def __aenter__(s):
                        return s
                    async def __aexit__(s, *args):
                        pass
                    def raise_for_status(self):
                        pass
                    async def aiter_lines(self):
                        yield 'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"test_tool"}}]}}]}'
                        yield 'data: {"choices":[{"delta":{}}]}'
                        yield 'data: [DONE]'
                return MockResp()
            async def post(self, path, **kwargs):
                return _make_response(200, {})
            async def aclose(self):
                pass

        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        provider._http_client = MockStreamClient()
        chunks = []
        async for chunk in provider.chat_with_tools_stream(
            [{"role": "user", "content": "query"}],
            [{"type": "function", "function": {"name": "test_tool", "parameters": {}}}],
        ):
            chunks.append(chunk)
        assert len(chunks) > 0

    def test_last_usage(self):
        """最后调用的 token 统计"""
        from backend.llm.deepseek import DeepSeekProvider
        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        assert provider.last_usage == {}

    @pytest.mark.asyncio
    async def test_close(self):
        """关闭客户端"""
        from backend.llm.deepseek import DeepSeekProvider
        provider = DeepSeekProvider({"api_key": "not-a-real-provider-key"})
        await provider.close()
        assert provider._http_client is None


def _make_response(status_code, json_data):
    """创建带 request 的 httpx.Response，避免 raise_for_status 报错"""
    request = httpx.Request("POST", "http://test")
    return httpx.Response(status_code, json=json_data, request=request)




class TestQwenProvider:
    """Qwen Provider 单元测试"""

    def test_provider_creation(self):
        """创建 Qwen Provider"""
        from backend.llm.qwen import QwenProvider
        provider = QwenProvider({"api_key": "not-a-real-provider-key"})
        assert provider is not None
        assert provider.config.model is not None
        assert len(provider.config.model) > 0

    def test_provider_custom_config(self):
        """自定义配置"""
        from backend.llm.qwen import QwenProvider
        provider = QwenProvider({
            "api_key": "sk-custom",
            "api_base": "https://custom.api.com",
            "model": "qwen-custom",
        })
        assert provider.config.api_base == "https://custom.api.com"
        assert provider.config.model == "qwen-custom"

    @pytest.mark.asyncio
    async def test_chat_success(self, monkeypatch):
        """chat 成功返回"""
        from backend.llm.qwen import QwenProvider

        async def mock_post(self, path, **kwargs):
            return _make_response(200, {
                "choices": [{"message": {"content": "Qwen回复内容"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 10},
                "model": "qwen-max",
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        provider = QwenProvider({"api_key": "not-a-real-provider-key"})
        result = await provider.chat([{"role": "user", "content": "你好"}])
        assert result.content == "Qwen回复内容"
        assert result.usage["prompt_tokens"] == 5

    @pytest.mark.asyncio
    async def test_chat_with_tools(self, monkeypatch):
        """工具调用"""
        from backend.llm.qwen import QwenProvider

        async def mock_post(self, path, **kwargs):
            return _make_response(200, {
                "choices": [{
                    "message": {
                        "content": "",
                        "tool_calls": [{
                            "id": "call_001",
                            "type": "function",
                            "function": {"name": "firewall", "arguments": '{"ip": "1.2.3.4"}'},
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
                "usage": {},
                "model": "qwen-max",
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        provider = QwenProvider({"api_key": "not-a-real-provider-key"})
        content, tool_calls = await provider.chat_with_tools(
            [{"role": "user", "content": "封禁IP"}],
            [{"type": "function", "function": {"name": "firewall", "parameters": {}}}],
        )
        assert len(tool_calls) == 1
        assert tool_calls[0]["function"]["name"] == "firewall"

    @pytest.mark.asyncio
    async def test_chat_stream(self, monkeypatch):
        """流式返回"""
        from backend.llm.qwen import QwenProvider

        class MockStreamClient:
            def stream(self, method, url, **kwargs):
                class MockResp:
                    async def __aenter__(self):
                        return self
                    async def __aexit__(self, *args):
                        pass
                    def raise_for_status(self):
                        pass
                    async def aiter_lines(self):
                        yield 'data: {"choices":[{"delta":{"content":"流式"}}]}'
                        yield 'data: {"choices":[{"delta":{"content":"回复"}}]}'
                        yield 'data: [DONE]'
                return MockResp()
            async def post(self, path, **kwargs):
                return _make_response(200, {})
            async def aclose(self):
                pass

        provider = QwenProvider({"api_key": "not-a-real-provider-key"})
        provider._http_client = MockStreamClient()
        chunks = []
        async for chunk in provider.chat_stream([{"role": "user", "content": "hello"}]):
            chunks.append(chunk)
        assert len(chunks) == 2
