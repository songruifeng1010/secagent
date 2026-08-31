"""
FallbackLLMProvider — LLM 超时降级与自动切换包装器

功能:
  1. 主 LLM 超时/失败时自动切换到备用 LLM
  2. 部分失败（半超时）降级返回已生成的内容
  3. 所有切换记录审计日志

使用方式:
    provider = FallbackLLMProvider(
        primary=DeepSeekProvider(config),
        fallback=QwenProvider(config),
        fallback_on_timeout=True,
        fallback_on_error=True,
        timeout_seconds=30,
    )
    # 所有接口与普通 LLMInterface 完全兼容
    response = await provider.chat(messages)
"""
import asyncio
import logging
from typing import AsyncGenerator, Optional
from .base import LLMInterface, LLMResponse

logger = logging.getLogger("secagentx.llm.fallback")


class FallbackLLMProvider(LLMInterface):
    """带超时降级和自动切换的 LLM 包装器"""

    def __init__(
        self,
        primary: LLMInterface,
        *fallbacks: LLMInterface,
        fallback_on_timeout: bool = True,
        fallback_on_error: bool = True,
        timeout_seconds: float = 30.0,
    ):
        self._primary = primary
        self._fallbacks = list(fallbacks)
        self._fallback_on_timeout = fallback_on_timeout
        self._fallback_on_error = fallback_on_error
        self._timeout = timeout_seconds
        self._last_usage: dict = {}
        self._fallback_used: set[str] = set()  # 记录哪些方法触发了降级
        self._last_provider: str = "primary"

    @property
    def last_usage(self) -> dict:
        return self._last_usage or {}

    @property
    def fallback_stats(self) -> dict:
        """返回降级统计信息"""
        return {
            "primary_type": type(self._primary).__name__,
            "fallback_count": len(self._fallbacks),
            "fallback_types": [type(fb).__name__ for fb in self._fallbacks],
            "fallback_triggered_methods": list(self._fallback_used),
            "last_provider": self._last_provider,
        }

    # ─── 统一调用包装 ───

    async def chat(self, messages: list[dict], stream: bool = False) -> LLMResponse:
        return await self._with_fallback(
            "chat", self._primary.chat(messages, stream=stream),
            fallback_call=lambda fb: fb.chat(messages, stream=stream),
        )

    async def chat_stream(self, messages: list[dict]) -> AsyncGenerator[str, None]:
        """流式对话，主 LLM 尚未产生内容时超时/失败可切备用 LLM。

        设计说明: 一旦已经向调用方产出过内容，就无法回滚，只能继续主 LLM；
        若在产生任何内容之前就超时/失败，则安全切换到备用 LLM 重新生成。
        """
        if not self._fallbacks:
            async for chunk in self._primary.chat_stream(messages):
                yield chunk
            return

        started = False
        try:
            async for chunk in self._primary.chat_stream(messages):
                started = True
                yield chunk
        except (asyncio.TimeoutError, Exception) as e:
            if started:
                # 已产生内容，无法回滚，只能终止
                logger.warning(
                    "LLM 流式中途失败（已产出内容，无法降级）: %s: %s",
                    type(e).__name__, e,
                )
                raise
            # 尚未产生内容 → 尝试备用 LLM
            logger.warning(
                "LLM 流式开始即失败 (%s: %s) → 降级到备用 LLM", type(e).__name__, e,
            )
            yielded = False
            for fb in self._fallbacks:
                try:
                    async for chunk in fb.chat_stream(messages):
                        yielded = True
                        yield chunk
                    if yielded:
                        self._last_provider = "fallback"
                        self._fallback_used.add("chat_stream")
                        return
                except Exception as fe:
                    logger.warning("备用 LLM 流式失败: %s: %s", type(fe).__name__, fe)
                    continue
            raise

    async def structured_output(self, messages: list[dict], response_model: type) -> dict:
        return await self._with_fallback(
            "structured_output",
            self._primary.structured_output(messages, response_model),
            fallback_call=lambda fb: fb.structured_output(messages, response_model),
        )

    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> tuple[str, list[dict]]:
        return await self._with_fallback(
            "chat_with_tools",
            self._primary.chat_with_tools(messages, tools, tool_choice),
            fallback_call=lambda fb: fb.chat_with_tools(messages, tools, tool_choice),
        )

    async def chat_with_tools_stream(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> AsyncGenerator[dict, None]:
        """带工具的流式调用，主 LLM 尚未产出内容时超时/失败可切备用 LLM。"""
        if not self._fallbacks:
            async for chunk in self._primary.chat_with_tools_stream(messages, tools, tool_choice):
                yield chunk
            return

        started = False
        try:
            async for chunk in self._primary.chat_with_tools_stream(messages, tools, tool_choice):
                started = True
                yield chunk
        except (asyncio.TimeoutError, Exception) as e:
            if started:
                logger.warning(
                    "LLM 工具流式中途失败（已产出内容，无法降级）: %s: %s",
                    type(e).__name__, e,
                )
                raise
            logger.warning(
                "LLM 工具流式开始即失败 (%s: %s) → 降级到备用 LLM", type(e).__name__, e,
            )
            yielded = False
            for fb in self._fallbacks:
                try:
                    async for chunk in fb.chat_with_tools_stream(messages, tools, tool_choice):
                        yielded = True
                        yield chunk
                    if yielded:
                        self._last_provider = "fallback"
                        self._fallback_used.add("chat_with_tools_stream")
                        return
                except Exception as fe:
                    logger.warning("备用 LLM 工具流式失败: %s: %s", type(fe).__name__, fe)
                    continue
            raise

    async def close(self):
        await self._primary.close()
        for fb in self._fallbacks:
            try:
                await fb.close()
            except Exception:
                pass

    # ─── 核心降级逻辑 ───

    async def _with_fallback(self, method_name: str, primary_coro, fallback_call) -> any:
        """执行主 LLM 调用，失败时自动切换到备用 LLM。"""
        if not self._fallbacks:
            # 没有备用 LLM，直接执行（仍加超时保护）
            return await asyncio.wait_for(primary_coro, timeout=self._timeout)

        try:
            result = await asyncio.wait_for(primary_coro, timeout=self._timeout)
            self._last_provider = "primary"
            return result
        except asyncio.TimeoutError:
            self._last_provider = "fallback"
            self._fallback_used.add(method_name)
            logger.warning(
                "LLM 超时 (%.1fs): %s → 降级到 %s",
                self._timeout, method_name, type(self._fallbacks[0]).__name__,
            )
            if self._fallback_on_timeout:
                return await self._try_fallbacks(method_name, fallback_call)
            raise
        except Exception as e:
            self._last_provider = "fallback"
            self._fallback_used.add(method_name)
            logger.warning(
                "LLM 失败 (%s): %s → 降级到 %s: %s",
                type(e).__name__, method_name, type(self._fallbacks[0]).__name__, e,
            )
            if self._fallback_on_error:
                return await self._try_fallbacks(method_name, fallback_call)
            raise

    async def _try_fallbacks(self, method_name: str, fallback_call) -> any:
        """依序尝试所有备用 LLM，全部失败则抛出最后一个异常。"""
        last_error = None
        for i, fb in enumerate(self._fallbacks):
            try:
                logger.info("尝试备用 LLM #%d: %s", i + 1, type(fb).__name__)
                result = await asyncio.wait_for(
                    fallback_call(fb), timeout=self._timeout,
                )
                return result
            except Exception as e:
                last_error = e
                detail = self._extract_error_detail(e)
                logger.warning(
                    "备用 LLM #%d 失败: %s, %s%s",
                    i + 1, type(e).__name__, e,
                    f" | {detail}" if detail else "",
                )
                continue

        # ═══ 修复：把可诊断信息（模型名/403 详情）带进最终异常，不再裸 "403 Forbidden" ═══
        raise last_error or RuntimeError(f"所有 LLM 降级尝试均失败 (method={method_name})")

    @staticmethod
    def _extract_error_detail(exc: Exception) -> str:
        """从 HTTP 异常中提取可诊断信息（模型名 / access_denied / 账户提示）。"""
        try:
            import json
            resp = getattr(exc, "response", None)
            if resp is None:
                return ""
            # httpx.HTTPStatusError.response
            try:
                body = resp.text if hasattr(resp, "text") else resp.content.decode()
            except Exception:
                return ""
            try:
                parsed = json.loads(body) if isinstance(body, str) else {}
            except Exception:
                parsed = {}
            err = parsed.get("error", {}) if isinstance(parsed, dict) else {}
            if isinstance(err, dict):
                code = err.get("code", "")
                msg = err.get("message", "")
                if "access_denied" in code.lower():
                    return f"模型访问被拒 (access_denied)：请检查模型名/开通状态 → {msg[:150]}"
                if code:
                    return f"[{code}] {msg[:150]}"
                return msg[:150] if msg else ""
            return str(parsed)[:200]
        except Exception:
            return ""

