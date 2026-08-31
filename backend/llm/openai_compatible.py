"""通用 OpenAI Chat Completions 兼容 Provider。"""

from __future__ import annotations

from typing import Optional

import httpx

from .base import LLMConfig
from .deepseek import DeepSeekProvider


class OpenAICompatibleProvider(DeepSeekProvider):
    """支持任意实现 OpenAI `/chat/completions` 协议的云端或本地服务。"""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.config = LLMConfig(
            api_base=str(cfg.get("api_base", "")).rstrip("/"),
            api_key=cfg.get("api_key", ""),
            model=cfg.get("model", ""),
            temperature=float(cfg.get("temperature", 0.1)),
            max_tokens=int(cfg.get("max_tokens", 4096)),
            timeout_seconds=float(cfg.get("timeout_seconds", 60)),
        )
        if not self.config.api_base:
            raise ValueError("OpenAI 兼容 Provider 缺少 api_base")
        if not self.config.model:
            raise ValueError("OpenAI 兼容 Provider 缺少 model")
        self.auth_style = cfg.get("auth_style", "bearer")
        self.api_version = cfg.get("api_version", "")
        self.allow_no_key = bool(cfg.get("allow_no_key", False))
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            headers = {"Content-Type": "application/json"}
            if self.config.api_key and not self.allow_no_key:
                if self.auth_style == "api-key":
                    headers["api-key"] = self.config.api_key
                else:
                    headers["Authorization"] = f"Bearer {self.config.api_key}"
            params = {"api-version": self.api_version} if self.api_version else None
            self._http_client = httpx.AsyncClient(
                base_url=self.config.api_base,
                timeout=self.config.timeout_seconds,
                headers=headers,
                params=params,
            )
        return self._http_client
