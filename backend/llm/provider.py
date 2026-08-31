import os
import logging
import hashlib
import json
from typing import Optional
from .base import LLMInterface
from .deepseek import DeepSeekProvider
from .qwen import QwenProvider
from .openai_compatible import OpenAICompatibleProvider
from .anthropic_compatible import AnthropicCompatibleProvider
from .mock import MockLLMProvider, is_mock_key
from .fallback import FallbackLLMProvider

logger = logging.getLogger("secagentx.llm")


def _cache_fingerprint(*values) -> str:
    """生成稳定且不在缓存键中保留明文 API Key 的配置指纹。"""
    payload = json.dumps(values, sort_keys=True, ensure_ascii=False, default=repr)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _resolve_runtime_profile(provider: str, config: dict) -> tuple[str, dict, bool]:
    """用 onboarding 选定的活动档案覆盖硬编码 Agent Provider。"""
    active = os.getenv("SECAGENTX_ACTIVE_PROVIDER", "").strip().lower()
    if not active:
        return provider, dict(config), False
    runtime = dict(config)
    env_map = {
        "api_base": "SECAGENTX_LLM_API_BASE",
        "api_key": "SECAGENTX_LLM_API_KEY",
        "model": "SECAGENTX_LLM_MODEL",
        "auth_style": "SECAGENTX_LLM_AUTH_STYLE",
        "api_version": "SECAGENTX_LLM_API_VERSION",
    }
    for field, env_name in env_map.items():
        value = os.getenv(env_name, "")
        if value:
            runtime[field] = value
    runtime["allow_no_key"] = os.getenv("SECAGENTX_LLM_ALLOW_NO_KEY", "").lower() in (
        "1", "true", "yes",
    )
    return active, runtime, True


def build_provider(provider: str, config: dict, *, use_runtime_profile: bool = True) -> LLMInterface:
    """构建单个 LLM 提供者（不含 fallback 包装）。"""
    if use_runtime_profile:
        provider, config, _ = _resolve_runtime_profile(provider, config)
    else:
        config = dict(config)
    if provider == "mock":
        return MockLLMProvider(config)
    api_key = config.get("api_key") or os.getenv(f"{provider.upper()}_API_KEY", "")
    config["api_key"] = api_key

    # 企业运行时禁止把缺失凭据静默伪装成真实模型响应。
    # Mock 只能通过 provider=mock 显式选择；测试代码可继续直接使用 MockLLMProvider。
    if is_mock_key(api_key) and not config.get("allow_no_key", False):
        raise ValueError(
            f"{provider} 未配置有效 API Key；请运行 `secagentx onboard`，"
            "或显式选择 provider=mock（仅限测试/演示）"
        )

    if provider == "deepseek":
        return DeepSeekProvider(config)
    elif provider == "qwen":
        return QwenProvider(config)
    elif provider == "openai_compatible":
        return OpenAICompatibleProvider(config)
    elif provider == "anthropic_compatible":
        return AnthropicCompatibleProvider(config)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


def _build_single_provider(provider: str, config: dict) -> LLMInterface:
    """向后兼容的内部别名。"""
    return build_provider(provider, config)


class LLMFactory:
    _instances: dict[str, LLMInterface] = {}

    @classmethod
    def get_provider(cls, provider: str = "deepseek",
                     config: Optional[dict] = None,
                     fallback_config: Optional[dict] = None) -> LLMInterface:
        """
        获取 LLM 提供者（自动包装 FallbackLLMProvider）。

        Args:
            provider: 主 LLM 名称或兼容协议名称
            config: 主 LLM 配置字典
            fallback_config: fallback 配置，结构为:
                {
                    "enabled": True,
                    "provider": "qwen",       # 备用 LLM 名称
                    "config": {...},          # 备用 LLM 配置
                    "timeout_seconds": 25,    # 超时阈值
                    "fallback_on_error": True,
                }
        """
        if config is None:
            config = {}

        provider, config, has_runtime_profile = _resolve_runtime_profile(provider, config)
        if has_runtime_profile:
            # onboarding 档案是全局统一路由；避免旧 qwen fallback 再次调用同一接口。
            fallback_config = None

        key = f"{provider}:{_cache_fingerprint(config, fallback_config)}"
        if key in cls._instances:
            return cls._instances[key]

        # 构建主 LLM
        primary = build_provider(provider, config, use_runtime_profile=False)

        # 检查是否需要包装 FallbackLLMProvider
        if fallback_config and fallback_config.get("enabled", False):
            fb_provider_name = fallback_config.get("provider", "")
            fb_cfg = dict(fallback_config.get("config", {}))
            if fb_provider_name:
                # ═══ 修复：fallback 未显式配置时，从主 provider 继承关键字段 ═══
                # 问题：config.yaml 的 fallback 段常缺少嵌套 config，
                #       导致 QwenProvider 用默认模型 qwen2.5-72b-instruct（该模型对许多账号 403 access_denied）
                # 方案：模型只从【同 provider】继承（跨 provider 继承会拿到错误模型名）；
                #       api_key/api_base 允许跨 provider 继承（环境变量兜底）。
                if not fb_cfg:
                    if fb_provider_name == provider:
                        # 同 provider 兜底：完整继承主配置（含 model）
                        fb_cfg = dict(config)
                    else:
                        # 跨 provider：只继承 api_base / api_key，model 用各 provider 显式配置或默认
                        fb_cfg = {
                            k: config.get(k) for k in ("api_base", "api_key")
                            if config.get(k)
                        }
                    logger.warning(
                        "fallback(%s) 未提供嵌套 config，已从主 provider 继承字段: %s%s",
                        fb_provider_name, sorted(fb_cfg.keys()),
                        "（含 model，同 provider）" if fb_provider_name == provider else
                        "（model 用 fallback provider 默认，建议在 config 显式指定）",
                    )
                else:
                    # 部分提供 → 逐个字段继承缺失项（model 仅同 provider 继承）
                    for k in ("api_base", "api_key"):
                        if not fb_cfg.get(k) and config.get(k):
                            fb_cfg[k] = config[k]
                    if fb_provider_name == provider and not fb_cfg.get("model") and config.get("model"):
                        fb_cfg["model"] = config["model"]
                try:
                    fallback = build_provider(fb_provider_name, fb_cfg, use_runtime_profile=False)
                    # ═══ 修复：模型名黑名单校验（防止 403 access_denied 静默失败） ═══
                    # 必须基于【实际构建出的 fallback 实例】校验 —— 因为 QwenProvider 构造时
                    # 会用默认 qwen2.5-72b-instruct 填充 fb_cfg 里缺失的 model。
                    _BLOCKED_MODELS = (
                        "qwen2.5-72b-instruct", "qwen2.5-7b-instruct",
                    )
                    fb_actual_model = getattr(fallback, "config", None)
                    fb_actual_model = fb_actual_model.model if hasattr(fb_actual_model, "model") else ""
                    if (fb_actual_model or "").lower() in _BLOCKED_MODELS:
                        # 同 provider 优先回退主模型；跨 provider 用该 provider 的常用模型
                        corrected = (
                            config.get("model") if fb_provider_name == provider
                            else {"qwen": "qwen-max", "deepseek": "deepseek-chat"}.get(
                                fb_provider_name, fb_actual_model)
                        )
                        logger.warning(
                            "fallback(%s) 模型 %s 不可用（常见 403 access_denied），"
                            "已纠正为 %s",
                            fb_provider_name, fb_actual_model, corrected,
                        )
                        fb_cfg["model"] = corrected
                        fallback = build_provider(fb_provider_name, fb_cfg, use_runtime_profile=False)
                    wrapper = FallbackLLMProvider(
                        primary,
                        fallback,
                        fallback_on_timeout=fallback_config.get("fallback_on_timeout", True),
                        fallback_on_error=fallback_config.get("fallback_on_error", True),
                        timeout_seconds=float(fallback_config.get("timeout_seconds", 30)),
                    )
                    logger.info(
                        "FallbackLLM: primary=%s, fallback=%s, timeout=%.1fs",
                        provider, fb_provider_name,
                        float(fallback_config.get("timeout_seconds", 30)),
                    )
                    cls._instances[key] = wrapper
                    return wrapper
                except Exception as e:
                    logger.warning("FallbackLLM 构建失败（仅使用主 LLM）: %s", e)

        # 无 fallback 配置或构建失败 → 直接返回主 LLM
        cls._instances[key] = primary
        return primary

    @classmethod
    def get_deepseek(cls, config: Optional[dict] = None,
                     fallback_config: Optional[dict] = None) -> LLMInterface:
        return cls.get_provider("deepseek", config, fallback_config)

    @classmethod
    def get_qwen(cls, config: Optional[dict] = None,
                 fallback_config: Optional[dict] = None) -> LLMInterface:
        return cls.get_provider("qwen", config, fallback_config)

    @classmethod
    def clear(cls):
        for inst in cls._instances.values():
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(inst.close())
            except RuntimeError:
                pass
        cls._instances.clear()
