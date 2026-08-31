"""
LLM Provider 工厂测试

覆盖:
  - DeepSeek / Qwen / Mock 三种提供商
  - 环境变量切换
  - 自动降级 Mock
"""

import os
import pytest


class TestLLMFactory:
    """LLM 工厂单元测试"""

    def test_get_deepseek_provider(self):
        """DeepSeek 提供商创建"""
        from backend.llm.provider import LLMFactory
        llm = LLMFactory.get_deepseek({"api_key": "sk-test"})
        assert llm is not None
        assert "DeepSeek" in type(llm).__name__

    def test_get_qwen_provider(self):
        """Qwen 提供商创建"""
        from backend.llm.provider import LLMFactory
        llm = LLMFactory.get_qwen({"api_key": "sk-test"})
        assert llm is not None
        assert "Qwen" in type(llm).__name__

    def test_missing_key_is_rejected(self):
        """企业运行时不得把占位凭据静默降级为 Mock。"""
        from backend.llm.provider import LLMFactory
        import pytest
        with pytest.raises(ValueError, match="未配置有效 API Key"):
            LLMFactory.get_deepseek({"api_key": "sk-your-deepseek-api-key-here"})

    def test_provider_cache(self):
        """相同配置返回同一实例"""
        from backend.llm.provider import LLMFactory
        cfg = {"api_key": "sk-test-cache"}
        llm1 = LLMFactory.get_deepseek(cfg)
        llm2 = LLMFactory.get_deepseek(cfg)
        assert llm1 is llm2  # 同一实例

    def test_unknown_provider_raises(self):
        """未知提供商抛出 ValueError"""
        from backend.llm.provider import LLMFactory
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            # 使用非 Mock 的 Key，确保不会降级
            LLMFactory.get_provider("unknown_provider", {"api_key": "not-a-real-provider-key"})

    def test_clear_instances(self):
        """清除实例缓存"""
        from backend.llm.provider import LLMFactory
        cfg = {"api_key": "sk-test-clear"}
        llm = LLMFactory.get_deepseek(cfg)
        assert llm is not None
        LLMFactory.clear()
        # 清除后应该创建新实例
        llm2 = LLMFactory.get_deepseek(cfg)
        assert llm2 is not None

class TestFallbackFix:
    """A+B+C 修复：fallback 模型/API Key 继承与黑名单纠正"""

    def _mk_llm(self, primary_cfg, fb_cfg):
        from backend.llm.provider import LLMFactory
        LLMFactory.clear()
        return LLMFactory.get_provider("deepseek", primary_cfg, fb_cfg)

    def test_fallback_inherits_model_when_same_provider(self):
        """同 provider fallback：无 config 时继承主模型"""
        llm = self._mk_llm(
            {"model": "deepseek-chat", "api_key": "sk-x"},
            {"enabled": True, "provider": "deepseek", "timeout_seconds": 30},
        )
        assert llm._fallbacks[0].config.model == "deepseek-chat"

    def test_fallback_blacklist_corrected_cross_provider(self):
        """跨 provider fallback：默认 qwen2.5-72b-instruct 被纠正为 qwen-max"""
        llm = self._mk_llm(
            {"model": "deepseek-chat", "api_key": "sk-x"},
            {"enabled": True, "provider": "qwen", "timeout_seconds": 30},
        )
        assert llm._fallbacks[0].config.model == "qwen-max"

    def test_fallback_explicit_config_kept(self):
        """显式 config：模型保持不变"""
        llm = self._mk_llm(
            {"model": "deepseek-chat", "api_key": "sk-x"},
            {"enabled": True, "provider": "qwen", "timeout_seconds": 30,
             "config": {"model": "qwen-plus"}},
        )
        assert llm._fallbacks[0].config.model == "qwen-plus"

    def test_fallback_blacklist_corrected_explicit(self):
        """显式黑名单模型也被纠正"""
        llm = self._mk_llm(
            {"model": "deepseek-chat", "api_key": "sk-x"},
            {"enabled": True, "provider": "qwen", "timeout_seconds": 30,
             "config": {"model": "qwen2.5-72b-instruct"}},
        )
        assert llm._fallbacks[0].config.model == "qwen-max"

    def test_fallback_inherits_api_key(self):
        """跨 provider fallback：api_key 从主 provider 继承"""
        llm = self._mk_llm(
            {"model": "deepseek-chat", "api_key": "sk-main-key"},
            {"enabled": True, "provider": "qwen", "timeout_seconds": 30},
        )
        assert llm._fallbacks[0].config.api_key == "sk-main-key"


class TestErrorDetailExtraction:
    """C 修复：HTTP 错误详情提取"""

    def test_access_denied_detail(self):
        import json
        from backend.llm.fallback import FallbackLLMProvider

        class FakeResp:
            text = json.dumps({"error": {
                "code": "access_denied",
                "message": "Access denied. For details see help",
            }})

        class FakeExc(Exception):
            response = FakeResp()

        detail = FallbackLLMProvider._extract_error_detail(FakeExc())
        assert "access_denied" in detail
        assert "Access denied" in detail

    def test_no_response_returns_empty(self):
        from backend.llm.fallback import FallbackLLMProvider
        assert FallbackLLMProvider._extract_error_detail(ValueError("x")) == ""

    def test_plain_http_status(self):
        from backend.llm.fallback import FallbackLLMProvider

        class FakeResp:
            text = "plain error text"

        class FakeExc(Exception):
            response = FakeResp()

        detail = FallbackLLMProvider._extract_error_detail(FakeExc())
        assert isinstance(detail, str)
