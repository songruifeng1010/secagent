"""
云防火墙 SDK 集成测试 — 验证所有云厂商 SDK 安装正确、适配器可实例化
"""
import os
import pytest
from unittest.mock import patch


class TestAliyunSDK:
    """阿里云 SDK 安装验证"""

    def test_adapter_importable(self):
        """AliyunFirewallAdapter 可导入"""
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        assert AliyunFirewallAdapter is not None

    def test_adapter_no_credentials(self):
        """无凭证时状态正确"""
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        assert adapter._has_credentials is False
        assert adapter.client is None  # 不初始化

    def test_adapter_with_env_credentials(self):
        """通过环境变量配置凭证后适配器识别"""
        with patch.dict(os.environ, {
            "ALIBABA_CLOUD_ACCESS_KEY_ID": "test-key-id",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "test-key-secret",
            "ALIYUN_SECURITY_GROUP_ID": "sg-test-123",
        }):
            from backend.tools.aliyun_firewall import AliyunFirewallAdapter
            adapter = AliyunFirewallAdapter()
            assert adapter._has_credentials is True
            assert adapter.access_key_id == "test-key-id"
            assert adapter.security_group_id == "sg-test-123"

    @pytest.mark.asyncio
    async def test_block_ip_no_credentials(self):
        """无凭证时封禁返回友好错误"""
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        success, err = await adapter.block_ip("1.2.3.4", "test")
        assert success is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_unblock_ip_no_credentials(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        success, err = await adapter.unblock_ip("1.2.3.4")
        assert success is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_list_rules_no_credentials(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        rules = await adapter.list_rules()
        assert rules == []

    @pytest.mark.asyncio
    async def test_check_ip_no_credentials(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        result = await adapter.check_ip("1.2.3.4")
        assert result["is_blocked"] is False

    @pytest.mark.asyncio
    async def test_health_check_no_credentials(self):
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = AliyunFirewallAdapter()
        healthy = await adapter.health_check()
        assert healthy is False


class TestTencentSDK:
    """腾讯云 SDK 安装验证"""

    def test_adapter_importable(self):
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        assert TencentFirewallAdapter is not None

    def test_adapter_no_credentials(self):
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        adapter = TencentFirewallAdapter()
        assert adapter._has_credentials is False
        assert adapter._client is None

    def test_adapter_with_env_credentials(self):
        with patch.dict(os.environ, {
            "TENCENT_SECRET_ID": "test-secret-id",
            "TENCENT_SECRET_KEY": "test-secret-key",
            "TENCENT_SECURITY_GROUP_ID": "sg-test",
        }):
            from backend.tools.tencent_firewall import TencentFirewallAdapter
            adapter = TencentFirewallAdapter()
            assert adapter._has_credentials is True

    @pytest.mark.asyncio
    async def test_block_ip_no_credentials(self):
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        adapter = TencentFirewallAdapter()
        success, err = await adapter.block_ip("1.2.3.4")
        assert success is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_unblock_ip_no_credentials(self):
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        adapter = TencentFirewallAdapter()
        success, err = await adapter.unblock_ip("1.2.3.4")
        assert success is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_list_rules_no_credentials(self):
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        adapter = TencentFirewallAdapter()
        rules = await adapter.list_rules()
        assert rules == []

    @pytest.mark.asyncio
    async def test_health_check_no_credentials(self):
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        adapter = TencentFirewallAdapter()
        healthy = await adapter.health_check()
        assert healthy is False


class TestAwsSDK:
    """AWS SDK 安装验证"""

    def test_adapter_importable(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        assert AWSFirewallAdapter is not None

    def test_adapter_no_credentials(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = AWSFirewallAdapter()
        assert adapter._has_credentials is False

    def test_adapter_with_env_credentials(self):
        with patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "AKIA-test",
            "AWS_SECRET_ACCESS_KEY": "test-secret",
            "AWS_SECURITY_GROUP_ID": "sg-test",
        }):
            from backend.tools.aws_firewall import AWSFirewallAdapter
            adapter = AWSFirewallAdapter()
            assert adapter._has_credentials is True

    @pytest.mark.asyncio
    async def test_block_ip_no_credentials(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = AWSFirewallAdapter()
        success, err = await adapter.block_ip("1.2.3.4")
        assert success is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_unblock_ip_no_credentials(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = AWSFirewallAdapter()
        success, err = await adapter.unblock_ip("1.2.3.4")
        assert success is False
        assert "凭证" in err

    @pytest.mark.asyncio
    async def test_list_rules_no_credentials(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = AWSFirewallAdapter()
        rules = await adapter.list_rules()
        assert rules == []

    @pytest.mark.asyncio
    async def test_health_check_no_credentials(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = AWSFirewallAdapter()
        healthy = await adapter.health_check()
        assert healthy is False

    def test_waf_mode_default_off(self):
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = AWSFirewallAdapter()
        assert adapter.use_waf is False

    def test_waf_mode_env_var(self):
        with patch.dict(os.environ, {"AWS_USE_WAF": "true"}):
            from backend.tools.aws_firewall import AWSFirewallAdapter
            adapter = AWSFirewallAdapter()
            assert adapter.use_waf is True


class TestFactoryLazyLoading:
    """验证工厂的延迟加载机制能正确初始化云厂商适配器"""

    def test_factory_create_aliyun(self):
        from backend.tools.base import FirewallAdapterFactory
        from backend.tools.aliyun_firewall import AliyunFirewallAdapter
        adapter = FirewallAdapterFactory.create("aliyun")
        assert isinstance(adapter, AliyunFirewallAdapter)

    def test_factory_create_tencent(self):
        from backend.tools.base import FirewallAdapterFactory
        from backend.tools.tencent_firewall import TencentFirewallAdapter
        adapter = FirewallAdapterFactory.create("tencent")
        assert isinstance(adapter, TencentFirewallAdapter)

    def test_factory_create_aws(self):
        from backend.tools.base import FirewallAdapterFactory
        from backend.tools.aws_firewall import AWSFirewallAdapter
        adapter = FirewallAdapterFactory.create("aws")
        assert isinstance(adapter, AWSFirewallAdapter)

    def test_factory_lazy_loader_configs(self):
        from backend.tools.base import FirewallAdapterFactory as Factory
        for name in ["aliyun", "tencent", "aws"]:
            assert name in Factory._LAZY_LOADERS
            assert Factory._LAZY_LOADERS[name]["class"] is not None
            assert Factory._LAZY_LOADERS[name]["pip"] is not None

    def test_factory_backends_registered(self):
        from backend.tools.base import FirewallAdapterFactory as Factory
        expected = {"disabled", "mock", "iptables", "nftables", "aliyun", "tencent", "aws"}
        assert set(Factory.BACKENDS.keys()) == expected

    def test_factory_backends_all_instantiable(self):
        """所有 6 个后端均可实例化（无凭证时也能创建）"""
        from backend.tools.base import FirewallAdapterFactory
        expected_types = {
            "disabled": "DisabledFirewallAdapter",
            "mock": "MockFirewallAdapter",
            "iptables": "IptablesAdapter",
            "nftables": "NftablesAdapter",
            "aliyun": "AliyunFirewallAdapter",
            "tencent": "TencentFirewallAdapter",
            "aws": "AWSFirewallAdapter",
        }
        for backend, expected_type in expected_types.items():
            adapter = FirewallAdapterFactory.create(backend)
            assert type(adapter).__name__ == expected_type, (
                f"{backend}: 期望 {expected_type}, 实际 {type(adapter).__name__}"
            )
