"""
ThreatIntelTool 单元测试
"""
import os
import pytest
from backend.tools.threat_intel import ThreatIntelTool


@pytest.mark.asyncio
async def test_private_ip_detection():
    """测试：私有 IP 直接返回不查询外部 API"""
    tool = ThreatIntelTool()
    # 手动设置有 key 状态以绕过安全检查
    tool._has_real_api = True

    result = await tool.execute(indicator="10.0.0.5", indicator_type="ip")
    assert result.success is True
    assert result.data["is_private"] is True
    assert result.data["risk_level"] == "低危"


@pytest.mark.asyncio
async def test_another_private_ip():
    """测试：172.16.x.x 私有 IP"""
    tool = ThreatIntelTool()
    tool._has_real_api = True
    result = await tool.execute(indicator="172.16.0.1", indicator_type="ip")
    assert result.success is True
    assert result.data["is_private"] is True


@pytest.mark.asyncio
async def test_loopback_ip():
    """测试：127.0.0.1 回环地址"""
    tool = ThreatIntelTool()
    tool._has_real_api = True
    result = await tool.execute(indicator="127.0.0.1", indicator_type="ip")
    assert result.success is True
    assert result.data["is_private"] is True


@pytest.mark.asyncio
async def test_private_ip_in_cache():
    """测试：私有 IP 缓存"""
    tool = ThreatIntelTool()
    tool._has_real_api = True

    # 第一次查询
    result1 = await tool.execute(indicator="192.168.1.1", indicator_type="ip")
    assert result1.success is True
    assert result1.data["is_private"] is True

    # 第二次查询（走缓存）
    result2 = await tool.execute(indicator="192.168.1.1", indicator_type="ip")
    assert result2.success is True


@pytest.mark.asyncio
async def test_missing_api_key():
    """测试：未配置 API Key 时，IP 查询走本地黑名单库兜底（不再报错）"""
    # 模拟无 key 状态
    tool = ThreatIntelTool()
    tool._has_real_api = False
    tool.abuseipdb_key = ""
    tool.otx_key = ""
    tool.vt_key = ""

    # 显式模拟“真实本地库已安装但未命中”，与“库不存在”严格区分。
    tool._local_ips = {}
    tool._local_ips_available = True
    result = await tool.execute(indicator="8.8.8.8", indicator_type="ip")
    assert result.success is True
    assert "本地黑名单库" in result.data["alerts"][0]

    # 非 IP 类型（domain/hash）：本地库无数据，才报配置错误
    result2 = await tool.execute(indicator="example.com", indicator_type="domain")
    assert result2.success is False
    assert "API Key" in result2.error


@pytest.mark.asyncio
async def test_is_private_ip_static():
    """测试：_is_private_ip 静态方法"""
    # 私有 IP
    assert ThreatIntelTool._is_private_ip("10.0.0.1") is True
    assert ThreatIntelTool._is_private_ip("172.16.0.1") is True
    assert ThreatIntelTool._is_private_ip("172.31.255.255") is True
    assert ThreatIntelTool._is_private_ip("192.168.0.1") is True
    assert ThreatIntelTool._is_private_ip("127.0.0.1") is True
    assert ThreatIntelTool._is_private_ip("169.254.1.1") is True

    # 公网 IP
    assert ThreatIntelTool._is_private_ip("8.8.8.8") is False
    assert ThreatIntelTool._is_private_ip("1.1.1.1") is False
    assert ThreatIntelTool._is_private_ip("45.33.32.156") is False


@pytest.mark.asyncio
async def test_invalid_ip():
    """测试：非法 IP 格式"""
    # _is_private_ip 返回 False 对于无法解析的 IP
    assert ThreatIntelTool._is_private_ip("not-an-ip") is False
    assert ThreatIntelTool._is_private_ip("") is False


@pytest.mark.asyncio
async def test_domain_indicator():
    """测试：域名类型的威胁指标"""
    tool = ThreatIntelTool()
    tool._has_real_api = False

    result = await tool.execute(indicator="example.com", indicator_type="domain")
    # 没有 API Key 时，域名查询也应该报错
    assert result.success is False
    assert "未配置" in result.error or "API Key" in result.error


# ============================================================
# 确定性评分：情报源缺失处理（修复"把未查询当无恶意"的漏报缺陷）
# ============================================================


@pytest.mark.asyncio
async def test_missing_api_keys_not_counted_as_clean():
    """缺 Key 的源必须标记为 unavailable，不贡献 0 分，且进入 missing 列表"""
    tool = ThreatIntelTool()
    # 显式清空所有 key，避免 .env 中的配置影响测试确定性
    tool.abuseipdb_key = ""
    tool.otx_key = ""
    tool.vt_key = ""
    result = await tool._check_ip("45.155.205.66")

    # 仓库没有下载本地情报时，不得把“文件不存在”伪装为“已查且干净”。
    assert result["coverage"] == 0.0
    assert result["total_sources"] == 0
    # 未配置源在 unconfigured 列表，而非 missing（missing 仅真失败）
    assert set(result["unconfigured_sources"]) == {"local_blacklist", "abuseipdb", "otx", "virustotal"}
    assert result["missing_sources"] == []
    assert result["score"] == 0

    # 每个缺失源都应标记 status=unavailable（而非 status=ok/score=0）
    for name in ("abuseipdb", "otx", "virustotal"):
        assert result["source_details"][name]["status"] == "unavailable"
        assert result["source_details"][name]["note"] == "no_api_key"


@pytest.mark.asyncio
async def test_partial_coverage_exposes_missing_sources():
    """部分源缺失时：未配置源不计分母，仅真失败(配置了但查询失败)拉低覆盖率"""
    tool = ThreatIntelTool()
    tool.abuseipdb_key = ""
    tool.otx_key = "fake-otx"
    tool.vt_key = ""

    # mock OTX 返回（避免真实网络）；新版 _otx_lookup 带 indicator_type 参数
    async def _fake_otx(self, ip, indicator_type="ip"):
        return {"malicious": False, "pulse_count": 0, "families": []}
    import backend.tools.threat_intel as ti
    ti.ThreatIntelTool._otx_lookup = _fake_otx

    result = await tool._check_ip("45.155.205.66")

    # 本地库未安装不计为已检查源；只有真实返回的 OTX 计入。
    assert result["total_sources"] == 1
    assert result["coverage"] == 1.0
    assert result["missing_sources"] == []
    assert set(result["unconfigured_sources"]) == {"local_blacklist", "abuseipdb", "virustotal"}
    assert result["source_details"]["otx"]["status"] == "ok"


def test_coverage_from_real_threat_feed():
    """实测：攻击 IP 不在本地 115k 恶意库中，情报覆盖需显式告知而非默认干净"""
    import json
    import os
    root = os.path.join(os.path.dirname(__file__), "..", "..")
    path = os.path.join(root, "data/blacklist/threat_ips.json")
    if not os.path.exists(path):
        # 大型情报缓存是可选运行数据；不存在时工具应以空本地源正常降级。
        tool = ThreatIntelTool()
        tool._load_local_ips()
        assert tool._local_ips == {}
        return
    data = json.load(open(path))
    ips = data["ips"]
    assert "45.155.205.66" not in ips  # 目标 IP 不在库内
    # 同类攻击 IP 应有部分在库（证明本地库有价值，缺失源不能当干净）
    assert len(ips) > 100000
