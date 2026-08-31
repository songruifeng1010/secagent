"""
LogAnalyzerTool 规则阈值测试
覆盖: 暴力破解次数阈值（2次不判高危）、confirmed/confidence 字段
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import pytest


@pytest.mark.asyncio
async def test_brute_force_few_attempts_not_high_severity():
    """2 次 SSH 失败不应直接判高危（可能手输错误）"""
    from backend.tools.log_analyzer import LogAnalyzerTool
    tool = LogAnalyzerTool()
    r = await tool.execute("10:20:31 failed password for root\n10:20:35 failed password for root")

    brute = [f for f in r.data["findings"] if f["type"] == "brute_force"]
    assert brute, "应识别出 brute_force 类型"
    assert brute[0]["confirmed"] is False
    assert brute[0]["confidence"] == "low"
    assert brute[0]["severity"] == "中危"  # 降级，而非"高危"
    assert r.data["severity"] == "中危"


@pytest.mark.asyncio
async def test_brute_force_many_attempts_confirmed():
    """≥5 次 SSH 失败才判高危/确认"""
    from backend.tools.log_analyzer import LogAnalyzerTool
    tool = LogAnalyzerTool()
    logs = "\n".join(f"10:20:{i:02d} failed password for root" for i in range(10))
    r = await tool.execute(logs)

    brute = [f for f in r.data["findings"] if f["type"] == "brute_force"]
    assert brute[0]["confirmed"] is True
    assert brute[0]["confidence"] == "high"
    assert brute[0]["severity"] == "高危"
    assert r.data["severity"] == "高危"
