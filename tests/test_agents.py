"""
Agent 基础模块测试（base.py）
"""
import os
import sys
import time
import uuid
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestToolCallHistory:
    """ToolCallHistory 数据结构测试"""

    def test_parse_tool_calls_basic(self):
        """测试解析工具调用"""
        from backend.tools.calling import parse_tool_calls

        mock_response = {
            "choices": [{
                "message": {
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "threat_intel",
                                "arguments": '{"indicator": "8.8.8.8", "indicator_type": "ip"}'
                            }
                        }
                    ]
                }
            }]
        }

        calls = parse_tool_calls(mock_response, source="test")
        assert len(calls) == 1
        assert calls[0].tool_name == "threat_intel"
        assert calls[0].arguments["indicator"] == "8.8.8.8"

    def test_parse_tool_calls_empty(self):
        """测试：无工具调用时返回空列表"""
        from backend.tools.calling import parse_tool_calls

        mock_response = {
            "choices": [{"message": {"content": "直接回复"}}]
        }

        calls = parse_tool_calls(mock_response, source="test")
        assert calls == []


class TestStructuredVerdict:
    """结构化裁决解析测试"""

    def test_parse_verdict(self):
        """测试：从 LLM 回复中解析结构化裁决"""
        from backend.agents.analyst import AnalystAgent

        agent = AnalystAgent()
        text = """分析完毕。

```verdict
{
  "verdict": "malicious",
  "confidence": 0.85,
  "technique_ids": ["T1110"],
  "risk_level": "高危",
  "key_evidence": ["SSH暴力破解尝试", "100次登录失败"],
  "recommended_action": "block",
  "iocs": {"ips": ["45.33.32.156"], "domains": [], "hashes": []}
}
```"""

        result = agent._parse_structured_verdict(text)
        assert result["verdict"] == "malicious"
        assert result["confidence"] == 0.85
        assert result["risk_level"] == "高危"
        assert "T1110" in result["technique_ids"]
        assert result["recommended_action"] == "block"

    def test_parse_verdict_no_block(self):
        """测试：无结构化裁决时返回默认值"""
        from backend.agents.analyst import AnalystAgent

        agent = AnalystAgent()
        text = "这是普通文本回复，没有结构化裁决 JSON"

        result = agent._parse_structured_verdict(text)
        assert result["verdict"] == "unknown"
        assert result["confidence"] == 0.5

    def test_parse_verdict_partial(self):
        """测试：部分字段缺失时使用默认值"""
        from backend.agents.analyst import AnalystAgent

        agent = AnalystAgent()
        text = '```verdict\n{"verdict": "suspicious"}\n```'

        result = agent._parse_structured_verdict(text)
        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 0.5  # 默认值
        assert result["technique_ids"] == []  # 默认值


class TestBuildToolsForLLM:
    """工具定义构建测试"""

    def test_build_tools_basic(self):
        """测试：构建 LLM 工具定义"""
        from backend.tools.calling import build_tools_for_llm
        from backend.tools.registry import ToolRegistry
        from backend.tools.firewall import FirewallTool
        from backend.tools.geoip import GeoIPTool

        registry = ToolRegistry()
        registry.register(FirewallTool())
        registry.register(GeoIPTool())

        tools = build_tools_for_llm(registry.list_tools())
        assert len(tools) >= 2

        # 验证工具定义格式
        tool_names = [t["function"]["name"] for t in tools]
        assert "firewall_manage" in tool_names
        assert "geoip" in tool_names
