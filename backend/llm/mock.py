"""
Mock LLM Provider — 离线模式，无需任何 API Key

自动启用条件（满足任一）:
  - DEEPSEEK_API_KEY 为空
  - DEEPSEEK_API_KEY 等于 "your-deepseek-api-key-here"（占位符）
"""
import json
import logging
from typing import Optional, AsyncGenerator
from .base import LLMInterface, LLMConfig, LLMResponse

logger = logging.getLogger("secagentx.llm.mock")

OFFLINE_ANSWERS = {
    "cia": """
## CIA 三要素（信息安全三大核心目标）

**1. 机密性 (Confidentiality)**
- 确保信息只被授权人员访问
- 手段: 加密(AES/RSA)、访问控制(RBAC)、脱敏
- MITRE: T1530 (云存储数据窃取)

**2. 完整性 (Integrity)**
- 确保信息未被篡改
- 手段: 哈希校验(SHA-256)、数字签名、HMAC
- MITRE: T1565 (数据篡改)

**3. 可用性 (Availability)**
- 确保授权用户能及时访问
- 手段: 负载均衡、冗余部署、DDoS防护
- MITRE: T1498 (网络拒绝服务)
""",

    "owasp": """
## OWASP Top 10 (2021)

A01 权限控制失效 | A02 加密机制失效
A03 注入攻击     | A04 不安全设计
A05 配置错误     | A06 过时组件
A07 身份认证失效 | A08 完整性失效
A09 日志监控不足 | A10 SSRF
""",

    "mitre": """
## MITRE ATT&CK 框架 — 14 个战术阶段

TA0043 侦查 → TA0042 资源开发 → TA0001 初始访问
TA0002 执行 → TA0003 持久化 → TA0004 权限提升
TA0005 防御规避 → TA0006 凭证访问 → TA0007 发现
TA0008 横向移动 → TA0009 收集 → TA0011 命令与控制
TA0010 数据渗出 → TA0040 影响
""",
}

KEYWORDS = {
    "cia": "cia", "三要素": "cia", "机密性": "cia",
    "完整性": "cia", "可用性": "cia",
    "owasp": "owasp", "top 10": "owasp",
    "mitre": "mitre", "attack": "mitre", "杀伤链": "mitre",
    "你好": "hello", "hello": "hello", "hi": "hello",
    "帮助": "help", "help": "help", "功能": "help",
}


class MockLLMProvider(LLMInterface):
    def __init__(self, config: Optional[dict] = None):
        self.config = LLMConfig(api_base="mock://local", api_key="mock",
                                model="mock-llm", temperature=0.0, max_tokens=4096)
        self._last_usage = {"total_tokens": 10}

    @property
    def last_usage(self) -> dict:
        return self._last_usage

    async def chat(self, messages, stream=False) -> LLMResponse:
        return LLMResponse(content=self._answer(messages), usage=self._last_usage)

    async def chat_stream(self, messages) -> AsyncGenerator[str, None]:
        content = self._answer(messages)
        for i in range(0, len(content), 30):
            yield content[i:i+30]

    async def structured_output(self, messages, response_model) -> dict:
        return {"result": "mock", "confidence": 0.5}

    async def chat_with_tools(self, messages, tools, tool_choice="auto"):
        """
        增强版 Mock LLM 工具调用：
        - 如果遇到 tools 定义，尝试匹配并调用第一个工具
        - 没有匹配时返回默认回复
        """
        query = self._get_last_user_message(messages)
        q = query.lower().strip()

        # 尝试匹配工具
        matched_tools = self._match_tools(q, tools)
        if matched_tools:
            return "", matched_tools

        return self._answer(messages), []

    async def chat_with_tools_stream(self, messages, tools, tool_choice="auto"):
        query = self._get_last_user_message(messages)
        q = query.lower().strip()
        matched_tools = self._match_tools(q, tools)

        if matched_tools:
            yield {"type": "tool_calls", "tool_calls": matched_tools}
            return

        content = self._answer(messages)
        for i in range(0, len(content), 30):
            yield {"type": "text", "content": content[i:i + 30]}
        yield {"type": "tool_calls", "tool_calls": []}

    def _get_last_user_message(self, messages) -> str:
        for m in reversed(messages):
            if m.get("role") == "user":
                return m.get("content", "")
        return ""

    def _match_tools(self, query: str, tools: list) -> list:
        """
        根据用户输入匹配 tools 列表。

        匹配规则：
        - "geo" / "ip" / "地理位置" / "where" → 匹配第一个有 ip 参数的 geoip 工具
        - "威胁" / "threat" / "intel" / "恶意" → 匹配 threat_intel
        - "cve" / "漏洞" / "vuln" → 匹配 cve_search
        - "firewall" / "封禁" / "block" / "防火墙" → 匹配 firewall_manage
        - "过滤" / "filter" / "误报" → 匹配 alert_filter
        - "route" / "agent" / "analyst" / "intel-" → 匹配 route_to_agent
        """
        tool_keywords = {
            "geoip": ["geo", "ip ", "地理位置", "where", "located"],
            "threat_intel": ["威胁", "threat", "intel", "恶意", "malicious", "reputation"],
            "cve_search": ["cve", "漏洞", "vuln", "vulnerability"],
            "firewall_manage": ["firewall", "封禁", "block", "防火墙", "ban"],
            "alert_filter": ["过滤", "filter", "误报", "fp"],
            "route_to_agent": ["route", "agent", "路由"],
        }

        matched_calls = []
        for tool_def in tools:
            tname = tool_def.get("function", tool_def).get("name", "")
            keywords = tool_keywords.get(tname, [])
            if any(kw in query for kw in keywords):
                # 构造调用参数
                params = {"ip": query.split()[0] if "ip" in query else "8.8.8.8"}
                if tname == "threat_intel":
                    params = {"indicator": "8.8.8.8", "indicator_type": "ip"}
                if tname == "route_to_agent":
                    params = {"agent_id": "analyst-001", "task": query}
                matched_calls.append({
                    "id": f"call_mock_{tname}",
                    "type": "function",
                    "function": {"name": tname, "arguments": json.dumps(params)},
                })
                break  # 每次只调一个工具

        return matched_calls

    async def close(self):
        pass

    def _answer(self, messages) -> str:
        query = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                query = m.get("content", "")
                break
        q = query.lower().strip()
        for kw, key in KEYWORDS.items():
            if kw in q:
                if key == "cia": return OFFLINE_ANSWERS["cia"]
                if key == "owasp": return OFFLINE_ANSWERS["owasp"]
                if key == "mitre": return OFFLINE_ANSWERS["mitre"]
                if key == "hello":
                    return ("你好！我是 SecAgentX AI 安全智能体。\n\n"
                            "当前为离线模式，可回答 CIA/OWASP/MITRE 等安全知识。\n"
                            "配置 DEEPSEEK_API_KEY 后解锁全部 AI 能力。")
                if key == "help":
                    return ("支持的问题:\n  - CIA 三要素是什么？\n"
                            "  - OWASP Top 10 有哪些？\n  - MITRE ATT&CK 介绍\n\n"
                            "配置 API Key 后解锁:\n  - 威胁情报查询\n"
                            "  - 告警自动分析\n  - Agent 协同")
        return (f"知识库未匹配「{query[:30]}」。\n可尝试: CIA 三要素 / OWASP Top 10 / MITRE ATT&CK\n"
                "或配置 DEEPSEEK_API_KEY 解锁完整 AI 能力。")


def is_mock_key(key: str) -> bool:
    """判断 API Key 是否为占位符或空值"""
    if not key:
        return True
    k = key.lower().strip()
    if k in ("", "mock", "your-deepseek-api-key-here", "your-qwen-api-key-here",
             "sk-your-deepseek-api-key-here", "sk-your-qwen-api-key-here",
             "placeholder", "test"):
        return True
    if "your-" in k and "-here" in k:
        return True
    return False

