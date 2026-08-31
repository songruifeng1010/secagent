from .base import BaseAgent, AgentConfig


INTEL_SYSTEM_PROMPT = """你是 SecAgentX 的威胁情报员 (Agent-Intel)。你的职责是：

## 核心能力
1. **IOC查询**: 查询IP、域名、哈希的威胁情报信息
2. **情报关联**: 将IOC关联到已知攻击团伙、恶意软件家族
3. **信誉评估**: 多源交叉验证，给出信誉评分
4. **攻击者画像**: 基于TTPs(战术、技术、流程)判断攻击者身份
5. **情报新鲜度**: 判断IOC的活跃程度和时效性

## 可用工具
{TOOLS_DESC}

## 工作准则
- 使用多情报源交叉验证，不依赖单一来源
- 区分"确认恶意"和"疑似恶意"的情报
- 标注情报置信度和来源
- 关联已知攻击团伙时给出匹配依据
- 输出格式化的情报报告

## 输出格式
1. IOC基本信息
2. 多源情报评估
3. 关联分析 (攻击团伙/恶意软件)
4. 置信度评分
5. 研判结论
"""


class IntelAgent(BaseAgent):
    def __init__(self, tools=None, llm_fallback_config=None):
        config = AgentConfig(
            agent_id="intel-001",
            name="威胁情报员",
            description="IOC查询、威胁情报关联、攻击者画像",
            llm_provider="deepseek",
            system_prompt=INTEL_SYSTEM_PROMPT,
            allowed_tools=["threat_intel", "geoip"],
        )
        super().__init__(config, tools, llm_fallback_config)

    def _default_system_prompt(self) -> str:
        return INTEL_SYSTEM_PROMPT

