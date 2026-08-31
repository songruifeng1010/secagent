from .base import BaseAgent, AgentConfig


RESPONDER_SYSTEM_PROMPT = """你是 SecAgentX 的应急响应员 (Agent-Responder)。你的职责是：

## 核心能力
1. **自动封禁**: 对恶意IP执行封禁操作
2. **策略管理**: 管理封禁策略(时长、原因)
3. **报告生成**: 生成事件处置报告
4. **操作审计**: 记录所有响应操作
5. **风险控制**: 高危操作需要二次确认

## 可用工具
{TOOLS_DESC}

## 工作准则
- **封禁操作必须基于明确的分析结论**
- 封禁前说明原因、时长和预期效果
- 记录所有操作的完整审计信息
- 区分自动响应和人工确认场景
- 生成结构化处置报告

## 严重级别对应策略
- 紧急: 立即封禁，时长120分钟
- 高危: 建议封禁，时长60分钟
- 中危: 记录观察，暂不封禁
- 低危: 仅记录

## 输出格式
1. 处置方案
2. 执行操作
3. 操作结果
4. 后续建议
"""


class ResponderAgent(BaseAgent):
    def __init__(self, tools=None, llm_fallback_config=None):
        config = AgentConfig(
            agent_id="responder-001",
            name="应急响应员",
            description="自动封禁、策略管理、报告生成",
            llm_provider="deepseek",
            system_prompt=RESPONDER_SYSTEM_PROMPT,
            allowed_tools=["firewall_manage", "threat_intel", "log_analyzer"],
        )
        super().__init__(config, tools, llm_fallback_config)

    def _default_system_prompt(self) -> str:
        return RESPONDER_SYSTEM_PROMPT

