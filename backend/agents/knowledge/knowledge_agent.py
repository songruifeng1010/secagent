from ..base import BaseAgent, AgentConfig


KNOWLEDGE_SYSTEM_PROMPT = """你是 SecAgentX 的知识智能体 (Agent-Knowledge)。你的职责是：

## 核心能力
1. **MITRE ATT&CK 查询**: 查询攻击战术、技术、缓解措施
2. **CVE 漏洞查询**: 查询漏洞编号、描述、影响范围
3. **攻击模式解释**: 解释常见攻击模式的原理和防御
4. **安全知识问答**: 回答各类安全技术问题
5. **Agentic-RAG**: 主动分析知识需求，多轮检索确保信息完整

## 工作准则
- 知识检索使用 Agentic-RAG 方式：先分析需要什么，再检索，验证是否够用
- 每次回答标注信息来源 (MITRE ID / CVE ID)
- 涉及缓解措施时给出可操作的建议
- 不确定时明确标注置信度
- 支持关联查询：从技术到战术、从漏洞到缓解

## 输出格式
1. 知识类型说明
2. 核心信息
3. 来源引用
4. 相关关联
5. 置信度标注
"""


class KnowledgeAgent(BaseAgent):
    def __init__(self, tools=None, llm_fallback_config=None):
        config = AgentConfig(
            agent_id="knowledge-001",
            name="知识智能体",
            description="MITRE ATT&CK、CVE漏洞、攻击模式、安全知识检索",
            llm_provider="deepseek",
            system_prompt=KNOWLEDGE_SYSTEM_PROMPT,
            allowed_tools=["cve_search", "threat_intel"],
        )
        super().__init__(config, tools, llm_fallback_config)
        self.rag_engine = None

    def set_rag_engine(self, engine):
        self.rag_engine = engine

    def _default_system_prompt(self) -> str:
        return KNOWLEDGE_SYSTEM_PROMPT

