"""按场景选择对话展示模式的契约测试。"""

import os
import sys

os.environ.setdefault("CI", "true")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.models.output import is_plain_knowledge_query, select_response_mode


def test_definition_question_uses_knowledge_card_even_when_security_term_is_present():
    assert is_plain_knowledge_query("什么是 SQLite 注入", "攻击检测", "analysis")
    assert select_response_mode("攻击检测", "什么是 SQLite 注入", answer_mode="analysis") == "knowledge_card"


def test_actionable_security_questions_keep_structured_presentation():
    assert not is_plain_knowledge_query("如何防御 SQL 注入", "安全配置", "rag")
    assert select_response_mode("安全配置", "如何防御 SQL 注入", answer_mode="analysis") == "action_guide"


def test_scene_modes_are_stable():
    assert select_response_mode("威胁情报", "查询 45.33.32.156") == "ioc_card"
    assert select_response_mode("漏洞分析", "CVE-2024-6387 影响分析") == "investigation_report"
    assert select_response_mode("应急响应", "隔离受感染主机") == "incident_report"
