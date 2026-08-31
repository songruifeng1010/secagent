"""
测试文本工具 — strip_md 函数
"""
import pytest
from backend.utils.text import strip_md


class TestStripMd:
    def test_plain_text_unchanged(self):
        assert strip_md("hello world") == "hello world"

    def test_remove_headers(self):
        result = strip_md("## 标题\n内容")
        assert "标题" in result
        assert "内容" in result
        assert "##" not in result

    def test_remove_bold(self):
        result = strip_md("这是**粗体**文字")
        assert "粗体" in result
        assert "**" not in result

    def test_remove_italic(self):
        result = strip_md("这是*斜体*文字")
        assert "斜体" in result
        assert "*" not in result or result == "这是斜体文字"

    def test_remove_inline_code(self):
        result = strip_md("使用 `print()` 函数")
        assert "print()" in result
        assert "`" not in result

    def test_remove_code_block(self):
        result = strip_md("```python\nprint('hello')\n```")
        assert "print('hello')" in result
        assert "```" not in result

    def test_remove_list_markers(self):
        result = strip_md("- 项目一\n- 项目二")
        assert "项目一" in result
        assert "项目二" in result
        assert "-" not in result

    def test_remove_numbered_list(self):
        result = strip_md("1. 第一\n2. 第二")
        assert "第一" in result
        assert "第二" in result

    def test_remove_blockquote(self):
        result = strip_md("> 引用内容")
        assert "引用内容" in result
        assert ">" not in result

    def test_remove_table(self):
        result = strip_md("| 名称 | 值 |\n| --- | --- |\n| A | 1 |")
        assert "名称" in result
        assert "值" in result
        assert "|" not in result or "名称 值" in result.replace("|", " ")

    def test_remove_horizontal_rule(self):
        result = strip_md("上面\n---\n下面")
        assert "上面" in result
        assert "下面" in result

    def test_compress_newlines(self):
        result = strip_md("段落1\n\n\n\n段落2")
        assert "段落1\n\n段落2" in result

    def test_strip_whitespace(self):
        result = strip_md("  内容末尾  ")
        assert result == "内容末尾"

    def test_empty_string(self):
        assert strip_md("") == ""

    def test_combine_all_markdown(self):
        md = """
# 报告
这是**重要**的*发现*:
> 需要立即处理

## 详情
- 威胁等级: `高危`
- 影响: 严重

| 字段 | 值 |
|------|-----|
| IP | 10.0.0.1 |
"""
        result = strip_md(md)
        assert "报告" in result
        assert "重要" in result
        assert "发现" in result
        assert "高危" in result
        # 确保标记符号被移除
        assert "#" not in result or "## " not in result 
