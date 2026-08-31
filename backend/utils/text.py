"""
文本处理工具 — Markdown 脱符号、纯文本提取
"""
import re


def strip_md(text: str) -> str:
    """去除 Markdown 特殊符号，保留纯文本"""
    # 标题: ### 标题 → 标题
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    # 粗体/斜体: **text** → text
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    # 行内代码: `text` → text
    text = re.sub(r'`(.+?)`', r'\1', text)
    # 代码块标记: ``` 开头的行
    text = re.sub(r'^```[\w-]*\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'^```\s*', '', text, flags=re.MULTILINE)
    # 列表: - 或 1.  打头
    text = re.sub(r'^\s*[-*+]\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\s*\d+[\.\)]\s+', '', text, flags=re.MULTILINE)
    # 引用: > 开头
    text = re.sub(r'^>\s*', '', text, flags=re.MULTILINE)
    # 表格: 删分隔行, 删数据行首尾 |, 替换 | 为空格
    text = re.sub(r'^[\s|:\-]+$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\|(.+)\|$', r'\1', text, flags=re.MULTILINE)
    text = text.replace('|', ' ')
    # 分隔线: --- 或 ===
    text = re.sub(r'^[-=]{3,}\s*$', '', text, flags=re.MULTILINE)
    # 多余空行压缩
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()
