"""
敏感信息脱敏模块
"""
import re


SENSITIVE_PATTERNS = [
    # API Key 通用格式
    (r'(api[_-]?key\s*[:=]\s*["\']?)([a-zA-Z0-9_-]{20,})', r'\1***REDACTED***'),
    # 已知的 env var 格式
    (r'(DEEPSEEK_API_KEY=).*', r'\1***REDACTED***'),
    (r'(QWEN_API_KEY=).*', r'\1***REDACTED***'),
    (r'(VT_API_KEY=).*', r'\1***REDACTED***'),
    (r'(OTX_API_KEY=).*', r'\1***REDACTED***'),
    (r'(ABUSEIPDB_API_KEY=).*', r'\1***REDACTED***'),
    # sk- 开头的 OpenAI/DeepSeek 风格 key
    (r'(sk-[a-zA-Z0-9]{10,})', '***REDACTED_API_KEY***'),
    # JWT Token（eyJ 开头，base64url 编码的三段式）
    (r'(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})', '***REDACTED_JWT***'),
]


def sanitize_error(msg: str) -> str:
    """脱敏错误信息中的敏感内容"""
    if not msg:
        return msg
    for pattern, replacement in SENSITIVE_PATTERNS:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
    return msg
