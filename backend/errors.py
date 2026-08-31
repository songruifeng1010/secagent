"""
统一错误码与错误响应格式

所有 API 端点返回错误时，统一使用此模块构建响应。
确保前端和后端对接时错误格式一致。

使用方式:
    from backend.errors import AppError, error_response

    # 在路由中:
    return error_response("AUTH_TOKEN_MISSING", "缺少认证令牌")
    # → {"error": {"code": "AUTH_TOKEN_MISSING", "message": "缺少认证令牌", ...}}

    # 或直接抛出:
    raise AppError("EVENT_NOT_FOUND", "事件不存在")

内部 Agent/Tool 错误（非 API 场景）：
    raise AgentError("LLM 调用超时", agent_id="analyst-001")
    raise ToolError("API Key 未配置", tool_name="threat_intel")
"""

from typing import Optional, Any


# ═══════════════════════════════════════════════════════════
# 内部 Agent/Tool 异常体系（非 HTTP 场景）
# ═══════════════════════════════════════════════════════════

class AgentError(Exception):
    """
    Agent 执行异常，用于 Agent 内部错误传递（非 HTTP API 场景）。

    所有 Agent 内部（base.py / analyst.py / intel.py 等）统一抛出此异常，
    由 process_message() 的 except 块统一捕获并转换为 yield chunk。

    错误码体系:
        AGENT_ERROR      — Agent 通用错误
        TOOL_ERROR       — 工具调用失败
        LLM_ERROR        — LLM 调用失败
        ROUTE_ERROR      — 路由到不存在的 Agent
        TIMEOUT_ERROR    — 操作超时
        CONFIG_ERROR     — 配置缺失
    """
    def __init__(self, message: str, *, agent_id: str = "",
                 code: str = "AGENT_ERROR", recoverable: bool = True,
                 details: Optional[dict] = None):
        self.agent_id = agent_id
        self.code = code
        self.recoverable = recoverable
        self.details = details or {}
        super().__init__(message)


class ToolError(AgentError):
    """工具调用失败"""
    def __init__(self, message: str, *, tool_name: str = "", **kwargs):
        kwargs.setdefault("code", "TOOL_ERROR")
        self.tool_name = tool_name
        super().__init__(message, **kwargs)


class LLMError(AgentError):
    """LLM 调用失败（超时/限流/网络错误）"""
    def __init__(self, message: str, *, provider: str = "", **kwargs):
        kwargs.setdefault("code", "LLM_ERROR")
        kwargs.setdefault("recoverable", True)
        self.provider = provider
        super().__init__(message, **kwargs)


class RouteError(AgentError):
    """Agent 路由错误"""
    def __init__(self, message: str, *, target_agent: str = "", **kwargs):
        kwargs.setdefault("code", "ROUTE_ERROR")
        self.target_agent = target_agent
        super().__init__(message, **kwargs)


# ═══════════════════════════════════════════════════════════
# 错误码定义（API 场景）
# ═══════════════════════════════════════════════════════════

# 条件导入 FastAPI（无 FastAPI 时降级为纯 Python 实现）
try:
    from fastapi.responses import JSONResponse
    from fastapi import HTTPException
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False


ERROR_CODES = {
    # ─── 认证相关 (AUTH-*) ───
    "AUTH_TOKEN_MISSING":       (401, "缺少认证令牌"),
    "AUTH_TOKEN_EXPIRED":       (401, "令牌已过期"),
    "AUTH_TOKEN_INVALID":       (401, "无效令牌"),
    "AUTH_WRONG_CREDENTIALS":   (401, "用户名或密码错误"),
    "AUTH_FORBIDDEN":           (403, "权限不足"),
    "AUTH_PASSWORD_NOT_SET":    (500, "未配置安全的管理员凭据，请设置 SECAGENTX_PASSWORD 或 SECAGENTX_PASSWORD_HASH"),

    # ─── 速率限制 (RATE-*) ───
    "RATE_LIMIT_EXCEEDED":      (429, "请求过于频繁，请稍后重试"),

    # ─── 资源相关 (RES-*) ───
    "RES_NOT_FOUND":            (404, "请求的资源不存在"),
    "RES_ALREADY_EXISTS":       (409, "资源已存在"),
    "RES_EVENT_NOT_FOUND":      (404, "事件不存在"),
    "RES_TECHNIQUE_NOT_FOUND":  (404, "MITRE ATT&CK 技术不存在"),

    # ─── WebSocket (WS-*) ───
    "WS_TOKEN_REQUIRED":        (401, "WebSocket 需要 token 参数 (ws://host/ws/chat?token=xxx)"),

    # ─── 自动操作 (AUTO-*) ───
    "AUTO_NOT_ENABLED":         (400, "零人工干预模式未启用（需在 config.yaml 设置 auto_operation.enabled=true）"),
    "AUTO_PATROL_NOT_ENABLED":  (400, "AutoPatrol 未启用"),
    "AUTO_QUEUE_FULL":          (503, "告警队列已满，请稍后重试"),

    # ─── 联邦模块 (FED-*) ───
    "FED_NOT_ENABLED":          (400, "跨区域联邦模块未启用"),
    "FED_AUTH_FAILED":          (403, "联邦认证失败，Token 无效或已过期"),

    # ─── 配置相关 (CFG-*) ───
    "CFG_LLM_MISSING":          (500, "LLM API Key 未配置，请设置 DEEPSEEK_API_KEY"),
    "CFG_THREAT_INTEL_MISSING": (500, "威胁情报 API Key 未配置"),

    # ─── 防火墙 (FW-*) ───
    "FW_BACKEND_UNSUPPORTED":   (400, "不支持的防火墙后端类型"),

    # ─── 通用 (GEN-*) ───
    "GEN_INTERNAL_ERROR":       (500, "服务器内部错误"),
    "GEN_BAD_REQUEST":          (400, "请求参数有误"),
    "GEN_NOT_FOUND":            (404, "接口不存在"),
}


# ─── 条件定义 AppError ───
# 有 FastAPI 时继承 HTTPException（可 raise 在路由中）
# 无 FastAPI 时继承普通 Exception

if _HAS_FASTAPI:

    class AppError(HTTPException):
        """
        应用级错误，可直接在 FastAPI 路由中 raise。

        示例:
            raise AppError("EVENT_NOT_FOUND")
            raise AppError("AUTH_TOKEN_EXPIRED", "自定义信息")
        """

        def __init__(self, code: str, message: Optional[str] = None, *,
                     extra: Optional[dict] = None, headers: Optional[dict] = None):
            err_info = ERROR_CODES.get(code, (500, "未知错误"))
            status_code = err_info[0]
            detail_message = message or err_info[1]
            self.error_code = code
            detail = {
                "error": {
                    "code": code,
                    "message": detail_message,
                },
            }
            if extra:
                detail["error"].update(extra)
            super().__init__(
                status_code=status_code,
                detail=detail,
                headers=headers,
            )

else:

    class AppError(Exception):
        """应用级错误（无 FastAPI 环境降级版）"""
        def __init__(self, code: str, message: Optional[str] = None, *,
                     extra: Optional[dict] = None, headers: Optional[dict] = None):
            err_info = ERROR_CODES.get(code, (500, "未知错误"))
            self.status_code = err_info[0]
            self.error_code = code
            self.detail = {
                "error": {
                    "code": code,
                    "message": message or err_info[1],
                },
            }
            if extra:
                self.detail["error"].update(extra)
            super().__init__(self.detail["error"]["message"])


def error_response(code: str, message: Optional[str] = None,
                   extra: Optional[dict] = None,
                   headers: Optional[dict] = None):
    """
    构建统一错误响应。

    参数:
        code: 错误码（必须在 ERROR_CODES 中定义，或自定义）
        message: 错误描述（可选，默认使用 ERROR_CODES 中定义的）
        extra: 额外信息（可选，会合并到 error 对象中）
        headers: 自定义 HTTP 头（可选）

    返回:
        JSONResponse 对象（有 FastAPI 时）或 dict（无 FastAPI 时）
    """
    err_info = ERROR_CODES.get(code, (500, message or "未知错误"))
    status_code = err_info[0]
    detail_message = message or err_info[1]

    body = {
        "error": {
            "code": code,
            "message": detail_message,
        },
    }
    if extra:
        body["error"].update(extra)

    if _HAS_FASTAPI:
        return JSONResponse(
            status_code=status_code,
            content=body,
            headers=headers,
        )
    # 无 FastAPI 时返回 dict（调用方自行处理）
    return {"status_code": status_code, "body": body, "headers": headers}


def success_response(data: Any, message: str = "ok"):
    """
    构建统一成功响应（可选）。

    示例:
        return success_response({"events": [...]})
    """
    body = {
        "success": True,
        "message": message,
        "data": data,
    }
    if _HAS_FASTAPI:
        return JSONResponse(status_code=200, content=body)
    return {"status_code": 200, "body": body}
