import os
import sys
import json
import asyncio
import difflib
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# 统一环境初始化 (加载 .env + 设置项目根目录)
from backend.utils.env import init_environment
init_environment()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.main import load_config, init_application, init_db
from backend.orchestrator.core import Orchestrator
from backend.knowledge.mitre_attack import MitreAttackKnowledge, TECHNIQUES_INDEX
from backend.knowledge.cve_db import CVEDatabase
from backend.knowledge.compliance import ComplianceKnowledge
from backend.knowledge.remediation import RemediationKnowledge
from backend.storage.repositories.conversation_repo import ConversationRepository
from backend.storage.database import Database, get_repository
from backend.utils.logger import logger
from backend.errors import error_response, AppError, ERROR_CODES
from backend.monitoring.metrics import (
    record_alert, record_http_request, set_queue_size,
    set_circuit_breaker as set_cb_metric,
)
from pydantic import BaseModel

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request, Depends, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.exception_handlers import http_exception_handler
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


class WebSocketManager:
    def __init__(self):
        self.connections: dict[str, WebSocket] = {}

    async def connect(self, ws_id: str, ws: WebSocket):
        await ws.accept()
        self.connections[ws_id] = ws

    def disconnect(self, ws_id: str):
        self.connections.pop(ws_id, None)

    async def broadcast(self, message: dict):
        dead = []
        for ws_id, ws in self.connections.items():
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws_id)
        for ws_id in dead:
            self.disconnect(ws_id)


orchestrator: Optional[Orchestrator] = None
ws_manager = WebSocketManager()


# ═══════════ 话题切换检测（v2.5：切断跨话题历史串味） ═══════════
# 同一 WS 会话内连续提问时，若当前问题与最近一轮历史提问相似度低，
# 视为"新话题"，不注入旧历史 —— 防止 LLM 把新问题当作旧分析的延续。
TOPIC_SIM_THRESHOLD = 0.20    # 低于此相似度 → 判定为新话题，不注入历史

# 追问信号：新文本含这些承接词 → 视为对上一话题的追问，保留历史
TOPIC_FOLLOWUP_MARKERS = (
    "这个", "该IP", "这个IP", "它", "其", "该", "继续", "另外", "还有",
    "那", "哪些", "具体", "进一步", "如何", "补充", "还有没有",
)


def _is_new_topic(new_text: str, last_user_text: str) -> bool:
    """判断当前提问是否为全新话题（与最近一轮用户提问比较）。"""
    if not last_user_text:
        return False
    # 追问信号：新问题包含承接词 → 视为追问同一话题
    for marker in TOPIC_FOLLOWUP_MARKERS:
        if marker in new_text:
            return False
    # 相似度：字符 bigram Jaccard
    def bigrams(s: str):
        s = (s or "").strip()
        return {s[i:i+2] for i in range(max(0, len(s)-1))}
    a, b = bigrams(new_text), bigrams(last_user_text)
    if not a or not b:
        return True
    inter = len(a & b)
    sim = inter / (len(a) + len(b) - inter) if (len(a) + len(b) - inter) else 0
    return sim < TOPIC_SIM_THRESHOLD


def create_app() -> Optional[FastAPI]:
    if not HAS_FASTAPI:
        logger.warning("fastapi not installed. run: pip install fastapi uvicorn websockets")
        return None

    global orchestrator
    config = load_config()
    orchestrator = init_application(config)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """管理后台任务的启动和关闭"""
        _bg_tasks = []
        auto_modules = getattr(orchestrator, '_auto_modules', {})

        # 启动后台任务
        ingestor = auto_modules.get('ingestor')
        if ingestor and hasattr(ingestor, 'start'):
            task = asyncio.ensure_future(ingestor.start())
            _bg_tasks.append(task)
            logger.info("[auto] 告警接入器: 已启动")

        email_ingestor = auto_modules.get('email_ingestor')
        if email_ingestor and hasattr(email_ingestor, 'start'):
            task = asyncio.ensure_future(email_ingestor.start())
            _bg_tasks.append(task)
            logger.info("[auto] 邮件接入器: 已启动")

        patrol = auto_modules.get('patrol')
        if patrol and hasattr(patrol, 'start'):
            task = asyncio.ensure_future(patrol.start())
            _bg_tasks.append(task)
            logger.info(f"[auto] 安全巡检器: 已启动")

        yield

        # 关闭后台任务
        for task in _bg_tasks:
            task.cancel()
        if _bg_tasks:
            await asyncio.gather(*_bg_tasks, return_exceptions=True)
            logger.info(f"[auto] 后台任务已关闭 ({len(_bg_tasks)} 个)")

    app = FastAPI(title="SecAgentX API", version="3.1.0", lifespan=lifespan)

    # ═══════════════════════ 安全中间件 ═══════════════════════

    # CORS 加固 — 限制来源域名
    _server_port = os.getenv("SECAGENTX_PORT", "8000").strip() or "8000"
    _default_origins = ",".join((
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5173", "http://127.0.0.1:5173",
        f"http://localhost:{_server_port}", f"http://127.0.0.1:{_server_port}",
    ))
    ALLOWED_ORIGINS = os.getenv(
        "SECAGENTX_CORS_ORIGINS",
        _default_origins,
    ).split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token",
        ],
    )
    _allowed_hosts = [
        item.strip() for item in os.getenv("SECAGENTX_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    ]
    if _allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)

    def _apply_security_headers(request: Request, response) -> None:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' ws: wss:; "
            "font-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        if request.url.scheme == "https" or os.getenv(
            "SECAGENTX_FORCE_HSTS", ""
        ).lower() in ("1", "true", "yes"):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

    # 请求追踪中间件（生产可观测性）— 为每个请求分配唯一 trace_id
    @app.middleware("http")
    async def trace_middleware(request: Request, call_next):
        import uuid
        import time
        trace_id = getattr(request.state, "trace_id", "") or (
            request.headers.get("X-Request-ID", "") or uuid.uuid4().hex[:16]
        )
        request.state.trace_id = trace_id
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        record_http_request(
            request.method, route_path, response.status_code, duration_ms / 1000
        )
        response.headers["X-Request-ID"] = trace_id
        # 记录慢请求（>2s）便于排查
        if duration_ms > 2000:
            logger.warning(
                f"[trace:{trace_id}] 慢请求 {request.method} {request.url.path} "
                f"耗时 {duration_ms:.0f}ms"
            )
        return response

    # 速率限制中间件（防止 API 滥用）
    @app.middleware("http")
    async def ratelimit_middleware(request: Request, call_next):
        path = request.url.path
        client_ip = request.client.host if request.client else "unknown"

        # 监控采集与容器探针不限流，避免健康检查自身造成故障放大。
        if path in (
            "/api/metrics", "/api/health", "/api/health/live", "/api/health/ready",
        ):
            return await call_next(request)

        from backend.security.ratelimit import ratelimiter
        allowed, retry_after = await ratelimiter.check(path, client_ip)
        if not allowed:
            return error_response(
                "RATE_LIMIT_EXCEEDED",
                extra={"retry_after": retry_after},
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    # 认证中间件（除开放路径外的所有 API 都需要 JWT）
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        method = request.method

        # 开放路径跳过认证
        from backend.security.auth import is_open_path
        if is_open_path(path):
            return await call_next(request)

        # WebSocket 认证在 ws handler 内完成（返回 HTTP 错误对 WS 无效）
        if path.startswith("/ws/"):
            return await call_next(request)

        # API 路径需要 Bearer Token
        if path.startswith("/api") or path.startswith("/webhook"):
            from backend.security.auth import (
                WEB_ACCESS_COOKIE,
                WEB_CSRF_COOKIE,
                get_bearer_token_from_request,
                verify_token,
            )
            try:
                credentials = await get_bearer_token_from_request(request)
                cookie_authenticated = (
                    credentials is None and bool(request.cookies.get(WEB_ACCESS_COOKIE))
                )
                if credentials is None and not cookie_authenticated:
                    return error_response("AUTH_TOKEN_MISSING")
                if cookie_authenticated and method in {"POST", "PUT", "PATCH", "DELETE"}:
                    csrf_cookie = request.cookies.get(WEB_CSRF_COOKIE, "")
                    csrf_header = request.headers.get("X-CSRF-Token", "")
                    import hmac
                    if not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_header):
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": {
                                    "code": "AUTH_CSRF_INVALID",
                                    "message": "CSRF 校验失败",
                                }
                            },
                        )
                await verify_token(credentials, request)
            except Exception as e:
                err_str = str(e)
                if "expired" in err_str.lower():
                    return error_response("AUTH_TOKEN_EXPIRED")
                return error_response("AUTH_TOKEN_INVALID", message=err_str)
            return await call_next(request)

        return await call_next(request)

    # 最外层响应加固：认证/限流的提前返回也必须包含安全头和请求 ID。
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        import uuid
        request.state.trace_id = (
            request.headers.get("X-Request-ID", "") or uuid.uuid4().hex[:16]
        )
        response = await call_next(request)
        response.headers.setdefault("X-Request-ID", request.state.trace_id)
        _apply_security_headers(request, response)
        return response

    # 全局异常处理器 — 敏感信息脱敏
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        from backend.security.sanitizer import sanitize_error
        sanitized = sanitize_error(str(exc))
        logger.error(
            f"未捕获异常: {sanitized}",
            extra={"path": request.url.path},
        )
        return error_response("GEN_INTERNAL_ERROR", message=sanitized)

    # ═══════════════════ 托管前端静态文件 ═══════════════════
    from fastapi.staticfiles import StaticFiles
    from backend.runtime_assets import frontend_dist as resolve_frontend_dist
    frontend_dist = str(resolve_frontend_dist())
    if os.path.exists(frontend_dist):
        app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

        @app.get("/")
        async def serve_frontend():
            from fastapi.responses import FileResponse
            return FileResponse(os.path.join(frontend_dist, "index.html"))

        @app.exception_handler(404)
        async def spa_fallback(request, exc):
            """Vue SPA fallback: 所有非 API 路由返回 index.html"""
            from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
            path = request.url.path
            if path.startswith("/api") or path.startswith("/ws") or path.startswith("/webhook"):
                return JSONResponse({"error": "Not Found"}, status_code=404)

            # ─── 修复: 子路由下被 SPA fallback 吞掉的静态资源请求 ───
            # 前端 vite 使用 base:'./' 构建(为兼容 OpenIM /secagentx/ 子路径部署)，
            # index.html 中资源为相对路径 ./assets/xxx.js。
            # 独立部署时若在 /chat、/dashboard 等子路由刷新页面，浏览器会把
            # ./assets/xxx.js 解析为 /chat/assets/xxx.js，被本 fallback 捕获并返回
            # index.html(HTML)，浏览器将其当作 JS 执行 → 语法错误 → 白屏。
            #
            # 修复: 识别这类被吞掉的资源请求并重定向到真实 /assets/ 路径。
            if "/assets/" in path:
                asset_rel = path.split("/assets/", 1)[1]
                real_asset = os.path.join(frontend_dist, "assets", asset_rel)
                if os.path.isfile(real_asset):
                    return RedirectResponse(f"/assets/{asset_rel}", status_code=301)
                return JSONResponse({"error": "Not Found"}, status_code=404)

            # 其他带扩展名的静态资源请求(非 assets 目录)：直接 404，
            # 避免把 HTML 当 JS/CSS 返回导致白屏
            ext = os.path.splitext(path)[1].lower()
            if ext in {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                       ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".webm"}:
                return JSONResponse({"error": "Not Found"}, status_code=404)

            # 正常 SPA 路由(不带扩展名) → 返回 index.html
            index_path = os.path.join(frontend_dist, "index.html")
            if os.path.exists(index_path):
                return FileResponse(index_path)
            return JSONResponse({"error": "Not Found"}, status_code=404)
        logger.info(f"serving frontend from: {frontend_dist}")
    else:
        logger.info(f"frontend dist not found at {frontend_dist}, API-only mode")

    # ═══════════════════════ 认证 API ═══════════════════════

    from backend.security.auth import (
        ACCESS_TOKEN_EXPIRE_MINUTES,
        REFRESH_TOKEN_EXPIRE_MINUTES,
        WEB_ACCESS_COOKIE,
        WEB_CSRF_COOKIE,
        WEB_REFRESH_COOKIE,
        RefreshTokenInvalid,
        RefreshTokenReuseDetected,
        create_access_token,
        create_refresh_token,
        revoke_refresh_token_family,
        rotate_refresh_token,
        LoginBody,
    )
    from backend.security.rbac import get_user_manager
    user_manager = get_user_manager()  # 启动时即校验管理员初始凭据

    _cookie_secure = os.getenv("SECAGENTX_COOKIE_SECURE", "").lower() in (
        "1", "true", "yes",
    )

    def _require_allowed_web_origin(request: Request) -> None:
        origin = (request.headers.get("origin") or "").rstrip("/")
        allowed = {item.strip().rstrip("/") for item in ALLOWED_ORIGINS if item.strip()}
        if origin and origin not in allowed:
            raise HTTPException(status_code=403, detail="Web 登录来源不在允许列表")

    def _set_web_auth_cookies(response, access_token: str, refresh_token: str) -> None:
        import secrets
        csrf_token = secrets.token_urlsafe(32)
        common = {
            "secure": _cookie_secure,
            "samesite": "strict",
        }
        response.set_cookie(
            WEB_ACCESS_COOKIE,
            access_token,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True,
            path="/",
            **common,
        )
        response.set_cookie(
            WEB_REFRESH_COOKIE,
            refresh_token,
            max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True,
            path="/api/auth/web",
            **common,
        )
        response.set_cookie(
            WEB_CSRF_COOKIE,
            csrf_token,
            max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60,
            httponly=False,
            path="/",
            **common,
        )
        response.headers["Cache-Control"] = "no-store"

    def _clear_web_auth_cookies(response) -> None:
        response.delete_cookie(WEB_ACCESS_COOKIE, path="/")
        response.delete_cookie(WEB_REFRESH_COOKIE, path="/api/auth/web")
        response.delete_cookie(WEB_CSRF_COOKIE, path="/")
        response.headers["Cache-Control"] = "no-store"

    @app.post("/api/auth/login")
    async def login(body: LoginBody):
        """登录获取 JWT 双令牌（access_token + refresh_token）

        使用 RBAC UserManager 进行用户认证，支持多用户（admin/operator/analyst/viewer）。
        """
        user = user_manager.authenticate(body.username, body.password)
        if not user:
            return error_response("AUTH_WRONG_CREDENTIALS")

        access_token = create_access_token(
            sub=user.username, role=user.role, token_version=user.token_version
        )
        refresh_token = create_refresh_token(
            sub=user.username, role=user.role, token_version=user.token_version
        )

        # ─── OpenIM 账号同步钩子（异步，不影响登录响应） ───
        # 登录成功后，自动将用户同步到 OpenIM（通过桥接器）
        try:
            bridge_url = os.getenv("OPENIM_BRIDGE_URL", "").rstrip("/")
            if bridge_url:
                asyncio.ensure_future(_sync_user_to_openim(
                    bridge_url, user.username,
                    user.display_name or user.username, user.role,
                ))
        except Exception as _sync_e:
            logger.warning(f"OpenIM 账号同步钩子异常: {_sync_e}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": REFRESH_TOKEN_EXPIRE_MINUTES * 60,
            "user": user.to_dict(),
        }


    async def _sync_user_to_openim(bridge_url: str, username: str,
                                   display_name: str, role: str) -> None:
        """异步调用桥接器同步用户到 OpenIM（失败仅记录日志）"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{bridge_url}/account/sync",
                    json={
                        "username": username,
                        "display_name": display_name,
                        "role": role,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success"):
                        logger.info(f"OpenIM 账号自动同步成功: {username} → {data.get('openim_user_id')}")
                    else:
                        logger.warning(f"OpenIM 账号同步返回失败: {username}: {data}")
                else:
                    logger.warning(f"OpenIM 账号同步 HTTP {resp.status_code}")
        except Exception as e:
            logger.warning(f"OpenIM 账号同步异常: {e}")

    class RefreshBody(BaseModel):
        refresh_token: str

    @app.post("/api/auth/refresh")
    async def refresh_token(body: RefreshBody):
        """使用 refresh_token 换取新的 access_token + refresh_token

        请求体: {"refresh_token": "..."}
        返回: 新的 access_token + refresh_token（轮换机制：旧 refresh_token 不再有效）
        """
        try:
            new_access, new_refresh, expires_in = rotate_refresh_token(body.refresh_token)
            return {
                "access_token": new_access,
                "refresh_token": new_refresh,
                "token_type": "bearer",
                "expires_in": expires_in,
                "refresh_expires_in": REFRESH_TOKEN_EXPIRE_MINUTES * 60,
            }
        except RefreshTokenReuseDetected as e:
            return error_response("AUTH_TOKEN_INVALID", message=str(e))
        except RefreshTokenInvalid as e:
            return error_response("AUTH_TOKEN_INVALID", message=str(e))
        except Exception as e:
            err_msg = str(e)
            if "expired" in err_msg.lower():
                return error_response("AUTH_TOKEN_EXPIRED", message="refresh_token 已过期，请重新登录")
            return error_response("AUTH_TOKEN_INVALID", message=f"无效的 refresh_token: {err_msg}")

    @app.post("/api/auth/web/login")
    async def web_login(body: LoginBody, request: Request):
        """浏览器专用登录：令牌只写入 HttpOnly Cookie，不返回给 JavaScript。"""
        _require_allowed_web_origin(request)
        user = user_manager.authenticate(body.username, body.password)
        if not user:
            return error_response("AUTH_WRONG_CREDENTIALS")
        access_token = create_access_token(
            sub=user.username, role=user.role, token_version=user.token_version
        )
        refresh_token_value = create_refresh_token(
            sub=user.username, role=user.role, token_version=user.token_version
        )
        response = JSONResponse({
            "status": "ok",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user.to_dict(),
        })
        _set_web_auth_cookies(response, access_token, refresh_token_value)
        return response

    @app.post("/api/auth/web/refresh")
    async def web_refresh(request: Request):
        """轮换 HttpOnly refresh Cookie，并重新签发浏览器会话。"""
        _require_allowed_web_origin(request)
        token = request.cookies.get(WEB_REFRESH_COOKIE, "")
        if not token:
            return error_response("AUTH_TOKEN_MISSING", message="缺少 Web 刷新会话")
        try:
            new_access, new_refresh, expires_in = rotate_refresh_token(token)
            response = JSONResponse({"status": "ok", "expires_in": expires_in})
            _set_web_auth_cookies(response, new_access, new_refresh)
            return response
        except (RefreshTokenReuseDetected, RefreshTokenInvalid) as exc:
            response = error_response("AUTH_TOKEN_INVALID", message=str(exc))
            _clear_web_auth_cookies(response)
            return response
        except Exception as exc:
            response = error_response("AUTH_TOKEN_INVALID", message=str(exc))
            _clear_web_auth_cookies(response)
            return response

    @app.post("/api/auth/web/logout")
    async def web_logout(request: Request):
        """撤销浏览器 refresh 会话并清除全部认证 Cookie。"""
        _require_allowed_web_origin(request)
        token = request.cookies.get(WEB_REFRESH_COOKIE, "")
        if token:
            revoke_refresh_token_family(token)
        response = JSONResponse({"status": "ok"})
        _clear_web_auth_cookies(response)
        return response


    # ═══════════════════════ 用户管理 API ═══════════════════════
    from backend.security.auth import verify_token
    from backend.security.rbac import require_permission

    @app.get("/api/users")
    async def list_users(_=Depends(require_permission("admin:users"))):
        """列出所有用户（需要 admin:users 权限）"""
        mgr = get_user_manager()
        return {"users": mgr.list_users()}

    class CreateUserBody(BaseModel):
        username: str
        password: str
        role: str = "viewer"
        display_name: str = ""

    @app.post("/api/users")
    async def create_user(body: CreateUserBody,
                          _=Depends(require_permission("admin:users"))):
        """创建用户（需要 admin:users 权限）"""
        mgr = get_user_manager()
        try:
            user = mgr.create_user(
                username=body.username,
                password=body.password,
                role=body.role,
                display_name=body.display_name,
            )
            return {"status": "ok", "user": user.to_dict()}
        except ValueError as e:
            return error_response("USER_CREATE_FAILED", message=str(e))

    class UpdateUserBody(BaseModel):
        role: str = None
        enabled: bool = None
        display_name: str = None
        password: str = None

    @app.put("/api/users/{username}")
    async def update_user(username: str, body: UpdateUserBody,
                          _=Depends(require_permission("admin:users"))):
        """更新用户信息（需要 admin:users 权限）"""
        mgr = get_user_manager()
        try:
            user = mgr.update_user(
                username=username,
                role=body.role,
                enabled=body.enabled,
                display_name=body.display_name,
                password=body.password,
            )
            if not user:
                return error_response("USER_NOT_FOUND", message=f"用户不存在: {username}")
            return {"status": "ok", "user": user.to_dict()}
        except ValueError as e:
            return error_response("USER_UPDATE_FAILED", message=str(e))

    @app.delete("/api/users/{username}")
    async def delete_user(username: str,
                          _=Depends(require_permission("admin:users"))):
        """删除用户（需要 admin:users 权限）"""
        mgr = get_user_manager()
        try:
            if mgr.delete_user(username):
                return {"status": "ok", "message": f"用户 {username} 已删除"}
            return error_response("USER_NOT_FOUND", message=f"用户不存在: {username}")
        except ValueError as e:
            return error_response("USER_DELETE_FAILED", message=str(e))

    @app.get("/api/users/me")
    async def current_user(token=Depends(verify_token)):
        """获取当前用户信息"""
        mgr = get_user_manager()
        user = mgr.get_user(token.sub)
        if not user:
            return error_response("USER_NOT_FOUND")
        result = user.to_dict()
        result["permissions"] = sorted(list(
            __import__("backend.security.rbac", fromlist=["ROLE_PERMISSIONS"]).ROLE_PERMISSIONS.get(user.role, set())
        ))
        return result

    # ═══════════════════════ 健康检查 API ═══════════════════════

    @app.get("/api/health/live")
    async def liveness():
        """进程存活探针，不依赖外部 Provider。"""
        return {"status": "ok", "service": "secagentx", "version": "3.1.0"}

    @app.get("/api/health/ready")
    async def readiness():
        """流量接入探针：核心调度器和数据库均可用才返回 200。"""
        try:
            if orchestrator is None:
                raise RuntimeError("orchestrator unavailable")
            async with get_repository() as repo:
                await repo.fetch_one("SELECT COUNT(*) as cnt FROM events")
            return {"status": "ready", "service": "secagentx", "version": "3.1.0"}
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "service": "secagentx"},
            )

    @app.get("/api/health")
    async def health():
        """详细的健康检查（含各组件状态）"""
        checks = {
            "status": "ok",
            "service": "secagentx",
            "version": "3.1.0",
            "timestamp": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
        }

        # 1. Agent 状态摘要（精简版，不暴露内部运行细节）
        agents = orchestrator.get_agent_statuses()
        checks["agents"] = [
            {"id": a["id"], "name": a["name"], "status": a["status"]}
            for a in agents
        ]

        # 2. 数据库检查
        try:
            async with get_repository() as repo:
                row = await repo.fetch_one("SELECT COUNT(*) as cnt FROM events")
            checks["database"] = "ok"
            checks["database_events"] = row["cnt"] if row else 0
        except Exception as e:
            checks["database"] = "error"
            checks["status"] = "degraded"

        # 3. LLM 只报告是否可用，不暴露厂商、模型或哪个 Key 已配
        deepseek_ok = bool(os.getenv("DEEPSEEK_API_KEY"))
        qwen_ok = bool(os.getenv("QWEN_API_KEY"))
        runtime_provider = bool(os.getenv("SECAGENTX_ACTIVE_PROVIDER"))
        runtime_key = bool(os.getenv("SECAGENTX_LLM_API_KEY"))
        no_key_provider = os.getenv("SECAGENTX_LLM_ALLOW_NO_KEY", "false").lower() == "true"
        llm_available = deepseek_ok or qwen_ok or (
            runtime_provider and (runtime_key or no_key_provider)
        )
        checks["llm"] = {
            "available": llm_available,
        }
        if not llm_available:
            checks["status"] = "degraded"

        # 4. 工具状态必须反映真实可用性，不能把缺失的本地库报告为 ready。
        threat_keys = ["VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"]
        local_threat_path = Path(os.getenv(
            "THREAT_IPS_PATH", "data/blacklist/threat_ips.json"
        ))
        threat_status = (
            "external_api" if any(os.getenv(k) for k in threat_keys)
            else "local_blacklist" if local_threat_path.is_file()
            else "unavailable"
        )
        firewall_backend = os.getenv("FIREWALL_BACKEND", "disabled")
        checks["tools"] = {
            "threat_intel": threat_status,
            "firewall": (
                "disabled" if firewall_backend == "disabled"
                else "test_only" if firewall_backend == "mock"
                else "ready"
            ),
        }

        # 5. 熔断器
        try:
            from backend.security.circuit_breaker import circuit_breaker
            cb = circuit_breaker.get_status()
            checks["circuit_breaker"] = {
                "state": cb["state"],
                "is_blocked": cb["is_blocked"],
                "blocks_today": cb["blocks_today"],
            }
        except Exception:
            pass

        return checks

    # ═══════════════════════ Prometheus 指标 API ═══════════════════════

    @app.get("/api/metrics")
    async def metrics():
        """Prometheus 格式的监控指标"""
        from backend.monitoring.metrics import get_metrics, set_active_blocks, set_agent_status
        from starlette.responses import Response

        # 更新实时指标
        try:
            from backend.security.circuit_breaker import circuit_breaker
            cb_status = circuit_breaker.get_status()
            set_cb_metric(cb_status.get("state", "closed"))

            # Agent 状态
            agents = orchestrator.get_agent_statuses()
            for a in agents:
                set_agent_status(a.get("id", ""), a.get("name", ""), a.get("status", "unknown"))

            # 活跃封禁数（通过防火墙工具查询）
            try:
                fw_result = await orchestrator.tools.execute("firewall_manage", action="list")
                if fw_result.success:
                    rules = fw_result.data.get("rules", [])
                    set_active_blocks(len(rules))
            except Exception:
                pass

            # 队列大小
            auto_mods = orchestrator.get_auto_modules()
            ingestor = auto_mods.get("ingestor")
            if ingestor:
                stats = ingestor.get_stats()
                set_queue_size(stats.get("queue_size", 0))
        except Exception:
            pass

        metrics_data = get_metrics()
        return Response(
            content=metrics_data,
            media_type="text/plain; charset=utf-8",
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/api/stats", dependencies=[Depends(require_permission("dashboard:view"))])
    async def stats():
        """系统统计（含 Agent 状态和数据库真实数据指标）"""
        base = orchestrator.get_stats()
        # 补充数据库统计
        try:
            from backend.storage.database import get_repository
            async with get_repository() as repo:
                ev_total = (await repo.fetch_one("SELECT COUNT(*) as c FROM events"))["c"] or 0
                ev_open = (await repo.fetch_one("SELECT COUNT(*) as c FROM events WHERE status='open'"))["c"] or 0
                ev_high = (await repo.fetch_one("SELECT COUNT(*) as c FROM events WHERE severity='紧急' OR severity='高危'"))["c"] or 0
                ioc_total = (await repo.fetch_one("SELECT COUNT(*) as c FROM ioc_database"))["c"] or 0
                src_ips = (await repo.fetch_one("SELECT COUNT(DISTINCT source_ip) as c FROM events"))["c"] or 0
            base.update({
                "events_total": ev_total,
                "events_open": ev_open,
                "events_high_severity": ev_high,
                "ioc_total": ioc_total,
                "unique_source_ips": src_ips,
            })
        except Exception:
            pass
        return base

    # ==================== 零人工干预 API ====================

    class AlertWebhookBody(BaseModel):
        """Webhook 告警数据模型"""
        id: str = ""
        title: str = ""
        description: str = ""
        src_ip: str = ""
        source_ip: str = ""  # 兼容不同字段名
        dst_ip: str = ""
        severity: str = "中危"
        alert_type: str = ""
        timestamp: str = ""

    @app.post("/webhook/alert", dependencies=[Depends(require_permission("events:write"))])
    async def webhook_alert(alert: AlertWebhookBody):
        """
        Webhook 告警接入端点

        企业平台只需 POST JSON 到 /webhook/alert，SecAgentX 将自动:
        1. 分析告警
        2. 评估置信度
        3. 按阈值自动处置（封禁/闭环/升级通知）

        请求示例:
        {
            "id": "alert-001",
            "title": "SSH暴力破解",
            "description": "源IP 45.33.32.156 在5分钟内进行了100次SSH登录尝试",
            "src_ip": "45.33.32.156",
            "severity": "高危"
        }
        """
        auto_mods = orchestrator.get_auto_modules()
        ingestor = auto_mods.get("ingestor")

        if not ingestor:
            return error_response("AUTO_NOT_ENABLED")

        # 合并兼容字段
        alert_dict = alert.model_dump()
        if not alert_dict.get("src_ip") and alert_dict.get("source_ip"):
            alert_dict["src_ip"] = alert_dict["source_ip"]

        result = await ingestor.handle_webhook(alert_dict)

        # Prometheus 指标记录
        action = result.get("action", "unknown")
        record_alert(action)

        return result

    @app.get("/api/auto/status", dependencies=[Depends(require_permission("dashboard:view"))])
    async def auto_operation_status():
        """获取零人工干预模块的运行状态"""
        auto_mods = orchestrator.get_auto_modules()
        # 数据保留策略状态
        retention_status = None
        try:
            from backend.storage.retention import DataRetention
            config = orchestrator.get_config() if hasattr(orchestrator, 'get_config') else {}
            retention = DataRetention(config.get("auto_operation", {}))
            retention_status = retention.get_summary()
        except Exception:
            pass

        return {
            "enabled": bool(auto_mods),
            "ingestor": auto_mods.get("ingestor", {}).get_stats() if auto_mods.get("ingestor") else None,
            "patrol": auto_mods.get("patrol", {}).get_stats() if auto_mods.get("patrol") else None,
            "escalation": auto_mods.get("escalator", {}).get_status() if auto_mods.get("escalator") else None,
            "data_retention": retention_status,
        }

    @app.post("/api/auto/patrol", dependencies=[Depends(require_permission("events:write"))])
    async def trigger_patrol():
        """手动触发一次巡检"""
        auto_mods = orchestrator.get_auto_modules()
        patrol = auto_mods.get("patrol")
        if not patrol:
            return error_response("AUTO_PATROL_NOT_ENABLED")
        result = await patrol.patrol_once()
        return {"status": "ok", "result": result}

    # ═══════════════════ 跨区域联邦 API ═══════════════════
    # 联邦 API 依赖: 验证对端 Token
    async def verify_federation_request(request: Request):
        """FastAPI 依赖: 验证跨区域同步请求的身份"""
        from backend.federation.core import verify_peer_request
        valid, detail = await verify_peer_request(request)
        if not valid:
            from fastapi.responses import JSONResponse
            raise HTTPException(status_code=403, detail=f"联邦认证失败: {detail}")
        return detail  # 返回 region_id

    @app.get("/api/federation/status", dependencies=[Depends(require_permission("dashboard:view"))])
    async def federation_status():
        """获取跨区域联邦状态（所有对端区域健康状态）"""
        fed = getattr(orchestrator, "_federation", None)
        if not fed:
            return {"enabled": False, "error": "联邦模块未初始化"}
        return fed.get_status()

    class FederationEventBody(BaseModel):
        events: list[dict] = []
        source_region: str = ""

    @app.post("/api/federation/events",
              dependencies=[Depends(verify_federation_request)])
    async def federation_receive_events(body: FederationEventBody):
        """接收对端区域推送的事件（由对端 Federation 调用，需验证 Token）"""
        fed = getattr(orchestrator, "_federation", None)
        if not fed or not fed.enabled:
            return error_response("FED_NOT_ENABLED")
        await fed._save_remote_events(body.source_region, body.events)
        return {"status": "ok", "received": len(body.events)}

    @app.get("/api/federation/events",
             dependencies=[Depends(verify_federation_request)])
    async def federation_get_events(limit: int = 100, since: str = "", exclude_region: str = ""):
        """
        提供给对端区域拉取事件（增量同步）

        防环路（修复版）:
          远程同步的事件 ID 前缀为 `fed-{region}-`，
          用 `WHERE id NOT LIKE 'fed-?-%%'` 在 SQL 层面过滤，
          不再依赖标题字符串匹配。
        """
        async with get_repository() as db:
            if since:
                if exclude_region:
                    exclude_pattern = f"fed-{exclude_region}-%"
                    rows = await db.fetch_all(
                        "SELECT * FROM events WHERE created_at > ? "
                        "AND id NOT LIKE ? "
                        "ORDER BY created_at ASC LIMIT ?",
                        (since, exclude_pattern, limit),
                    )
                else:
                    rows = await db.fetch_all(
                        "SELECT * FROM events WHERE created_at > ? ORDER BY created_at ASC LIMIT ?",
                        (since, limit),
                    )
            else:
                if exclude_region:
                    exclude_pattern = f"fed-{exclude_region}-%"
                    rows = await db.fetch_all(
                        "SELECT * FROM events WHERE id NOT LIKE ? "
                        "ORDER BY created_at DESC LIMIT ?",
                        (exclude_pattern, limit),
                    )
                else:
                    rows = await db.fetch_all(
                        "SELECT * FROM events ORDER BY created_at DESC LIMIT ?",
                        (limit,),
                    )
            events = []
            for r in rows:
                events.append({
                    "id": r["id"], "title": r["title"],
                    "severity": r["severity"], "status": r["status"],
                    "source_ip": r.get("source_ip", ""),
                    "description": r.get("description", ""),
                    "created_at": r["created_at"],
                })
            return {"events": events}

    class FederationBlacklistBody(BaseModel):
        entries: list[dict] = []
        source_region: str = ""

    @app.post("/api/federation/blacklist",
              dependencies=[Depends(verify_federation_request)])
    async def federation_receive_blacklist(body: FederationBlacklistBody):
        """接收对端区域推送的黑名单（由对端 Federation 调用，需验证 Token）"""
        fed = getattr(orchestrator, "_federation", None)
        if not fed or not fed.enabled:
            return error_response("FED_NOT_ENABLED")
        await fed._apply_remote_blacklist(body.source_region, body.entries)
        return {"status": "ok", "received": len(body.entries)}

    @app.get("/api/federation/blacklist",
             dependencies=[Depends(verify_federation_request)])
    async def federation_get_blacklist():
        """提供给对端区域拉取黑名单（需验证 Token）"""
        try:
            # 从 orchestrator 注册的防火墙工具获取实际后端，而非硬编码 mock
            fw = orchestrator.tools.get("firewall_manage")
            if not fw:
                return {"entries": [], "error": "防火墙工具未注册"}
            result = await fw.execute(action="list")
            if result.success:
                rules = result.data.get("rules", [])
                entries = [
                    {"ip": r["ip"], "reason": r.get("reason", ""),
                     "duration_minutes": r.get("duration_minutes", 120),
                     "blocked_at": r.get("blocked_at", "")}
                    for r in rules
                ]
                return {"entries": entries}
            return {"entries": []}
        except Exception as e:
            return {"entries": [], "error": str(e)}

    @app.get("/api/federation/dashboard", dependencies=[Depends(require_permission("dashboard:view"))])
    async def federation_dashboard():
        """跨区域统一安全仪表盘 — 聚合所有区域的事件和封禁状态"""
        fed = getattr(orchestrator, "_federation", None)
        if not fed or not fed.enabled:
            return {"enabled": False, "regions": [{"id": "local", "name": "本区域"}]}

        regions_data = []
        # 本区域
        async with get_repository() as db:
            row = await db.fetch_one("SELECT COUNT(*) as cnt FROM events")
            local_events = row["cnt"] if row else 0
            row2 = await db.fetch_one(
                "SELECT COUNT(*) as cnt FROM events WHERE status='open'"
            )
            open_events = row2["cnt"] if row2 else 0

        regions_data.append({
            "id": fed.region_id,
            "name": fed.region_name,
            "is_local": True,
            "is_healthy": True,
            "events": local_events,
            "open_events": open_events,
        })

        # 对端区域
        for peer in fed.get_peers():
            import httpx
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(
                        f"{peer.api_url}/api/health",
                        headers={"Authorization": f"Bearer {peer.api_token}"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        regions_data.append({
                            "id": peer.region_id,
                            "name": peer.region_name,
                            "is_local": False,
                            "is_healthy": True,
                            "events": data.get("database_events", 0),
                        })
                    else:
                        regions_data.append({
                            "id": peer.region_id,
                            "name": peer.region_name,
                            "is_local": False,
                            "is_healthy": False,
                        })
            except Exception:
                regions_data.append({
                    "id": peer.region_id,
                    "name": peer.region_name,
                    "is_local": False,
                    "is_healthy": False,
                })

        return {"enabled": True, "regions": regions_data}

    # ==================== 审计日志 API ====================
    @app.get("/api/audit/logs", dependencies=[Depends(require_permission("audit:read"))])
    async def list_audit_logs(
        target: str = "",
        action_type: str = "",
        limit: int = 50,
    ):
        """查询操作审计日志"""
        from backend.security.audit import audit_repo
        return {
            "logs": audit_repo.query(
                target=target, action_type=action_type, limit=min(limit, 200)
            )
        }

    @app.get("/api/audit/recent", dependencies=[Depends(require_permission("audit:read"))])
    async def recent_audit_logs(limit: int = 20):
        """获取最近的操作审计日志"""
        from backend.security.audit import audit_repo
        return {"logs": audit_repo.get_recent(limit=min(limit, 200))}

    @app.get("/api/auto/config", dependencies=[Depends(require_permission("admin:config"))])
    async def auto_operation_config():
        """返回当前零人工干预配置"""
        config = orchestrator.get_config()
        return config.get("auto_operation", {})

    @app.put("/api/admin/config", dependencies=[Depends(require_permission("admin:config"))])
    async def update_config(body: dict):
        """更新运行时配置（自动处置阈值、巡检间隔、数据保留策略等）"""
        if not orchestrator._auto_modules:
            raise HTTPException(status_code=503, detail="自动模块未初始化")
        try:
            old_config = orchestrator.get_config() or {}
            new_config = old_config.copy()
            auto_op = new_config.setdefault("auto_operation", {})

            if "auto_operation" in body:
                for key, val in body["auto_operation"].items():
                    if isinstance(val, dict) and isinstance(auto_op.get(key), dict):
                        auto_op[key].update(val)
                    else:
                        auto_op[key] = val

            if "data_retention" in body:
                dr = new_config.setdefault("auto_operation", {}).setdefault("data_retention", {})
                dr.update(body["data_retention"])

            import yaml
            config_path = os.getenv("SECAGENTX_CONFIG", "config.yaml")
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(new_config, f, allow_unicode=True, default_flow_style=False)

            logger.info(f"[config] 运行时配置已更新: {list(body.keys())}")
            return {"status": "ok", "updated_keys": list(body.keys())}
        except Exception as e:
            logger.error(f"[config] 配置更新失败: {e}")
            raise HTTPException(status_code=500, detail=f"配置保存失败: {e}")

    @app.get("/api/agents", dependencies=[Depends(require_permission("agents:read"))])
    async def list_agents():
        return {"agents": orchestrator.get_agent_statuses()}

    @app.get("/api/agents/runtime", dependencies=[Depends(require_permission("agents:read"))])
    async def agents_runtime():
        """Agent 运行时仪表盘数据（状态、延迟、Token 消耗）"""
        return {"agents": orchestrator.get_agent_runtime()}

    @app.get("/api/evaluation/agents", dependencies=[Depends(require_permission("agents:read"))])
    async def evaluation_agents():
        """Agent 评估评分卡（M5 确定性评分）"""
        try:
            from backend.evaluation.metrics import AgentMetrics
            from backend.evaluation.evaluator import AgentEvaluator
            metrics = AgentMetrics()
            result = await AgentEvaluator.evaluate_all(metrics)
            return result
        except Exception as e:
            logger.error(f"[evaluation] 评估计算失败: {e}")
            raise HTTPException(status_code=500, detail=f"评估计算失败: {e}")

    # ==================== 事件格式化辅助函数 ====================
    def _extract_raw(raw_str: str) -> dict:
        """安全解析 raw_data JSON 字段"""
        try:
            return json.loads(raw_str) if isinstance(raw_str, str) and raw_str.strip() else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def _format_event_list_item(r: dict) -> dict:
        """格式化事件列表项，从 raw_data 提取结构化字段"""
        raw = _extract_raw(r.get("raw_data", ""))
        desc = r.get("description", "") or ""

        # 优先使用 raw_data 中的结构化置信度
        confidence = raw.get("confidence", 0)
        if not confidence:
            import re
            conf_match = re.search(r'置信度\s*(\d+\.?\d*)%?', desc)
            confidence = min(float(conf_match.group(1)) / 100.0, 1.0) if conf_match else 0.75

        return {
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "status": r["status"],
            "source_ip": r["source_ip"],
            "alert_type": r["alert_type"],
            "technique_id": r.get("technique_id", ""),
            "tactic_id": r.get("tactic_id", ""),
            "description": (desc[:200] + "...") if len(desc) > 200 else desc,
            "confidence": round(confidence, 2),
            "cve_id": raw.get("cve_id", ""),
            "actor_name": raw.get("actor_name", ""),
            "malware_name": raw.get("malware_name", ""),
            "threat_sources": raw.get("threat_sources", []),
            "threat_level": raw.get("threat_level", ""),
            "dest_ip": raw.get("dest_ip", ""),
            "dest_port": raw.get("dest_port", 0),
            "protocol": raw.get("protocol", ""),
            "created_at": r["created_at"],
            "resolved_at": r.get("resolved_at"),
        }

    def _format_event_detail(r: dict) -> dict:
        """格式化事件详情，完整解析 raw_data"""
        raw = _extract_raw(r.get("raw_data", ""))
        desc = r.get("description", "") or ""

        # 置信度
        confidence = raw.get("confidence", 0)
        if not confidence:
            import re
            conf_match = re.search(r'置信度\s*(\d+\.?\d*)%?', desc)
            confidence = min(float(conf_match.group(1)) / 100.0, 1.0) if conf_match else 0.85

        # 技术映射
        techniques = raw.get("techniques", [])
        if not techniques and r.get("mitre_technique_id"):
            techniques = [{
                "id": r["mitre_technique_id"],
                "name": raw.get("mitre_technique_name", ""),
                "confidence": confidence,
                "tactic": r.get("mitre_tactic_id", ""),
                "tactic_name": raw.get("mitre_tactic_name", ""),
            }]

        return {
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "status": r["status"],
            "source_ip": r["source_ip"],
            "alert_type": r["alert_type"],
            "description": desc,
            "confidence": round(confidence, 2),
            "source": raw.get("source", "实时威胁情报"),
            "destination": raw.get("dest_ip", raw.get("destination", "Server-01")),
            "destination_port": raw.get("dest_port", None),
            "cve_id": raw.get("cve_id", ""),
            "actor_name": raw.get("actor_name", ""),
            "actor_country": raw.get("actor_country", ""),
            "malware_name": raw.get("malware_name", ""),
            "threat_sources": raw.get("threat_sources", []),
            "threat_level": raw.get("threat_level", ""),
            "protocol": raw.get("protocol", ""),
            "dest_ip": raw.get("dest_ip", ""),
            "dest_port": raw.get("dest_port", 0),
            "created_at": r["created_at"],
            "resolved_at": r.get("resolved_at"),
            "techniques": techniques,
            "iocs": raw.get("iocs", []),
            "recommendation": raw.get("recommendation", []),
            "ai_analysis": desc,
            "raw_data": r.get("raw_data", "{}"),
        }

    # ==================== 事件 API ====================
    @app.get("/api/events", dependencies=[Depends(require_permission("events:read"))])
    async def list_events(
        limit: int = 50,
        offset: int = 0,
        severity: str = "",
        status: str = "",
        alert_type: str = "",
    ):
        """获取安全事件列表（支持分页和筛选）"""
        limit = min(max(limit, 1), 200)
        offset = max(offset, 0)
        async with get_repository() as repo:
            where_clauses = []
            params = []
            if severity:
                where_clauses.append("severity = ?")
                params.append(severity)
            if status:
                where_clauses.append("status = ?")
                params.append(status)
            if alert_type:
                where_clauses.append("alert_type = ?")
                params.append(alert_type)
            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            import re
            rows = await repo.fetch_all(
                f"SELECT id, title, severity, status, source_ip, alert_type, "
                f"COALESCE(mitre_technique_id, '') as technique_id, "
                f"COALESCE(mitre_tactic_id, '') as tactic_id, "
                f"description, raw_data, created_at, resolved_at "
                f"FROM events {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                tuple(params) + (limit, offset),
            )
            # 同时查总数
            count_row = await repo.fetch_one(
                f"SELECT COUNT(*) as cnt FROM events {where_sql}",
                tuple(params),
            )
            total = count_row["cnt"] if count_row else 0
            events = []
            for r in rows:
                event = _format_event_list_item(dict(r))
                events.append(event)
            return {"events": events, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/events/{event_id}", dependencies=[Depends(require_permission("events:read"))])
    async def get_event(event_id: str):
        """获取单个事件详情（含 IOC、技术映射、响应建议等完整数据）"""
        async with get_repository() as repo:
            row = await repo.fetch_one(
                "SELECT id, title, severity, status, source_ip, alert_type, "
                "description, mitre_tactic_id, mitre_technique_id, "
                "resolution, resolved_by, raw_data, created_at, resolved_at "
                "FROM events WHERE id = ?", (event_id,)
            )
            if not row:
                raise HTTPException(status_code=404, detail="事件未找到")

            event = _format_event_detail(dict(row))
            return event

    # ==================== 处置 API（供 IM 桥接器调用） ====================
    class DispatchBody(BaseModel):
        action: str  # block / unblock / confirm / ignore / escalate / status
        ip: str = ""
        event_id: str = ""
        duration_minutes: int = 120
        reason: str = ""

    @app.post("/api/dispatch")
    async def dispatch(body: DispatchBody, token=Depends(verify_token)):
        """
        安全处置统一入口（IM 桥接器调用）

        动作:
          block    <ip>          — 封禁 IP（默认 120 分钟）
          unblock  <ip>          — 解封 IP
          confirm  <event_id>    — 确认事件（状态→confirmed）
          ignore   <event_id>    — 忽略事件（状态→ignored）
          escalate <event_id>    — 升级事件（状态→escalated）
          status   [ip]          — 查询封禁状态

        认证: JWT（需 events:write / firewall:block 权限）
        """
        action = (body.action or "").lower()
        ip = (body.ip or "").strip()
        event_id = (body.event_id or "").strip()
        from backend.security.dispatch import permission_for_dispatch
        from backend.security.rbac import enforce_permission
        try:
            required_permission = permission_for_dispatch(action)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        current_user = enforce_permission(token, required_permission)
        operator = current_user.username

        # ─── 封禁 IP ───
        if action == "block":
            if not ip:
                return {"success": False, "error": "block 需要指定 IP"}
            try:
                fw_tool = orchestrator.tools.get("firewall_manage")
                if not fw_tool:
                    return {"success": False, "error": "防火墙工具未初始化"}
                from backend.tools.firewall import FirewallExecutionContext
                authorization_context = FirewallExecutionContext.authenticated_api(
                    actor=operator,
                    permission=required_permission,
                    reason=body.reason or "IM 人工处置",
                )
                result = await fw_tool.execute(
                    action="block", ip=ip, reason=body.reason or "IM 人工处置",
                    duration_minutes=body.duration_minutes, confidence=1.0,
                    authorization_context=authorization_context,
                )
                if result.success:
                    # 更新该 IP 相关事件状态为 blocked
                    async with get_repository() as repo:
                        await repo.execute(
                            "UPDATE events SET status='blocked' WHERE source_ip=? AND status IN ('open','escalated')",
                            (ip,),
                        )
                    return {"success": True, "action": "blocked", "ip": ip,
                            "message": result.data.get("message", f"IP {ip} 已封禁")}
                return {"success": False, "action": "blocked", "ip": ip,
                        "error": result.error or "封禁失败"}
            except Exception as e:
                logger.error(f"封禁异常: {e}")
                return {"success": False, "error": f"封禁异常: {e}"}

        # ─── 解封 IP ───
        if action == "unblock":
            if not ip:
                return {"success": False, "error": "unblock 需要指定 IP"}
            try:
                fw_tool = orchestrator.tools.get("firewall_manage")
                if not fw_tool:
                    return {"success": False, "error": "防火墙工具未初始化"}
                from backend.tools.firewall import FirewallExecutionContext
                authorization_context = FirewallExecutionContext.authenticated_api(
                    actor=operator,
                    permission=required_permission,
                    reason=body.reason or "IM 人工解封",
                )
                result = await fw_tool.execute(
                    action="unblock", ip=ip, reason=body.reason or "IM 人工解封",
                    confidence=1.0,
                    authorization_context=authorization_context,
                )
                if result.success:
                    return {"success": True, "action": "unblocked", "ip": ip,
                            "message": f"IP {ip} 已解封"}
                return {"success": False, "action": "unblocked", "ip": ip,
                        "error": result.error or "解封失败"}
            except Exception as e:
                logger.error(f"解封异常: {e}")
                return {"success": False, "error": f"解封异常: {e}"}

        # ─── 确认/忽略/升级事件 ───
        if action in ("confirm", "ignore", "escalate"):
            if not event_id:
                return {"success": False, "error": f"{action} 需要指定事件ID"}
            status_map = {"confirm": "confirmed", "ignore": "ignored", "escalate": "escalated"}
            new_status = status_map[action]
            try:
                async with get_repository() as repo:
                    row = await repo.fetch_one(
                        "SELECT source_ip FROM events WHERE id=?", (event_id,)
                    )
                    if not row:
                        return {"success": False, "error": f"事件 {event_id} 不存在"}
                    await repo.execute(
                        "UPDATE events SET status=?, resolved_at=? WHERE id=?",
                        (new_status, datetime.now(timezone.utc).isoformat(), event_id),
                    )
                return {"success": True, "action": action, "event_id": event_id,
                        "status": new_status, "source_ip": row["source_ip"]}
            except Exception as e:
                logger.error(f"事件处置异常: {e}")
                return {"success": False, "error": f"事件处置异常: {e}"}

        # ─── 查询封禁状态 ───
        if action == "status":
            try:
                fw_tool = orchestrator.tools.get("firewall_manage")
                if not fw_tool:
                    return {"success": False, "error": "防火墙工具未初始化"}
                if ip:
                    result = await fw_tool.execute(action="check", ip=ip)
                    return {"success": True, "ip": ip, "is_blocked": bool(
                        result.data.get("is_blocked") if result.success else False
                    )}
                # 无 IP 时返回系统概览
                return {"success": True, "note": "请指定 IP 查询封禁状态"}
            except Exception as e:
                logger.error(f"查询状态异常: {e}")
                return {"success": False, "error": f"查询状态异常: {e}"}

        return {"success": False, "error": f"未知动作: {action}"}

    # ==================== 轨迹数据（Trajectory） ====================
    @app.get("/api/conversations")
    async def list_conversations_api(
        limit: int = 50, token_data=Depends(verify_token)
    ):
        """获取会话列表（供轨迹页下拉选择）"""
        from backend.storage.repositories.conversation_repo import ConversationRepository
        async with get_repository() as repo_db:
            repo = ConversationRepository(repo_db, owner_id=token_data.sub)
            rows = await repo.list_conversations(limit=limit)
            conversations = []
            for r in rows:
                conversations.append({
                    "conversation_id": r.get("id") or r.get("conversation_id"),
                    "title": r.get("title", ""),
                    "created_at": r.get("created_at", ""),
                    "updated_at": r.get("updated_at", ""),
                })
            return {"conversations": conversations}

    @app.get("/api/trajectory/stats")
    async def trajectory_stats(token_data=Depends(verify_token)):
        """轨迹聚合统计（供轨迹界面顶部卡片）"""
        from backend.storage.repositories.trajectory_repo import TrajectoryRepository
        async with get_repository() as repo_db:
            repo = TrajectoryRepository(repo_db, owner_id=token_data.sub)
            return await repo.get_stats()

    @app.get("/api/trajectory")
    async def list_trajectories(
        conversation_id: str = "",
        limit: int = 50,
        token_data=Depends(verify_token),
    ):
        """查询轨迹记录（可选按会话过滤）"""
        from backend.storage.repositories.trajectory_repo import TrajectoryRepository
        async with get_repository() as repo_db:
            repo = TrajectoryRepository(repo_db, owner_id=token_data.sub)
            cid = conversation_id.strip() or None
            try:
                rows = await repo.get_trajectories(conversation_id=cid, limit=limit)
            except PermissionError:
                raise HTTPException(status_code=404, detail="会话不存在")
            return {"trajectories": rows}

    @app.get("/api/trajectory/{conversation_id}")
    async def get_conversation_trajectory_api(
        conversation_id: str, token_data=Depends(verify_token)
    ):
        """获取指定会话的完整轨迹（合并同会话多条记录为一条时间线）"""
        from backend.storage.repositories.trajectory_repo import TrajectoryRepository
        async with get_repository() as repo_db:
            repo = TrajectoryRepository(repo_db, owner_id=token_data.sub)
            try:
                return await repo.get_conversation_trajectory(conversation_id)
            except PermissionError:
                raise HTTPException(status_code=404, detail="会话不存在")

    # ==================== 对抗测试（Adversarial） ====================
    @app.get("/api/adversarial/report", dependencies=[Depends(require_permission("agents:read"))])
    async def adversarial_report():
        """批量执行对抗样本，返回检出率/误报率报告"""
        from backend.security.adversarial.scanner import PromptInjectionScanner
        from backend.security.adversarial.redteam import RedTeamProbe
        scanner = PromptInjectionScanner()
        return RedTeamProbe.run_all(scanner)

    @app.get("/api/adversarial/probes", dependencies=[Depends(require_permission("agents:read"))])
    async def adversarial_probes():
        """返回对抗样本库 + 正常样本（供界面展示与手动测试）"""
        from backend.security.adversarial.redteam import RedTeamProbe
        return {
            "probes": RedTeamProbe.all_probes(),
            "benign": RedTeamProbe.benign_samples(),
        }

    @app.post("/api/adversarial/probe", dependencies=[Depends(require_permission("agents:read"))])
    async def adversarial_probe(payload: dict):
        """手动探测一条输入是否含注入"""
        from backend.security.adversarial.scanner import PromptInjectionScanner
        text = (payload or {}).get("text", "")
        scanner = PromptInjectionScanner()
        return scanner.scan(text or "")

    @app.get("/api/attack-chain/from-events", dependencies=[Depends(require_permission("events:read"))])
    async def attack_chain_from_events(count: int = 30):
        """只从数据库中的最近事件聚类生成攻击链。"""
        async with get_repository() as repo:
            rows = await repo.fetch_all(
                "SELECT id, title, severity, source_ip, alert_type, "
                "mitre_technique_id, mitre_tactic_id, description, created_at "
                "FROM events ORDER BY created_at DESC LIMIT ?", (min(count, 200),)
            )

        if not rows:
            # 无事件时返回空结构
            return {
                "coverage": 0, "detected_steps": 0, "total_steps": 7,
                "overall_confidence": 0, "total_alerts": 0,
                "source_ip": "", "kill_chain_visual": [],
                "steps": [], "missing_stages": [],
                "cluster": None,
            }

        # MITRE ATT&CK 杀伤链 7 阶段
        KILL_CHAIN = [
            {"pos": 1, "tactic_id": "TA0043", "tactic_name": "侦察"},
            {"pos": 2, "tactic_id": "TA0001", "tactic_name": "初始访问"},
            {"pos": 3, "tactic_id": "TA0002", "tactic_name": "执行"},
            {"pos": 4, "tactic_id": "TA0003", "tactic_name": "持久化"},
            {"pos": 5, "tactic_id": "TA0004", "tactic_name": "权限提升"},
            {"pos": 6, "tactic_id": "TA0005", "tactic_name": "防御规避"},
            {"pos": 7, "tactic_id": "TA0040", "tactic_name": "影响"},
        ]

        # 按源 IP 聚类
        from collections import Counter
        source_ips = Counter(r["source_ip"] for r in rows if r.get("source_ip"))
        top_ip = source_ips.most_common(1)[0][0] if source_ips else ""

        # 提取检测到的战术阶段
        detected_tactics = set()
        for r in rows:
            tid = (r.get("mitre_tactic_id") or "").strip()
            if tid:
                detected_tactics.add(tid)

        steps = []
        kill_chain_visual = []
        matched_count = 0
        for kc in KILL_CHAIN:
            detected = kc["tactic_id"] in detected_tactics
            if detected:
                matched_count += 1
                conf = round(0.65 + (len([r for r in rows if r.get("mitre_tactic_id") == kc["tactic_id"]]) * 0.05), 2)
                technique_id = ""
                technique_name = ""
                for r in rows:
                    if r.get("mitre_tactic_id") == kc["tactic_id"] and r.get("mitre_technique_id"):
                        technique_id = r["mitre_technique_id"]
                        break
                evidence = [r["title"] for r in rows[:3] if r.get("title")]
                steps.append({
                    "position": kc["pos"],
                    "tactic_name": kc["tactic_name"],
                    "confidence": min(conf, 0.98),
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "alerts_count": sum(1 for r in rows if r.get("mitre_tactic_id") == kc["tactic_id"]),
                    "evidence": evidence,
                })
                kill_chain_visual.append({
                    "position": f"{kc['pos']}/{len(KILL_CHAIN)}",
                    "tactic_name": kc["tactic_name"],
                    "status": "detected",
                    "confidence": min(conf, 0.98),
                    "technique_name": technique_name,
                    "technique_id": technique_id,
                    "alerts_count": len(evidence),
                })
            else:
                kill_chain_visual.append({
                    "position": f"{kc['pos']}/{len(KILL_CHAIN)}",
                    "tactic_name": kc["tactic_name"],
                    "status": "missed",
                    "confidence": 0,
                    "technique_name": "",
                    "technique_id": "",
                    "alerts_count": 0,
                })

        missing_stages = [
            {"tactic_id": kc["tactic_id"], "tactic_name": kc["tactic_name"], "pos": kc["pos"]}
            for kc in KILL_CHAIN if kc["tactic_id"] not in detected_tactics
        ]

        overall_confidence = round(matched_count / len(KILL_CHAIN), 2) if matched_count > 0 else 0
        total_alerts = len(rows)
        alert_types = list(set(r["alert_type"] for r in rows if r.get("alert_type")))

        return {
            "coverage": round(matched_count / len(KILL_CHAIN) * 100),
            "detected_steps": matched_count,
            "total_steps": len(KILL_CHAIN),
            "overall_confidence": overall_confidence,
            "total_alerts": total_alerts,
            "source_ip": top_ip,
            "kill_chain_visual": kill_chain_visual,
            "steps": steps,
            "missing_stages": missing_stages,
            "cluster": {
                "cluster_id": f"CLU-{uuid.uuid4().hex[:6].upper()}",
                "source_ip": top_ip,
                "alert_count": total_alerts,
                "duration_minutes": 30,
                "target_ips": list(source_ips.keys())[:5],
                "alert_types": alert_types[:8],
            },
        }

    # ==================== MITRE ATT&CK 结构化API ====================
    @app.get("/api/mitre/technique/{technique_id}", dependencies=[Depends(require_permission("knowledge:read"))])
    async def mitre_technique(technique_id: str):
        """查询MITRE ATT&CK技术详情（含评分、检测、缓解、关联CVE）"""
        mk = MitreAttackKnowledge()
        result = mk.get_technique(technique_id.upper())
        if not result:
            return error_response("RES_TECHNIQUE_NOT_FOUND", message=f"Technique {technique_id} not found")
        return result

    @app.get("/api/mitre/search", dependencies=[Depends(require_permission("knowledge:read"))])
    async def mitre_search(q: str = "", risk: str = "", tactic: str = ""):
        """搜索MITRE ATT&CK（支持按风险等级和战术筛选）"""
        mk = MitreAttackKnowledge()

        def _mitre_all_techniques() -> dict:
            """返回全部技术的内部索引（id → 技术详情）"""
            return TECHNIQUES_INDEX
        filters = {}
        if risk: filters["risk_levels"] = risk.split(",")
        if tactic: filters["tactics"] = tactic.split(",")
        # q="*" 或空字符串表示返回全部
        if not q or q.strip() in ("*", ""):
            # 直接遍历所有技术，返回完整列表（不截断，供前端热力图全量展示）
            all_results = []
            for tid, tech in _mitre_all_techniques().items():
                if filters.get("tactics") and tech.get("tactic", "") not in filters["tactics"]:
                    continue
                all_results.append({
                    "id": tid, "name": tech.get("name", ""),
                    "tactic_id": tech.get("tactic", ""),
                    "tactic_name": tech.get("tactic_name", "未知"),
                    "type": "technique",
                    "description": tech.get("description", "")[:200],
                    "risk_level": tech.get("scores", {}).get("risk_level", "中危"),
                    "risk_score": tech.get("scores", {}).get("risk_score", 5.0),
                    "has_cve": bool(tech.get("related_cves")),
                    "sub_techniques": list(tech.get("sub_techniques", {}).keys()),
                    "sub_count": len(tech.get("sub_techniques", {})),
                })
            # 按风险分排序（高风险的在前）
            all_results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
            return all_results
        results = mk.search(q, filters) if q else []
        return results

    @app.get("/api/mitre/kill-chain", dependencies=[Depends(require_permission("knowledge:read"))])
    async def mitre_kill_chain():
        """获取完整杀伤链视图（战术阶段排序+技术分布）"""
        mk = MitreAttackKnowledge()
        return mk.get_kill_chain()

    @app.get("/api/mitre/dashboard", dependencies=[Depends(require_permission("knowledge:read"))])
    async def mitre_dashboard():
        """获取MITRE仪表盘数据"""
        mk = MitreAttackKnowledge()
        return mk.get_dashboard()

    @app.get("/api/mitre/attack-flow", dependencies=[Depends(require_permission("knowledge:read"))])
    async def mitre_attack_flow(ids: str = ""):
        """获取攻击路径流（逗号分隔的技术ID）"""
        mk = MitreAttackKnowledge()
        technique_ids = [i.strip() for i in ids.split(",") if i.strip()]
        if not technique_ids:
            return []
        return mk.get_attack_flow(technique_ids)

    # ==================== CVE 漏洞库 API ====================
    @app.get("/api/cve/search", dependencies=[Depends(require_permission("knowledge:read"))])
    async def cve_search(q: str = ""):
        """搜索 CVE 漏洞（支持 ID、描述模糊搜索）"""
        cve_db = CVEDatabase()
        if not q or q.strip() in ("*", ""):
            # 返回全部（按严重程度排序）
            all_cves = cve_db.get_critical_recent(days=3650)
            # 补充 non-critical
            for c in cve_db.vulnerabilities:
                if c not in all_cves and len(all_cves) < 76:
                    all_cves.append(c)
            return all_cves[:76]
        results = cve_db.search(q)
        return results

    @app.get("/api/cve/{cve_id}", dependencies=[Depends(require_permission("knowledge:read"))])
    async def cve_detail(cve_id: str):
        """查询 CVE 详情"""
        cve_db = CVEDatabase()
        result = cve_db.get_by_id(cve_id.upper())
        if not result:
            return error_response("RES_CVE_NOT_FOUND", message=f"CVE {cve_id} not found")
        return result

    # ==================== 合规知识库 API ====================
    @app.get("/api/compliance/search", dependencies=[Depends(require_permission("knowledge:read"))])
    async def compliance_search(q: str = ""):
        """搜索合规法规（支持按名称、关键词搜索）"""
        ck = ComplianceKnowledge()
        if not q or q.strip() in ("*", ""):
            # 返回全部
            return [{
                "name": r.get("name", ""),
                "abbr": r.get("abbr", ""),
                "description": r.get("description", ""),
                "key_requirements": r.get("key_requirements", [])[:5],
                "penalties": r.get("penalties", ""),
            } for r in ck.regulations]
        results = ck.search(q)
        return results

    @app.get("/api/compliance/{regulation_name}", dependencies=[Depends(require_permission("knowledge:read"))])
    async def compliance_detail(regulation_name: str):
        """查询某个法规的完整信息"""
        ck = ComplianceKnowledge()
        result = ck.get_regulation(regulation_name)
        if not result:
            return error_response("RES_REGULATION_NOT_FOUND", message=f"Regulation {regulation_name} not found")
        return result

    # ==================== 应急响应剧本 API ====================
    @app.get("/api/remediation/search", dependencies=[Depends(require_permission("knowledge:read"))])
    async def remediation_search(q: str = ""):
        """搜索应急响应剧本（按场景名称、指标、处置动作搜索）"""
        rk = RemediationKnowledge()
        if not q or q.strip() in ("*", ""):
            return [{
                "scenario": pb.get("scenario", ""),
                "indicators": pb.get("indicators", ""),
                "immediate_actions": pb.get("immediate_actions", []),
                "medium_term": pb.get("medium_term", []),
                "long_term": pb.get("long_term", []),
            } for pb in rk.playbooks]
        return rk.search(q)

    @app.get("/api/remediation/{scenario_name}", dependencies=[Depends(require_permission("knowledge:read"))])
    async def remediation_detail(scenario_name: str):
        """查询某个场景的完整响应剧本"""
        rk = RemediationKnowledge()
        result = rk.get_by_scenario(scenario_name)
        if not result:
            return error_response("RES_SCENARIO_NOT_FOUND", message=f"Scenario {scenario_name} not found")
        return result

    # ==================== CVE 按 MITRE 技术关联查询 ====================
    @app.get("/api/cve/by-mitre/{technique_id}", dependencies=[Depends(require_permission("knowledge:read"))])
    async def cve_by_mitre(technique_id: str):
        """按 MITRE ATT&CK 技术 ID 查询相关 CVE"""
        cve_db = CVEDatabase()
        results = cve_db.get_by_mitre_technique(technique_id.upper())
        return results

    # ==================== 统一 WebSocket（带对话上下文持久化）====================
    @app.websocket("/ws/chat")
    async def chat_websocket(websocket: WebSocket):
        """
        统一 WebSocket 入口（带对话上下文持久化）

        使用 TrueReAct 循环（LLM Function Calling 驱动的 Think→Tool→Observe）。
        每次用户消息会从数据库加载历史上下文，并将本轮对话保存到数据库，
        实现多轮对话的连贯性。

        认证方式: 通过 query param 传递 JWT Token
          ws://host/ws/chat?token=xxx
        """
        ws_id = uuid.uuid4().hex[:8]

        # 浏览器 WebSocket 必须来自显式 CORS 白名单；无 Origin 的 CLI/服务端客户端保留。
        origin = (websocket.headers.get("origin") or "").rstrip("/")
        allowed_ws_origins = {o.strip().rstrip("/") for o in ALLOWED_ORIGINS if o.strip()}
        if origin and origin not in allowed_ws_origins:
            await websocket.close(code=4003, reason="WebSocket Origin 不在允许列表")
            return

        # ═══════════ WebSocket 认证（在 accept() 之前完成） ═══════════
        try:
            # Web 优先使用 HttpOnly Cookie；query token 仅保留给旧版或非浏览器客户端。
            from backend.security.auth import WEB_ACCESS_COOKIE
            token = websocket.cookies.get(WEB_ACCESS_COOKIE, "") or websocket.query_params.get("token", "")
            if not token:
                await websocket.close(code=4001, reason="缺少认证令牌")
                return
            from backend.security.auth import verify_token, validate_live_token_data
            from fastapi.security import HTTPAuthorizationCredentials
            credentials = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
            token_data = await verify_token(credentials)
        except Exception as e:
            err_str = str(e)
            reason = "令牌已过期" if "expired" in err_str.lower() else f"无效令牌: {err_str}"
            try:
                await websocket.close(code=4001, reason=reason)
            except Exception:
                pass
            return

        await ws_manager.connect(ws_id, websocket)

        # 支持恢复历史对话：客户端可通过 query param 传入 conversation_id
        resume_id = websocket.query_params.get("conversation_id", "").strip()

        # 初始化数据库和会话仓库（统一使用 Repository，自动适配 SQLite/PostgreSQL）
        from backend.storage.database import Repository
        repo_db = Repository()
        repo = ConversationRepository(repo_db, owner_id=token_data.sub)
        # PostgreSQL 模式下不执行内联 DDL（由 Alembic 迁移管理）
        from backend.storage.database import _is_postgres
        if not _is_postgres():
            from backend.storage.database import get_sqlite_path
            init_db(get_sqlite_path(repo_db.url))

        if resume_id:
            # 恢复已有对话
            existing = await repo.get_conversation(resume_id)
            if existing:
                conversation_id = resume_id
                logger.info(f"恢复历史对话", extra={"ws_id": ws_id, "conversation_id": conversation_id})
            else:
                # 指定的 conversation_id 不存在 → 自动创建新对话（兼容旧客户端）
                conversation_id = f"ws-{ws_id}-{uuid.uuid4().hex[:8]}"
                await repo.create_conversation(
                    title=f"WebSocket对话 {conversation_id}",
                    conversation_id=conversation_id,
                )
                logger.info(f"指定的对话 {resume_id} 不存在，创建新对话", extra={"ws_id": ws_id, "conversation_id": conversation_id})
        else:
            # 新对话
            conversation_id = f"ws-{ws_id}-{uuid.uuid4().hex[:8]}"
            await repo.create_conversation(
                title=f"WebSocket对话 {conversation_id}",
                conversation_id=conversation_id,
            )
            logger.info(f"新 WebSocket 连接", extra={"ws_id": ws_id, "conversation_id": conversation_id})

        try:
            while True:
                data = await websocket.receive_json()

                # 长连接不能绕过 access token 过期、禁用或角色/密码变更。
                try:
                    validate_live_token_data(token_data)
                except HTTPException as exc:
                    await websocket.close(code=4001, reason=str(exc.detail))
                    return

                # ═══════════════════ 心跳检测 ═══════════════════
                if data.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": __import__("datetime").datetime.now(
                            __import__("datetime").timezone.utc
                        ).isoformat(),
                    })
                    continue

                text = data.get("message", "").strip()
                if not text:
                    continue

                # 1. 从数据库加载历史消息，构造 LLM 对话历史
                history_db = await repo.get_messages(conversation_id, limit=20)
                history_messages = []
                # 话题切换检测：若当前提问与最近一轮用户提问相似度低，
                # 视为全新话题，不注入旧历史（切断跨话题串味）
                _last_user = ""
                for _m in history_db:
                    if _m.get("role") == "user" and _m.get("content"):
                        _last_user = _m.get("content")
                _is_topic_switch = _is_new_topic(text, _last_user) if _last_user else False
                if _is_topic_switch:
                    logger.info(
                        "[topic] 检测到话题切换，不注入历史上下文 (新问题 vs 上轮问题 相似度过低)"
                    )
                for msg in history_db:
                    role = msg.get("role", "")
                    content = msg.get("content", "")
                    if role in ("user", "assistant") and content:
                        # 新话题：跳过所有旧历史（仅保留当前问题，由下方单独追加）
                        if _is_topic_switch:
                            continue
                        history_messages.append({"role": role, "content": content})

                # 2. 保存用户消息到数据库
                await repo.save_message(
                    conversation_id=conversation_id,
                    role="user",
                    content=text,
                    agent_id="orchestrator",
                )

                # 3. 调用编排器（传入历史上下文）
                assistant_content = ""
                async for chunk in orchestrator.process(text, history_messages=history_messages):
                    # 收集最终 assistant 回复（用于保存到 DB）
                    ctype = chunk.get("type", "")
                    if ctype in ("true_react_complete", "orchestrator_complete", "true_react_max_rounds"):
                        content = chunk.get("content", "") or chunk.get("summary", "")
                        if content and not assistant_content:
                            assistant_content = content
                    await websocket.send_json(chunk)

                # 4. 保存 LLM 回复到数据库
                if assistant_content:
                    await repo.save_message(
                        conversation_id=conversation_id,
                        role="assistant",
                        content=assistant_content,
                        agent_id="orchestrator",
                    )

        except WebSocketDisconnect:
            logger.info(f"WebSocket 断开", extra={"ws_id": ws_id})
            ws_manager.disconnect(ws_id)
        except Exception as e:
            try:
                await websocket.send_json({"type": "error", "error": str(e)})
            except Exception:
                pass
            ws_manager.disconnect(ws_id)
            logger.error(f"WebSocket 异常", extra={
                "ws_id": ws_id, "error": str(e),
            })
        finally:
            # 关闭数据库连接，防止泄漏
            try:
                await repo_db.close()
            except Exception:
                pass

    return app


if __name__ == "__main__":
    if not HAS_FASTAPI:
        logger.error("请安装依赖: pip install fastapi uvicorn websockets")
        sys.exit(1)

    import uvicorn
    app = create_app()
    if app:
        host = os.getenv("SECAGENTX_HOST", "0.0.0.0")
        port = int(os.getenv("SECAGENTX_PORT", "8000"))
        uvicorn.run(app, host=host, port=port)
