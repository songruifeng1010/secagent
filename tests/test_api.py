"""
API 端点集成测试 — 使用 FastAPI TestClient (httpx.AsyncClient)

测试覆盖:
  - 健康检查
  - 登录认证
  - 错误码标准化
  - MITRE 搜索
  - Prometheus 指标
  - 自动模块状态
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 必须在使用任何 backend 模块前设置环境变量
E2E_PASSWORD = "SecAgentX-E2E-Only-2026!"
os.environ["SECAGENTX_PASSWORD"] = E2E_PASSWORD
os.environ["DEEPSEEK_API_KEY"] = "sk-test-deepseek-key"
os.environ["QWEN_API_KEY"] = "sk-test-qwen-key"
os.environ["VT_API_KEY"] = "test-vt-key"
os.environ["SECAGENTX_JWT_SECRET"] = "ci-test-jwt-secret-at-least-32-chars-long!!"
os.environ["CI"] = "true"

from httpx import AsyncClient, ASGITransport
from fastapi.middleware.cors import CORSMiddleware
from backend.interface.api_server import create_app


@pytest.fixture
def app():
    return create_app()


def test_cors_defaults_include_runtime_loopback_port(monkeypatch):
    monkeypatch.setenv("SECAGENTX_PORT", "8765")
    runtime_app = create_app()
    cors = next(item for item in runtime_app.user_middleware if item.cls is CORSMiddleware)
    origins = cors.kwargs["allow_origins"]
    assert "http://127.0.0.1:8765" in origins
    assert "http://localhost:8765" in origins


@pytest.mark.asyncio
async def test_health_endpoint(app):
    """GET /api/health — 健康检查返回基本信息"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert data["service"] == "secagentx"
        assert "agents" in data
        assert "database" in data
        assert "llm" in data


@pytest.mark.asyncio
async def test_liveness_and_readiness_endpoints(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        live = await client.get("/api/health/live")
        ready = await client.get("/api/health/ready")
        assert live.status_code == 200
        assert live.json()["version"] == "3.1.0"
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_login_success(app):
    """POST /api/auth/login — 成功登录返回 JWT token"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 1800  # 默认 30 分钟
        assert "refresh_token" in body
        assert body["refresh_expires_in"] == 86400  # 24 小时
        # 返回用户信息
        assert "user" in body
        assert body["user"]["username"] == "admin"
        assert body["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_web_login_uses_httponly_cookies_and_cookie_auth(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/web/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        assert login_resp.status_code == 200
        body = login_resp.json()
        assert body["status"] == "ok"
        assert "access_token" not in body
        assert "refresh_token" not in body
        cookies = login_resp.headers.get_list("set-cookie")
        assert any("secagentx_access=" in value and "HttpOnly" in value for value in cookies)
        assert any("secagentx_refresh=" in value and "HttpOnly" in value for value in cookies)
        assert any("secagentx_csrf=" in value and "HttpOnly" not in value for value in cookies)

        protected = await client.get("/api/agents")
        assert protected.status_code == 200


@pytest.mark.asyncio
async def test_cookie_authenticated_mutation_requires_csrf(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/web/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        assert login_resp.status_code == 200
        rejected = await client.post("/api/dispatch", json={
            "action": "status",
            "params": {},
        })
        assert rejected.status_code == 403
        assert rejected.json()["error"]["code"] == "AUTH_CSRF_INVALID"


@pytest.mark.asyncio
async def test_web_refresh_rotates_cookie_without_exposing_tokens(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/web/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        old_refresh = client.cookies.get("secagentx_refresh")
        refreshed = await client.post("/api/auth/web/refresh")
        assert refreshed.status_code == 200
        assert refreshed.json()["status"] == "ok"
        assert "access_token" not in refreshed.json()
        assert client.cookies.get("secagentx_refresh") != old_refresh


@pytest.mark.asyncio
async def test_security_headers_are_present(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]

        rejected = await client.get("/api/agents")
        assert rejected.status_code == 401
        assert rejected.headers["x-content-type-options"] == "nosniff"
        assert rejected.headers["x-request-id"]


@pytest.mark.asyncio
async def test_refresh_token_success(app):
    """POST /api/auth/refresh — 使用 refresh_token 换取新的 access_token"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. 先登录获取 refresh_token
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        assert login_resp.status_code == 200
        refresh_token = login_resp.json()["refresh_token"]

        # 2. 使用 refresh_token 刷新
        refresh_resp = await client.post("/api/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert refresh_resp.status_code == 200
        body = refresh_resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["expires_in"] == 1800
        # 新 token 应该与旧 token 不同
        assert body["access_token"] != login_resp.json()["access_token"]

        # 3. 使用新的 access_token 访问受保护端点
        new_access = body["access_token"]
        agent_resp = await client.get(
            "/api/agents",
            headers={"Authorization": f"Bearer {new_access}"},
        )
        assert agent_resp.status_code == 200


@pytest.mark.asyncio
async def test_refresh_token_invalid(app):
    """POST /api/auth/refresh — 无效的 refresh_token 返回错误"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/auth/refresh", json={
            "refresh_token": "invalid-token",
        })
        assert resp.status_code == 401
        body = resp.json()
        assert "error" in body


@pytest.mark.asyncio
async def test_refresh_token_missing(app):
    """POST /api/auth/refresh — 缺少 refresh_token 返回 422"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/auth/refresh", json={})
        # Pydantic 校验拒绝空 body → 422
        assert resp.status_code == 422
        body = resp.json()
        assert "detail" in body


@pytest.mark.asyncio
async def test_refresh_token_as_access(app):
    """验证 refresh_token 不能直接用于 API 认证"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        assert login_resp.status_code == 200
        refresh_token = login_resp.json()["refresh_token"]

        # 直接用 refresh_token 访问受保护端点（应被拒绝）
        agent_resp = await client.get(
            "/api/agents",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )
        assert agent_resp.status_code == 401


@pytest.mark.asyncio
async def test_login_wrong_password(app):
    """POST /api/auth/login — 密码错误返回 401 标准化错误"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "wrong-password",
        })
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"]["code"] == "AUTH_WRONG_CREDENTIALS"
        assert "error" in body


@pytest.mark.asyncio
async def test_api_without_token(app):
    """GET /api/agents — 无 token 返回 401 标准化错误"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/agents")
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"]["code"] == "AUTH_TOKEN_MISSING"


@pytest.mark.asyncio
async def test_api_with_invalid_token(app):
    """GET /api/agents — 无效 token 返回 401"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/api/agents",
            headers={"Authorization": "Bearer invalid-token-here"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert "error" in body
        assert body["error"]["code"] in ("AUTH_TOKEN_INVALID", "AUTH_TOKEN_EXPIRED")


@pytest.mark.asyncio
async def test_mitre_search(app):
    """GET /api/mitre/search — MITRE 搜索需认证"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 先登录
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        token = login_resp.json()["access_token"]

        # 搜索
        resp = await client.get(
            "/api/mitre/search?q=T1566",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        results = resp.json()
        assert isinstance(results, list)


@pytest.mark.asyncio
async def test_mitre_technique_not_found(app):
    """GET /api/mitre/technique/ — 不存在返回 404 标准化错误"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/api/mitre/technique/T999999",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404
        body = resp.json()
        assert body["error"]["code"] == "RES_TECHNIQUE_NOT_FOUND"


@pytest.mark.asyncio
async def test_metrics_endpoint(app):
    """GET /api/metrics — Prometheus 指标返回"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/metrics")
        assert resp.status_code == 200
        assert "secagentx" in resp.text
        assert "alerts_total" in resp.text or "prometheus_client" in resp.text


@pytest.mark.asyncio
async def test_auto_status_endpoint(app):
    """GET /api/auto/status — 自动模块状态"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/api/auto/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "enabled" in body


@pytest.mark.asyncio
async def test_agents_endpoint(app):
    """GET /api/agents — Agent 列表"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": E2E_PASSWORD,
        })
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/api/agents",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "agents" in body
        assert len(body["agents"]) >= 5  # 5 个 Agent
