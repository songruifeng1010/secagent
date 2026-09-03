"""本机无登录控制台的 API 集成测试。"""
import os

import pytest
from fastapi.middleware.cors import CORSMiddleware
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("DEEPSEEK_API_KEY", "sk-test-deepseek-key")
os.environ.setdefault("QWEN_API_KEY", "sk-test-qwen-key")
os.environ.setdefault("CI", "true")

from backend.interface.api_server import create_app


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("SECAGENTX_ACTIVE_PROVIDER", "mock")
    monkeypatch.setenv("SECAGENTX_LLM_PROVIDER_ID", "mock")
    monkeypatch.setenv("SECAGENTX_LLM_API_BASE", "mock://local")
    monkeypatch.setenv("SECAGENTX_LLM_MODEL", "mock-llm")
    monkeypatch.setenv("SECAGENTX_LLM_ALLOW_NO_KEY", "true")
    return create_app()


@pytest.mark.asyncio
async def test_health_and_agents_are_available_without_credentials(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        health = await client.get("/api/health/live")
        agents = await client.get("/api/agents")
    assert health.status_code == 200
    assert health.json()["version"] == "4.0.0"
    assert agents.status_code == 200
    assert "agents" in agents.json()


@pytest.mark.asyncio
async def test_auth_and_user_endpoints_are_removed(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login = await client.post("/api/auth/login", json={"username": "admin", "password": "removed"})
        users = await client.get("/api/users")
    assert login.status_code == 404
    assert users.status_code == 404


@pytest.mark.asyncio
async def test_firewall_dispatch_requires_explicit_local_confirmation(app):
    """高风险网络动作不能因本机无登录模式而被静默执行。"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/dispatch",
            json={"action": "block", "ip": "203.0.113.42"},
        )
    assert response.status_code == 409
    assert "确认" in response.json()["detail"]


def test_cors_includes_runtime_loopback_port(monkeypatch):
    monkeypatch.setenv("SECAGENTX_PORT", "8765")
    monkeypatch.setenv("SECAGENTX_ACTIVE_PROVIDER", "mock")
    monkeypatch.setenv("SECAGENTX_LLM_PROVIDER_ID", "mock")
    monkeypatch.setenv("SECAGENTX_LLM_API_BASE", "mock://local")
    monkeypatch.setenv("SECAGENTX_LLM_MODEL", "mock-llm")
    monkeypatch.setenv("SECAGENTX_LLM_ALLOW_NO_KEY", "true")
    app = create_app()
    cors = next(item for item in app.user_middleware if item.cls is CORSMiddleware)
    assert "http://127.0.0.1:8765" in cors.kwargs["allow_origins"]
