import asyncio
import hashlib
import os

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from backend.security import auth, rbac
from backend.security.refresh_sessions import (
    RefreshSession,
    RefreshTokenInvalid,
    RefreshTokenReuseDetected,
    RefreshTokenStore,
)


STRONG_ADMIN_PASSWORD = "test-admin-password-123"


def _manager(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENTX_PASSWORD", STRONG_ADMIN_PASSWORD)
    monkeypatch.delenv("SECAGENTX_PASSWORD_HASH", raising=False)
    manager = rbac.UserManager(users_file=str(tmp_path / "users.json"))
    monkeypatch.setattr(rbac, "_user_manager", manager)
    return manager


def _token_store(tmp_path, monkeypatch):
    store = RefreshTokenStore(str(tmp_path / "auth_sessions.db"))
    monkeypatch.setattr(auth, "refresh_token_store", store)
    return store


def test_refresh_store_recreates_schema_after_database_replacement(tmp_path):
    db_path = tmp_path / "replaceable-auth-sessions.db"
    store = RefreshTokenStore(str(db_path))
    first = RefreshSession("first", "family-1", "admin", 1.0, 9999999999.0)
    store.register(first)

    db_path.unlink()
    second = RefreshSession("second", "family-2", "admin", 2.0, 9999999999.0)
    store.register(second)

    with store._connect() as conn:
        row = conn.execute(
            "SELECT jti FROM refresh_sessions WHERE jti = ?", ("second",)
        ).fetchone()
    assert row["jti"] == "second"


def test_first_start_requires_explicit_admin_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("SECAGENTX_PASSWORD", raising=False)
    monkeypatch.delenv("SECAGENTX_PASSWORD_HASH", raising=False)

    with pytest.raises(rbac.AdminBootstrapError):
        rbac.UserManager(users_file=str(tmp_path / "users.json"))


def test_known_default_admin_password_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENTX_PASSWORD", "secagentx_2026")
    monkeypatch.delenv("SECAGENTX_PASSWORD_HASH", raising=False)

    with pytest.raises(rbac.AdminBootstrapError):
        rbac.UserManager(users_file=str(tmp_path / "users.json"))


def test_legacy_sha256_password_is_upgraded_after_successful_login(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    manager.create_user("legacy", "temporary-password-123", role="analyst")
    legacy = manager.get_user("legacy")
    legacy.password_hash = hashlib.sha256(b"temporary-password-123").hexdigest()
    manager._save()

    authenticated = manager.authenticate("legacy", "temporary-password-123")

    assert authenticated is legacy
    assert legacy.password_hash.startswith(("$2a$", "$2b$", "$2y$"))
    assert legacy.token_version == 1


def test_admin_hash_environment_rejects_legacy_sha256(tmp_path, monkeypatch):
    monkeypatch.delenv("SECAGENTX_PASSWORD", raising=False)
    monkeypatch.setenv(
        "SECAGENTX_PASSWORD_HASH",
        hashlib.sha256(b"strong-but-legacy-password").hexdigest(),
    )

    with pytest.raises(rbac.AdminBootstrapError, match="bcrypt"):
        rbac.UserManager(users_file=str(tmp_path / "users.json"))


def test_refresh_rotation_and_replay_revoke_family(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    _token_store(tmp_path, monkeypatch)
    admin = manager.get_user("admin")
    original = auth.create_refresh_token(
        admin.username, admin.role, admin.token_version
    )

    _, rotated, _ = auth.rotate_refresh_token(original)

    with pytest.raises(RefreshTokenReuseDetected):
        auth.rotate_refresh_token(original)
    with pytest.raises(RefreshTokenInvalid):
        auth.rotate_refresh_token(rotated)


def test_role_change_invalidates_existing_access_and_refresh_tokens(
    tmp_path, monkeypatch
):
    manager = _manager(tmp_path, monkeypatch)
    _token_store(tmp_path, monkeypatch)
    manager.create_user("operator-1", "operator-password-123", role="operator")
    user = manager.get_user("operator-1")
    access = auth.create_access_token(user.username, user.role, user.token_version)
    refresh = auth.create_refresh_token(user.username, user.role, user.token_version)

    manager.update_user("operator-1", role="viewer")

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth.verify_token(credentials))
    assert exc.value.status_code == 401
    with pytest.raises(RefreshTokenInvalid):
        auth.rotate_refresh_token(refresh)


def test_refresh_uses_live_role(tmp_path, monkeypatch):
    manager = _manager(tmp_path, monkeypatch)
    _token_store(tmp_path, monkeypatch)
    manager.create_user("analyst-1", "analyst-password-123", role="analyst")
    user = manager.get_user("analyst-1")
    refresh = auth.create_refresh_token(user.username, user.role, user.token_version)

    access, _, _ = auth.rotate_refresh_token(refresh)
    payload = auth._decode_token(access)

    assert payload["role"] == "analyst"
    assert payload["ver"] == user.token_version
