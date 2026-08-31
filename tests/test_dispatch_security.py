import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("SECAGENTX_PASSWORD", "test-admin-password-123")

from backend.security.dispatch import permission_for_dispatch
from backend.security.rbac import UserManager, enforce_permission


@pytest.mark.parametrize(
    ("action", "permission"),
    [
        ("block", "firewall:block"),
        ("unblock", "firewall:unblock"),
        ("confirm", "events:write"),
        ("ignore", "events:write"),
        ("escalate", "events:write"),
        ("status", "firewall:view"),
    ],
)
def test_dispatch_action_permission_mapping(action, permission):
    assert permission_for_dispatch(action) == permission


def test_unknown_dispatch_action_is_rejected():
    with pytest.raises(ValueError):
        permission_for_dispatch("shell")


def test_viewer_cannot_use_stale_admin_claim(tmp_path):
    manager = UserManager(users_file=str(tmp_path / "users.json"))
    manager.create_user("viewer-1", "test-password", role="viewer")
    stale_admin_token = SimpleNamespace(sub="viewer-1", role="admin")

    with pytest.raises(HTTPException) as exc:
        enforce_permission(
            stale_admin_token, "firewall:block", manager=manager
        )

    assert exc.value.status_code == 403


def test_operator_can_block_and_identity_comes_from_live_user(tmp_path):
    manager = UserManager(users_file=str(tmp_path / "users.json"))
    manager.create_user("operator-1", "test-password", role="operator")
    token = SimpleNamespace(sub="operator-1", role="viewer")

    user = enforce_permission(token, "firewall:block", manager=manager)

    assert user.username == "operator-1"
    assert user.role == "operator"


def test_disabled_user_is_rejected(tmp_path):
    manager = UserManager(users_file=str(tmp_path / "users.json"))
    manager.create_user(
        "operator-1", "test-password", role="operator", enabled=False
    )
    token = SimpleNamespace(sub="operator-1", role="operator")

    with pytest.raises(HTTPException) as exc:
        enforce_permission(token, "firewall:block", manager=manager)

    assert exc.value.status_code == 403
