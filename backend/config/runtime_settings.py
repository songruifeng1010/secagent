"""Web 运行设置。

管理员密码仅保存 bcrypt 哈希；JWT secret 保存于系统 Keyring。
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Optional

from .provider_profiles import CredentialStore, CredentialStoreError, get_secagentx_home


class RuntimeSettingsStore:
    def __init__(self, path: Optional[Path] = None, credentials: Optional[CredentialStore] = None):
        self.path = path or (get_secagentx_home() / "settings.json")
        self.credentials = credentials or CredentialStore()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "web": {"host": "127.0.0.1", "port": 8000}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"运行配置损坏: {self.path}: {exc}") from exc

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def configure_web_credentials(self, password: str) -> None:
        if len(password) < 12:
            raise ValueError("管理员密码至少需要 12 个字符")
        import bcrypt

        data = self.load()
        data["admin_password_hash"] = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")
        jwt_ref = data.get("jwt_secret_ref") or "runtime:jwt-secret"
        self.credentials.set(jwt_ref, secrets.token_urlsafe(48))
        data["jwt_secret_ref"] = jwt_ref
        self.save(data)

    def activate(self) -> dict[str, Any]:
        data = self.load()
        password_hash = data.get("admin_password_hash", "")
        if password_hash and not os.getenv("SECAGENTX_PASSWORD_HASH") and not os.getenv("SECAGENTX_PASSWORD"):
            os.environ["SECAGENTX_PASSWORD_HASH"] = password_hash
        jwt_ref = data.get("jwt_secret_ref", "")
        if jwt_ref and not os.getenv("SECAGENTX_JWT_SECRET"):
            jwt_secret = self.credentials.get(jwt_ref)
            if jwt_secret:
                os.environ["SECAGENTX_JWT_SECRET"] = jwt_secret
        return data

    def web_ready(self) -> bool:
        self.activate()
        return bool(
            (os.getenv("SECAGENTX_PASSWORD_HASH") or os.getenv("SECAGENTX_PASSWORD"))
            and os.getenv("SECAGENTX_JWT_SECRET")
        )


def activate_runtime_settings() -> None:
    try:
        RuntimeSettingsStore().activate()
    except (ValueError, CredentialStoreError):
        return
