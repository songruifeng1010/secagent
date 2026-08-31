"""模型 Provider 档案与系统凭据存储。

配置文件只保存路由元数据和凭据引用；API Key 由系统 Keyring 或 Windows
DPAPI 保存。也可通过环境变量提供凭据，适合 Docker、CI 和无桌面的服务器。
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import base64
import ctypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("secagentx.provider_profiles")

KEYRING_SERVICE = "SecAgentX"
CONFIG_VERSION = 1


PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "deepseek": {
        "label": "DeepSeek",
        "protocol": "openai_compatible",
        "api_base": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
    },
    "qwen": {
        "label": "通义千问 (DashScope)",
        "protocol": "openai_compatible",
        "api_base": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-max",
        "env_key": "QWEN_API_KEY",
    },
    "openai": {
        "label": "OpenAI",
        "protocol": "openai_compatible",
        "api_base": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
    },
    "anthropic": {
        "label": "Anthropic",
        "protocol": "anthropic_compatible",
        "api_base": "https://api.anthropic.com/v1",
        "model": "claude-sonnet-4-5",
        "env_key": "ANTHROPIC_API_KEY",
    },
    "azure_openai": {
        "label": "Azure OpenAI",
        "protocol": "openai_compatible",
        "api_base": "",
        "model": "",
        "env_key": "AZURE_OPENAI_API_KEY",
        "auth_style": "api-key",
        "api_version": "2024-10-21",
    },
    "gemini": {
        "label": "Google Gemini (OpenAI 兼容接口)",
        "protocol": "openai_compatible",
        "api_base": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "env_key": "GEMINI_API_KEY",
    },
    "openrouter": {
        "label": "OpenRouter",
        "protocol": "openai_compatible",
        "api_base": "https://openrouter.ai/api/v1",
        "model": "openai/gpt-4o-mini",
        "env_key": "OPENROUTER_API_KEY",
    },
    "xai": {
        "label": "xAI (Grok)",
        "protocol": "openai_compatible",
        "api_base": "https://api.x.ai/v1",
        "model": "grok-3-mini",
        "env_key": "XAI_API_KEY",
    },
    "kimi": {
        "label": "Moonshot / Kimi",
        "protocol": "openai_compatible",
        "api_base": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
        "env_key": "MOONSHOT_API_KEY",
    },
    "ollama": {
        "label": "Ollama（本地）",
        "protocol": "openai_compatible",
        "api_base": "http://127.0.0.1:11434/v1",
        "model": "llama3.2",
        "env_key": "",
        "requires_api_key": False,
    },
    "lmstudio": {
        "label": "LM Studio（本地）",
        "protocol": "openai_compatible",
        "api_base": "http://127.0.0.1:1234/v1",
        "model": "local-model",
        "env_key": "",
        "requires_api_key": False,
    },
    "custom_openai": {
        "label": "自定义 OpenAI 兼容接口",
        "protocol": "openai_compatible",
        "api_base": "",
        "model": "",
        "env_key": "SECAGENTX_LLM_API_KEY",
    },
    "custom_anthropic": {
        "label": "自定义 Anthropic 兼容接口",
        "protocol": "anthropic_compatible",
        "api_base": "",
        "model": "",
        "env_key": "SECAGENTX_LLM_API_KEY",
    },
    "mock": {
        "label": "离线 Mock（仅验证流程）",
        "protocol": "mock",
        "api_base": "mock://local",
        "model": "mock-llm",
        "env_key": "",
        "requires_api_key": False,
    },
}


def get_secagentx_home() -> Path:
    override = os.getenv("SECAGENTX_HOME", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt" and os.getenv("APPDATA"):
        return Path(os.environ["APPDATA"]) / "SecAgentX"
    config_home = os.getenv("XDG_CONFIG_HOME", "").strip()
    return (Path(config_home) if config_home else Path.home() / ".config") / "secagentx"


@dataclass
class ProviderProfile:
    profile_id: str
    provider_id: str
    label: str
    protocol: str
    api_base: str
    model: str
    credential_type: str = "keyring"
    credential_ref: str = ""
    env_key: str = ""
    auth_style: str = "bearer"
    api_version: str = ""
    requires_api_key: bool = True
    timeout_seconds: float = 60.0
    max_tokens: int = 4096

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProviderProfile":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: value[k] for k in allowed if k in value})

    def runtime_config(self, api_key: str = "") -> dict[str, Any]:
        return {
            "api_base": self.api_base,
            "api_key": api_key,
            "model": self.model,
            "timeout_seconds": self.timeout_seconds,
            "max_tokens": self.max_tokens,
            "auth_style": self.auth_style,
            "api_version": self.api_version,
            "allow_no_key": not self.requires_api_key,
        }


class CredentialStoreError(RuntimeError):
    pass


class CredentialStore:
    """系统凭据包装；Windows 可在无第三方包时使用用户级 DPAPI。"""

    def __init__(self, service: str = KEYRING_SERVICE, dpapi_path: Optional[Path] = None):
        self.service = service
        self.dpapi_path = dpapi_path or (get_secagentx_home() / "credentials.dpapi")

    @staticmethod
    def _keyring_available() -> bool:
        try:
            import keyring
            backend = keyring.get_keyring()
            return backend is not None and backend.priority > 0
        except Exception:
            return False

    @staticmethod
    def available() -> bool:
        return CredentialStore._keyring_available() or os.name == "nt"

    @staticmethod
    def _dpapi_transform(payload: bytes, protect: bool) -> bytes:
        if os.name != "nt":
            raise CredentialStoreError("当前系统无可用的本地安全凭据存储")

        class DataBlob(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        buffer = ctypes.create_string_buffer(payload)
        input_blob = DataBlob(len(payload), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        output_blob = DataBlob()
        crypt32 = ctypes.windll.crypt32
        function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        if protect:
            success = function(
                ctypes.byref(input_blob), None, None, None, None, 0,
                ctypes.byref(output_blob),
            )
        else:
            success = function(
                ctypes.byref(input_blob), None, None, None, None, 0,
                ctypes.byref(output_blob),
            )
        if not success:
            raise CredentialStoreError("Windows DPAPI 操作失败")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output_blob.pbData)

    def _load_dpapi(self) -> dict[str, str]:
        if not self.dpapi_path.exists():
            return {}
        try:
            encrypted = base64.b64decode(self.dpapi_path.read_bytes(), validate=True)
            raw = self._dpapi_transform(encrypted, protect=False)
            value = json.loads(raw.decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except Exception as exc:
            raise CredentialStoreError("无法读取 Windows DPAPI 凭据库") from exc

    def _save_dpapi(self, values: dict[str, str]) -> None:
        self.dpapi_path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(values, ensure_ascii=False).encode("utf-8")
        encoded = base64.b64encode(self._dpapi_transform(raw, protect=True))
        fd, tmp_name = tempfile.mkstemp(prefix="credentials-", suffix=".tmp", dir=self.dpapi_path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.dpapi_path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def set(self, reference: str, secret: str) -> None:
        if not secret:
            raise CredentialStoreError("拒绝保存空 API Key")
        if self._keyring_available():
            import keyring
            try:
                keyring.set_password(self.service, reference, secret)
                # 安装 Keyring 后迁移并清除可能遗留的 DPAPI 副本。
                if os.name == "nt" and self.dpapi_path.exists():
                    values = self._load_dpapi()
                    if values.pop(f"{self.service}:{reference}", None) is not None:
                        self._save_dpapi(values)
                return
            except Exception:
                if os.name != "nt":
                    raise CredentialStoreError("系统 Keyring 写入失败，请改用环境变量")
        values = self._load_dpapi()
        values[f"{self.service}:{reference}"] = secret
        self._save_dpapi(values)

    def get(self, reference: str) -> str:
        if not reference:
            return ""
        if self._keyring_available():
            import keyring
            try:
                secret = keyring.get_password(self.service, reference) or ""
                if secret:
                    return secret
            except Exception:
                pass
        if os.name == "nt":
            try:
                return self._load_dpapi().get(f"{self.service}:{reference}", "")
            except CredentialStoreError:
                return ""
        return ""

    def delete(self, reference: str) -> None:
        if not reference:
            return
        if self._keyring_available():
            import keyring
            try:
                keyring.delete_password(self.service, reference)
            except Exception:
                pass
        if os.name == "nt":
            values = self._load_dpapi()
            values.pop(f"{self.service}:{reference}", None)
            self._save_dpapi(values)


class ProviderProfileStore:
    def __init__(self, path: Optional[Path] = None, credentials: Optional[CredentialStore] = None):
        self.path = path or (get_secagentx_home() / "providers.json")
        self.credentials = credentials or CredentialStore()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": CONFIG_VERSION, "active_profile": "", "profiles": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data.get("profiles"), dict):
                raise ValueError("profiles 必须为对象")
            return data
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Provider 配置损坏: {self.path}: {exc}") from exc

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix="providers-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def active(self) -> Optional[ProviderProfile]:
        data = self.load()
        profile_id = data.get("active_profile", "")
        raw = data.get("profiles", {}).get(profile_id)
        return ProviderProfile.from_dict(raw) if raw else None

    def list_profiles(self) -> list[ProviderProfile]:
        return [ProviderProfile.from_dict(v) for v in self.load().get("profiles", {}).values()]

    def get_secret(self, profile: ProviderProfile) -> str:
        if not profile.requires_api_key:
            return "local-no-key"
        if profile.env_key and os.getenv(profile.env_key):
            return os.environ[profile.env_key]
        if profile.credential_type == "env":
            return os.getenv(profile.credential_ref or profile.env_key, "")
        return self.credentials.get(profile.credential_ref)

    def put(self, profile: ProviderProfile, api_key: str = "", make_active: bool = True) -> None:
        if profile.requires_api_key and api_key:
            profile.credential_type = "keyring"
            profile.credential_ref = profile.credential_ref or f"provider:{profile.profile_id}"
            self.credentials.set(profile.credential_ref, api_key)
        elif profile.requires_api_key and not (
            (profile.env_key and os.getenv(profile.env_key)) or self.get_secret(profile)
        ):
            raise CredentialStoreError("未提供可用 API Key")

        data = self.load()
        data["version"] = CONFIG_VERSION
        data.setdefault("profiles", {})[profile.profile_id] = asdict(profile)
        if make_active:
            data["active_profile"] = profile.profile_id
        self.save(data)

    def set_active(self, profile_id: str) -> ProviderProfile:
        data = self.load()
        raw = data.get("profiles", {}).get(profile_id)
        if not raw:
            raise KeyError(f"Provider 档案不存在: {profile_id}")
        data["active_profile"] = profile_id
        self.save(data)
        return ProviderProfile.from_dict(raw)


def activate_profile(profile: ProviderProfile, api_key: str) -> None:
    os.environ["SECAGENTX_ACTIVE_PROVIDER"] = profile.protocol
    os.environ["LLM_PROVIDER"] = profile.protocol
    os.environ["SECAGENTX_LLM_PROFILE"] = profile.profile_id
    os.environ["SECAGENTX_LLM_PROVIDER_ID"] = profile.provider_id
    os.environ["SECAGENTX_LLM_API_BASE"] = profile.api_base
    os.environ["SECAGENTX_LLM_MODEL"] = profile.model
    os.environ["SECAGENTX_LLM_AUTH_STYLE"] = profile.auth_style
    os.environ["SECAGENTX_LLM_API_VERSION"] = profile.api_version
    os.environ["SECAGENTX_LLM_ALLOW_NO_KEY"] = "true" if not profile.requires_api_key else "false"
    if api_key:
        os.environ["SECAGENTX_LLM_API_KEY"] = api_key


def activate_stored_profile(store: Optional[ProviderProfileStore] = None) -> Optional[ProviderProfile]:
    """加载活动档案到当前进程；无配置时保持现有环境变量兼容行为。"""
    store = store or ProviderProfileStore()
    try:
        profile = store.active()
        if not profile:
            return None
        secret = store.get_secret(profile)
        if profile.requires_api_key and not secret:
            logger.warning("活动 Provider %s 的凭据不可用", profile.profile_id)
            return profile
        activate_profile(profile, secret)
        return profile
    except ValueError as exc:
        logger.error("%s", exc)
        return None
