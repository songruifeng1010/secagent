import json

from backend.config.provider_profiles import (
    ProviderProfile,
    ProviderProfileStore,
    activate_profile,
)


class MemoryCredentials:
    def __init__(self):
        self.values = {}

    def set(self, reference, secret):
        self.values[reference] = secret

    def get(self, reference):
        return self.values.get(reference, "")

    def delete(self, reference):
        self.values.pop(reference, None)


def profile(**overrides):
    values = dict(
        profile_id="corp",
        provider_id="custom_openai",
        label="Corp Gateway",
        protocol="openai_compatible",
        api_base="https://llm.example.test/v1",
        model="security-model",
        credential_ref="provider:corp",
    )
    values.update(overrides)
    return ProviderProfile(**values)


def test_profile_json_never_contains_api_key(tmp_path):
    credentials = MemoryCredentials()
    store = ProviderProfileStore(tmp_path / "providers.json", credentials)
    store.put(profile(), api_key="top-secret-value")

    raw = store.path.read_text(encoding="utf-8")
    assert "top-secret-value" not in raw
    assert json.loads(raw)["active_profile"] == "corp"
    assert store.get_secret(store.active()) == "top-secret-value"


def test_environment_secret_takes_precedence(tmp_path, monkeypatch):
    credentials = MemoryCredentials()
    credentials.set("provider:corp", "stored")
    current = profile(env_key="CORP_LLM_KEY")
    store = ProviderProfileStore(tmp_path / "providers.json", credentials)
    store.put(current)
    monkeypatch.setenv("CORP_LLM_KEY", "from-env")

    assert store.get_secret(current) == "from-env"


def test_activate_profile_sets_shared_runtime(monkeypatch):
    current = profile()
    touched = (
        "SECAGENTX_ACTIVE_PROVIDER", "LLM_PROVIDER", "SECAGENTX_LLM_PROFILE",
        "SECAGENTX_LLM_PROVIDER_ID", "SECAGENTX_LLM_API_BASE",
        "SECAGENTX_LLM_MODEL", "SECAGENTX_LLM_AUTH_STYLE",
        "SECAGENTX_LLM_API_VERSION", "SECAGENTX_LLM_ALLOW_NO_KEY",
        "SECAGENTX_LLM_API_KEY",
    )
    # 先通过 monkeypatch 注册原值，确保 activate_profile 的直接写入在用例后全部恢复。
    for key in touched:
        monkeypatch.setenv(key, "before-test")
    activate_profile(current, "secret")

    assert __import__("os").environ["SECAGENTX_ACTIVE_PROVIDER"] == "openai_compatible"
    assert __import__("os").environ["SECAGENTX_LLM_MODEL"] == "security-model"
    assert __import__("os").environ["SECAGENTX_LLM_API_KEY"] == "secret"


def test_switch_active_profile(tmp_path):
    credentials = MemoryCredentials()
    store = ProviderProfileStore(tmp_path / "providers.json", credentials)
    store.put(profile(profile_id="one", credential_ref="provider:one"), api_key="a")
    store.put(profile(profile_id="two", credential_ref="provider:two"), api_key="b")

    selected = store.set_active("one")
    assert selected.profile_id == "one"
    assert store.active().profile_id == "one"
