from backend.storage.database import _asyncpg_dsn


def test_asyncpg_dsn_strips_sqlalchemy_driver_name():
    url = "postgresql+asyncpg://user:secret@postgres:5432/secagentx"
    assert _asyncpg_dsn(url) == "postgresql://user:secret@postgres:5432/secagentx"


def test_asyncpg_dsn_preserves_native_postgresql_url():
    url = "postgresql://user:secret@postgres:5432/secagentx"
    assert _asyncpg_dsn(url) == url
