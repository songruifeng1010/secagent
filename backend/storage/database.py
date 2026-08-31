"""统一数据库存储层，自动适配 SQLite 与 PostgreSQL。"""
import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("secagentx.db")

DB_PATH = os.getenv("SECAGENTX_DB_PATH", "data/secagentx.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")


def _is_sqlite() -> bool:
    return "sqlite" in DATABASE_URL


def _is_postgres() -> bool:
    return "postgresql" in DATABASE_URL


def _url_is_postgres(url: str) -> bool:
    return "postgresql" in url


def _asyncpg_dsn(url: str) -> str:
    """将 SQLAlchemy asyncpg URL 转为 asyncpg 原生可接受的 DSN。"""
    prefix = "postgresql+asyncpg://"
    if url.startswith(prefix):
        return f"postgresql://{url[len(prefix):]}"
    return url


def get_db_path() -> str:
    path = Path(DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def get_sqlite_path(url: Optional[str] = None) -> str:
    """返回 SQLite URL 对应的文件路径，统一配置与初始化所用数据库。"""
    database_url = url or DATABASE_URL
    if database_url.startswith("sqlite:///"):
        path = Path(database_url.removeprefix("sqlite:///"))
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)
    return get_db_path()


class Database:
    """同步 SQLite 连接（供 CLI 和兼容代码使用）。"""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_db_path()
        self._conn = None

    def connect(self):
        import sqlite3

        if self._conn is not None:
            try:
                self._conn.execute("SELECT 1")
                return self._conn
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                self.close()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=10000")
        return self._conn

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def execute(self, sql: str, params: tuple = ()):
        import sqlite3
        import time

        for attempt in range(3):
            try:
                connection = self.connect()
                cursor = connection.execute(sql, params)
                if sql.lstrip().upper().startswith(
                    ("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")
                ):
                    connection.commit()
                return cursor
            except sqlite3.OperationalError as exc:
                if "database is locked" in str(exc) and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    self.close()
                    continue
                raise

    def fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        row = self.execute(sql, params).fetchone()
        return dict(row) if row else None

    def fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(row) for row in self.execute(sql, params).fetchall()]

    def insert(self, sql: str, params: tuple = ()) -> int:
        cursor = self.execute(sql, params)
        return cursor.lastrowid or 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Repository:
    """异步统一仓储连接；SQLite 调用同步执行，PostgreSQL 使用 asyncpg。"""

    def __init__(self, url: Optional[str] = None):
        self.url = url or DATABASE_URL
        self._conn_sqlite = None
        self._conn_pg: Optional[Any] = None

    async def execute(self, sql: str, params: tuple = ()) -> Any:
        if _url_is_postgres(self.url):
            return await self._execute_pg(sql, params)
        return self._execute_sqlite(sql, params)

    async def fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        if _url_is_postgres(self.url):
            return await self._fetch_one_pg(sql, params)
        row = self._execute_sqlite(sql, params).fetchone()
        return dict(row) if row else None

    async def fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        if _url_is_postgres(self.url):
            return await self._fetch_all_pg(sql, params)
        return [dict(row) for row in self._execute_sqlite(sql, params).fetchall()]

    async def close(self):
        if _url_is_postgres(self.url):
            if self._conn_pg:
                try:
                    await self._conn_pg.close()
                finally:
                    self._conn_pg = None
        elif self._conn_sqlite:
            try:
                self._conn_sqlite.close()
            finally:
                self._conn_sqlite = None

    def _get_sqlite_conn(self):
        import sqlite3

        if self._conn_sqlite is not None:
            try:
                self._conn_sqlite.execute("SELECT 1")
                return self._conn_sqlite
            except Exception:
                self._conn_sqlite.close()
                self._conn_sqlite = None
        db_path = self.url.replace("sqlite:///", "")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn_sqlite = sqlite3.connect(db_path, check_same_thread=False)
        self._conn_sqlite.row_factory = sqlite3.Row
        self._conn_sqlite.execute("PRAGMA journal_mode=WAL")
        self._conn_sqlite.execute("PRAGMA foreign_keys=ON")
        self._conn_sqlite.execute("PRAGMA busy_timeout=10000")
        return self._conn_sqlite

    def _execute_sqlite(self, sql: str, params: tuple):
        import sqlite3
        import time

        for attempt in range(3):
            try:
                conn = self._get_sqlite_conn()
                cursor = conn.execute(sql, params)
                if sql.lstrip().upper().startswith(
                    ("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")
                ):
                    conn.commit()
                return cursor
            except sqlite3.OperationalError as exc:
                if "database is locked" in str(exc) and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    if self._conn_sqlite:
                        self._conn_sqlite.close()
                        self._conn_sqlite = None
                    continue
                raise

    @staticmethod
    def _pg_parametrize(sql: str, params: tuple) -> tuple[str, list]:
        """将字符串字面量之外的 ? 转换为 asyncpg 的 $n 参数。"""
        if not params:
            return sql, []
        result = []
        index = 0
        param_index = 0
        in_quote = False
        while index < len(sql):
            char = sql[index]
            if char == "'":
                result.append(char)
                if in_quote and index + 1 < len(sql) and sql[index + 1] == "'":
                    result.append("'")
                    index += 2
                    continue
                in_quote = not in_quote
            elif char == "?" and not in_quote:
                param_index += 1
                result.append(f"${param_index}")
            else:
                result.append(char)
            index += 1
        return "".join(result), list(params)

    async def _get_pg_conn(self):
        if self._conn_pg is not None:
            try:
                await self._conn_pg.execute("SELECT 1")
                return self._conn_pg
            except Exception:
                await self._conn_pg.close()
                self._conn_pg = None
        import asyncpg
        self._conn_pg = await asyncpg.connect(_asyncpg_dsn(self.url))
        return self._conn_pg

    async def _execute_pg(self, sql: str, params: tuple):
        conn = await self._get_pg_conn()
        pg_sql, pg_params = self._pg_parametrize(sql, params)
        return await conn.execute(pg_sql, *pg_params)

    async def _fetch_one_pg(self, sql: str, params: tuple) -> Optional[dict]:
        conn = await self._get_pg_conn()
        pg_sql, pg_params = self._pg_parametrize(sql, params)
        row = await conn.fetchrow(pg_sql, *pg_params)
        return dict(row) if row else None

    async def _fetch_all_pg(self, sql: str, params: tuple) -> list[dict]:
        conn = await self._get_pg_conn()
        pg_sql, pg_params = self._pg_parametrize(sql, params)
        return [dict(row) for row in await conn.fetch(pg_sql, *pg_params)]

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


@asynccontextmanager
async def get_repository(url: Optional[str] = None):
    repo = Repository(url)
    try:
        yield repo
    finally:
        await repo.close()


class AsyncDatabase:
    """旧异步数据库接口的兼容包装。"""

    def __init__(self, db_path: Optional[str] = None):
        self.repo = Repository(f"sqlite:///{db_path or get_db_path()}")

    async def connect(self):
        return self

    async def execute(self, sql: str, params: tuple = ()):
        return await self.repo.execute(sql, params)

    async def fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        return await self.repo.fetch_one(sql, params)

    async def fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        return await self.repo.fetch_all(sql, params)

    async def insert(self, sql: str, params: tuple = ()) -> int:
        cursor = await self.repo.execute(sql, params)
        return cursor.lastrowid or 0

    async def close(self):
        await self.repo.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
