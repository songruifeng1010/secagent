"""持久化刷新令牌会话与轮换状态。

刷新令牌采用一次性消费语义。若已消费的令牌再次出现，则认为令牌
可能泄露，并撤销同一 family 下的全部会话。
"""
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional


class RefreshTokenInvalid(Exception):
    """刷新令牌不存在、过期或已撤销。"""


class RefreshTokenReuseDetected(RefreshTokenInvalid):
    """检测到已轮换刷新令牌被重放。"""


@dataclass(frozen=True)
class RefreshSession:
    jti: str
    family_id: str
    user_id: str
    issued_at: float
    expires_at: float


class RefreshTokenStore:
    """SQLite 刷新会话存储，轮换通过 BEGIN IMMEDIATE 原子执行。"""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv(
            "SECAGENTX_REFRESH_SESSION_DB", "data/auth_sessions.db"
        )
        self._schema_lock = threading.Lock()
        self._schema_ready = False

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        # 相对 db_path 会随工作目录变化，测试/运维也可能删除后重建文件；
        # 不能仅凭进程内布尔值认定当前连接已经具备 schema。
        schema_exists = conn.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'refresh_sessions'"
        ).fetchone()
        if self._schema_ready and schema_exists:
            return
        with self._schema_lock:
            schema_exists = conn.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'refresh_sessions'"
            ).fetchone()
            if self._schema_ready and schema_exists:
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS refresh_sessions (
                    jti TEXT PRIMARY KEY,
                    family_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL,
                    revoked_at REAL,
                    rotated_to TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_refresh_family "
                "ON refresh_sessions(family_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_refresh_user "
                "ON refresh_sessions(user_id)"
            )
            conn.commit()
            self._schema_ready = True

    def register(self, session: RefreshSession) -> None:
        conn = self._connect()
        try:
            self._ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO refresh_sessions
                    (jti, family_id, user_id, issued_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session.jti,
                    session.family_id,
                    session.user_id,
                    session.issued_at,
                    session.expires_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def rotate(self, old_jti: str, new_session: RefreshSession) -> None:
        """原子消费旧会话并登记新会话。"""
        now = time.time()
        conn = self._connect()
        try:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM refresh_sessions WHERE jti = ?", (old_jti,)
            ).fetchone()
            if row is None:
                raise RefreshTokenInvalid("刷新会话不存在，请重新登录")
            if row["consumed_at"] is not None:
                conn.execute(
                    "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?) "
                    "WHERE family_id = ?",
                    (now, row["family_id"]),
                )
                conn.commit()
                raise RefreshTokenReuseDetected("检测到刷新令牌重放，会话已全部撤销")
            if row["revoked_at"] is not None or row["expires_at"] <= now:
                raise RefreshTokenInvalid("刷新会话已过期或撤销，请重新登录")
            if row["family_id"] != new_session.family_id:
                raise RefreshTokenInvalid("刷新令牌 family 不匹配")
            if row["user_id"] != new_session.user_id:
                raise RefreshTokenInvalid("刷新令牌用户不匹配")

            conn.execute(
                "UPDATE refresh_sessions SET consumed_at = ?, rotated_to = ? WHERE jti = ?",
                (now, new_session.jti, old_jti),
            )
            conn.execute(
                """
                INSERT INTO refresh_sessions
                    (jti, family_id, user_id, issued_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    new_session.jti,
                    new_session.family_id,
                    new_session.user_id,
                    new_session.issued_at,
                    new_session.expires_at,
                ),
            )
            conn.commit()
        except RefreshTokenReuseDetected:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def revoke_family(self, family_id: str) -> None:
        conn = self._connect()
        try:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?) "
                "WHERE family_id = ?",
                (time.time(), family_id),
            )
            conn.commit()
        finally:
            conn.close()

    def revoke_user(self, user_id: str) -> None:
        conn = self._connect()
        try:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, ?) "
                "WHERE user_id = ?",
                (time.time(), user_id),
            )
            conn.commit()
        finally:
            conn.close()


refresh_token_store = RefreshTokenStore()
