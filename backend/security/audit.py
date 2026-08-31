"""
操作审计日志模块
"""
import uuid
import json
import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional


def _get_db_path() -> str:
    """获取审计日志数据库路径（考虑测试环境 cwd 变化）"""
    return os.path.join(os.getcwd(), "data", "secagentx.db")


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT DEFAULT '{}',
    confidence REAL DEFAULT 0.0,
    result TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action_type);
"""


def ensure_audit_table():
    """确保审计日志表存在（每次写入前调用以保证测试环境可用）"""
    db_path = _get_db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(AUDIT_SCHEMA)
        conn.commit()
    finally:
        conn.close()


class AuditRepository:
    """操作审计日志仓库"""

    def log(self, actor: str, action_type: str, target: str,
            detail: Optional[dict] = None, confidence: float = 0.0,
            result: str = "", reason: str = "") -> str:
        """记录一条审计日志"""
        log_id = uuid.uuid4().hex[:12]
        # 每次写入前确保表存在（兼容测试环境目录切换）
        ensure_audit_table()
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                "INSERT INTO audit_logs (id, actor, action_type, target, detail, "
                "confidence, result, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    log_id,
                    actor,
                    action_type,
                    target,
                    json.dumps(detail or {}, ensure_ascii=False),
                    confidence,
                    result,
                    reason,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return log_id

    def query(self, target: str = "", action_type: str = "",
              limit: int = 50) -> list[dict]:
        """查询审计日志"""
        ensure_audit_table()
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            where_clauses = []
            params = []
            if target:
                where_clauses.append("target = ?")
                params.append(target)
            if action_type:
                where_clauses.append("action_type = ?")
                params.append(action_type)

            where_sql = ""
            if where_clauses:
                where_sql = "WHERE " + " AND ".join(where_clauses)

            rows = conn.execute(
                f"SELECT * FROM audit_logs {where_sql} "
                f"ORDER BY created_at DESC LIMIT ?",
                params + [limit],
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_recent(self, limit: int = 20) -> list[dict]:
        """获取最近的审计日志"""
        return self.query(limit=limit)


# 全局单例 — 注意：仅在首次 import 时创建，但表在实际写入时创建
audit_repo = AuditRepository()

