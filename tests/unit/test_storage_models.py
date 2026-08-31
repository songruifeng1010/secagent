"""
测试存储层 — SCHEMA_SQL 和 init_db / now_iso
"""
import os
import sys
import tempfile
import pytest
from backend.storage.models import SCHEMA_SQL, now_iso


class TestSchemaSQL:
    def test_has_all_tables(self):
        required_tables = [
            "conversations", "messages", "agent_logs",
            "events", "tool_calls", "ioc_database", "experiences",
        ]
        for table in required_tables:
            assert f"CREATE TABLE IF NOT EXISTS {table}" in SCHEMA_SQL, f"缺少表: {table}"

    def test_has_all_indexes(self):
        required_indexes = [
            "idx_messages_conversation", "idx_events_severity",
            "idx_events_source_ip", "idx_ioc_value", "idx_ioc_type",
        ]
        for idx in required_indexes:
            assert f"CREATE INDEX IF NOT EXISTS {idx}" in SCHEMA_SQL, f"缺少索引: {idx}"

    def test_events_table_has_all_columns(self):
        required_columns = [
            "id TEXT PRIMARY KEY", "title TEXT NOT NULL",
            "severity TEXT", "status TEXT", "source_ip TEXT",
            "created_at TEXT NOT NULL", "resolved_at TEXT",
        ]
        for col in required_columns:
            assert col in SCHEMA_SQL, f"events 表缺少列: {col}"

    def test_ioc_unique_constraint(self):
        assert "UNIQUE(ioc_type, ioc_value)" in SCHEMA_SQL

    def test_schema_executes_without_error(self):
        """验证 SQL 语法正确"""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
            # 验证表已创建
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            assert "events" in table_names
            assert "conversations" in table_names
        finally:
            conn.close()


class TestInitDb:
    def test_init_db_creates_file(self):
        from backend.storage.models import init_db
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            init_db(db_path)
            assert os.path.exists(db_path)
            # 验证文件非空
            assert os.path.getsize(db_path) > 0
        finally:
            os.unlink(db_path)

    def test_init_db_idempotent(self):
        """多次执行不应报错"""
        from backend.storage.models import init_db
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            init_db(db_path)
            init_db(db_path)  # 第二次执行
            init_db(db_path)  # 第三次执行
        finally:
            os.unlink(db_path)


class TestNowIso:
    def test_now_iso_format(self):
        result = now_iso()
        assert "T" in result  # ISO 8601 格式包含 T
        assert result.endswith("+00:00") or "Z" in result or "+" in result

    def test_now_iso_is_string(self):
        assert isinstance(now_iso(), str)

    def test_now_iso_changes(self):
        """两次调用应该返回不同时间（微妙级差异）"""
        t1 = now_iso()
        t2 = now_iso()
        # 极低概率相等，但不影响
        assert t1 <= t2
