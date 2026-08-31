"""数据库模型与 SQLite DDL 的单一数据源。"""
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import Column, Float, Index, Integer, MetaData, String, Table, Text

metadata = MetaData()

conversations = Table(
    "conversations",
    metadata,
    Column("id", String, primary_key=True),
    Column("owner_id", String, nullable=False),
    Column("title", String, server_default=""),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

messages = Table(
    "messages",
    metadata,
    Column("id", String, primary_key=True),
    Column("conversation_id", String, nullable=False),
    Column("role", String, nullable=False),
    Column("agent_id", String, server_default=""),
    Column("content", Text, nullable=False),
    Column("metadata", Text, server_default="{}"),
    Column("parent_id", String, nullable=True),
    Column("created_at", String, nullable=False),
    sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"]),
)

agent_logs = Table(
    "agent_logs",
    metadata,
    Column("id", String, primary_key=True),
    Column("conversation_id", String, nullable=True),
    Column("agent_id", String, nullable=False),
    Column("action_type", String, nullable=False),
    Column("action_data", Text, server_default="{}"),
    Column("duration_ms", Integer, server_default="0"),
    Column("created_at", String, nullable=False),
)

events = Table(
    "events",
    metadata,
    Column("id", String, primary_key=True),
    Column("title", String, nullable=False),
    Column("severity", String, server_default="低危"),
    Column("status", String, server_default="open"),
    Column("source_ip", String, server_default=""),
    Column("alert_type", String, server_default=""),
    Column("mitre_tactic_id", String, server_default=""),
    Column("mitre_technique_id", String, server_default=""),
    Column("description", Text, server_default=""),
    Column("resolution", Text, server_default=""),
    Column("resolved_by", String, server_default=""),
    Column("raw_data", Text, server_default="{}"),
    Column("created_at", String, nullable=False),
    Column("resolved_at", String, nullable=True),
)

tool_calls = Table(
    "tool_calls",
    metadata,
    Column("id", String, primary_key=True),
    Column("agent_id", String, nullable=False),
    Column("tool_name", String, nullable=False),
    Column("parameters", Text, server_default="{}"),
    Column("result", Text, server_default="{}"),
    Column("success", Integer, server_default="0"),
    Column("duration_ms", Integer, server_default="0"),
    Column("created_at", String, nullable=False),
)

ioc_database = Table(
    "ioc_database",
    metadata,
    Column("id", String, primary_key=True),
    Column("ioc_type", String, nullable=False),
    Column("ioc_value", String, nullable=False),
    Column("threat_type", String, server_default=""),
    Column("confidence", Float, server_default="0.0"),
    Column("source", String, server_default=""),
    Column("first_seen", String, nullable=False),
    Column("last_seen", String, nullable=False),
    Column("tags", Text, server_default="[]"),
    sa.UniqueConstraint("ioc_type", "ioc_value"),
)

experiences = Table(
    "experiences",
    metadata,
    Column("id", String, primary_key=True),
    Column("scenario", String, nullable=False),
    Column("input_summary", String, server_default=""),
    Column("actions_taken", Text, server_default="[]"),
    Column("outcome", String, server_default=""),
    Column("lessons", String, server_default=""),
    Column("vector_id", String, server_default=""),
    Column("created_at", String, nullable=False),
    Column("times_used", Integer, server_default="0"),
)

assets = Table(
    "assets",
    metadata,
    Column("id", String, primary_key=True),
    Column("ip", String, server_default=""),
    Column("hostname", String, server_default=""),
    Column("criticality", String, server_default="medium"),
    Column("business_unit", String, server_default=""),
    Column("contains_pii", Integer, server_default="0"),
    Column("exposed", Integer, server_default="0"),
    Column("tags", Text, server_default="[]"),
    Column("updated_at", String, nullable=False),
)

Index("idx_conversations_owner", conversations.c.owner_id)
Index("idx_messages_conversation", messages.c.conversation_id)
Index("idx_events_severity", events.c.severity)
Index("idx_events_source_ip", events.c.source_ip)
Index("idx_ioc_value", ioc_database.c.ioc_value)
Index("idx_ioc_type", ioc_database.c.ioc_type)
Index("idx_assets_ip", assets.c.ip)
Index("idx_assets_hostname", assets.c.hostname)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, title TEXT DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id),
    role TEXT NOT NULL, agent_id TEXT DEFAULT '', content TEXT NOT NULL,
    metadata TEXT DEFAULT '{}', parent_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_logs (
    id TEXT PRIMARY KEY, conversation_id TEXT, agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL, action_data TEXT DEFAULT '{}',
    duration_ms INTEGER DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT '低危',
    status TEXT NOT NULL DEFAULT 'open', source_ip TEXT DEFAULT '', alert_type TEXT DEFAULT '',
    mitre_tactic_id TEXT DEFAULT '', mitre_technique_id TEXT DEFAULT '',
    description TEXT DEFAULT '', resolution TEXT DEFAULT '', resolved_by TEXT DEFAULT '',
    raw_data TEXT DEFAULT '{}', created_at TEXT NOT NULL, resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS tool_calls (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, tool_name TEXT NOT NULL,
    parameters TEXT DEFAULT '{}', result TEXT DEFAULT '{}',
    success INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ioc_database (
    id TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, ioc_value TEXT NOT NULL,
    threat_type TEXT DEFAULT '', confidence REAL DEFAULT 0.0, source TEXT DEFAULT '',
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, tags TEXT DEFAULT '[]',
    UNIQUE(ioc_type, ioc_value)
);
CREATE TABLE IF NOT EXISTS experiences (
    id TEXT PRIMARY KEY, scenario TEXT NOT NULL, input_summary TEXT DEFAULT '',
    actions_taken TEXT DEFAULT '[]', outcome TEXT DEFAULT '', lessons TEXT DEFAULT '',
    vector_id TEXT DEFAULT '', created_at TEXT NOT NULL, times_used INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY, ip TEXT DEFAULT '', hostname TEXT DEFAULT '',
    criticality TEXT DEFAULT 'medium', business_unit TEXT DEFAULT '',
    contains_pii INTEGER DEFAULT 0, exposed INTEGER DEFAULT 0,
    tags TEXT DEFAULT '[]', updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conversations_owner ON conversations(owner_id);
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_database(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_database(ioc_type);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
"""


def init_db(db_path: str):
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
