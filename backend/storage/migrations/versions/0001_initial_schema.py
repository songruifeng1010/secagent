"""初始化数据库 schema

Revision ID: 0001
Revises:
Create Date: 2026-06-26
"""

from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "messages",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("conversation_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), server_default=""),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("metadata", sa.Text(), server_default="{}"),
        sa.Column("parent_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), server_default="低危"),
        sa.Column("status", sa.String(), server_default="open"),
        sa.Column("source_ip", sa.String(), server_default=""),
        sa.Column("alert_type", sa.String(), server_default=""),
        sa.Column("mitre_tactic_id", sa.String(), server_default=""),
        sa.Column("mitre_technique_id", sa.String(), server_default=""),
        sa.Column("description", sa.Text(), server_default=""),
        sa.Column("resolution", sa.Text(), server_default=""),
        sa.Column("resolved_by", sa.String(), server_default=""),
        sa.Column("raw_data", sa.Text(), server_default="{}"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("resolved_at", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "tool_calls",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("tool_name", sa.String(), nullable=False),
        sa.Column("parameters", sa.Text(), server_default="{}"),
        sa.Column("result", sa.Text(), server_default="{}"),
        sa.Column("success", sa.Integer(), server_default="0"),
        sa.Column("duration_ms", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ioc_database",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("ioc_type", sa.String(), nullable=False),
        sa.Column("ioc_value", sa.String(), nullable=False),
        sa.Column("threat_type", sa.String(), server_default=""),
        sa.Column("confidence", sa.Float(), server_default="0.0"),
        sa.Column("source", sa.String(), server_default=""),
        sa.Column("first_seen", sa.String(), nullable=False),
        sa.Column("last_seen", sa.String(), nullable=False),
        sa.Column("tags", sa.Text(), server_default="[]"),
        sa.UniqueConstraint("ioc_type", "ioc_value"),
        sa.PrimaryKeyConstraint("id"),
    )
    # 索引
    op.create_index("idx_messages_conversation", "messages", ["conversation_id"])
    op.create_index("idx_events_severity", "events", ["severity"])
    op.create_index("idx_events_source_ip", "events", ["source_ip"])


def downgrade() -> None:
    op.drop_index("idx_events_source_ip")
    op.drop_index("idx_events_severity")
    op.drop_index("idx_messages_conversation")
    op.drop_table("ioc_database")
    op.drop_table("tool_calls")
    op.drop_table("events")
    op.drop_table("messages")
    op.drop_table("conversations")
