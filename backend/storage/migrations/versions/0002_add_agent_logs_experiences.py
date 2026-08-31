"""添加 agent_logs 和 experiences 表（补齐 DDL 差异）

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-23
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # agent_logs 表（已在 inline DDL 中但被 0001 遗漏）
    op.create_table(
        "agent_logs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("conversation_id", sa.String(), nullable=True),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("action_data", sa.Text(), server_default="{}"),
        sa.Column("duration_ms", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    # experiences 表（已在 inline DDL 中但被 0001 遗漏）
    op.create_table(
        "experiences",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("scenario", sa.String(), nullable=False),
        sa.Column("input_summary", sa.String(), server_default=""),
        sa.Column("actions_taken", sa.Text(), server_default="[]"),
        sa.Column("outcome", sa.String(), server_default=""),
        sa.Column("lessons", sa.String(), server_default=""),
        sa.Column("vector_id", sa.String(), server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("times_used", sa.Integer(), server_default="0"),
        sa.PrimaryKeyConstraint("id"),
    )
    # 补齐索引
    op.create_index("idx_ioc_value", "ioc_database", ["ioc_value"])
    op.create_index("idx_ioc_type", "ioc_database", ["ioc_type"])


def downgrade() -> None:
    op.drop_index("idx_ioc_type")
    op.drop_index("idx_ioc_value")
    op.drop_table("experiences")
    op.drop_table("agent_logs")
