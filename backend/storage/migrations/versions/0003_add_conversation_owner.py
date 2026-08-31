"""为会话增加所有者隔离。

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "conversations", sa.Column("owner_id", sa.String(), nullable=True)
    )
    # 历史版本只有单一管理员，旧会话安全地归属 admin，不允许普通用户认领。
    op.execute("UPDATE conversations SET owner_id='admin' WHERE owner_id IS NULL")
    op.alter_column("conversations", "owner_id", nullable=False)
    op.create_index("idx_conversations_owner", "conversations", ["owner_id"])


def downgrade() -> None:
    op.drop_index("idx_conversations_owner", table_name="conversations")
    op.drop_column("conversations", "owner_id")
