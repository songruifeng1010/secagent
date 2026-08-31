"""
Alembic 迁移环境配置

使用方式:
    cd backend/storage/migrations
    alembic init .
    alembic revision --autogenerate -m "描述"
    alembic upgrade head
"""

import os
import sys
from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool

# 将项目根目录加入 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from backend.storage.models import metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 允许通过环境变量 DATABASE_URL 覆盖 SQLite 默认链接（生产 PostgreSQL）
db_url = os.getenv("DATABASE_URL", config.get_main_option("sqlalchemy.url"))
config.set_main_option("sqlalchemy.url", db_url)

target_metadata = metadata


def run_migrations_offline() -> None:
    """离线模式运行迁移（生成 SQL 脚本但不执行）"""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """在线模式运行迁移（直接修改数据库）"""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
