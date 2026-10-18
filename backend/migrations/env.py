"""Run Alembic using the separate migration credentials."""

import asyncio
from logging.config import fileConfig

from alembic import context
from alembic.runtime.environment import NameFilterParentNames, NameFilterType
from alembic.util import CommandError
from sqlalchemy.engine import Connection

from app.config import MigrationSettings
from app.database import create_migration_engine
from app.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def include_name(
    name: str | None,
    type_: NameFilterType,
    parent_names: NameFilterParentNames,
) -> bool:
    """Limit future database reflection to the application schema."""
    if type_ == "schema":
        return name == "app"

    if type_ == "table":
        return parent_names.get("schema_name") == "app"

    return True


def do_run_migrations(connection: Connection) -> None:
    """Run Alembic operations through an established connection."""
    context.configure(
        connection=connection,
        # Application model metadata will be connected in a later step.
        target_metadata=Base.metadata,
        version_table_schema="app",
        include_schemas=True,
        include_name=include_name,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Open the migration connection and always release its resources."""
    settings = MigrationSettings()
    engine = create_migration_engine(settings)

    try:
        async with engine.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """Use an event loop compatible with Psycopg on Windows."""
    asyncio.run(
        run_async_migrations(),
        loop_factory=asyncio.SelectorEventLoop,
    )


if context.is_offline_mode():
    raise CommandError("Offline SQL generation is not configured yet.")

run_migrations_online()
