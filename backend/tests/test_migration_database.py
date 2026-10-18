"""Migration engine tests; no live database is required."""

import asyncio
from pathlib import Path

import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.engine import URL
from sqlalchemy.pool import NullPool

from app.config import MigrationSettings
from app.database import create_migration_engine


class IsolatedMigrationSettings(MigrationSettings):
    """Prevent tests from reading real migration credentials."""

    model_config = SettingsConfigDict(env_file=None)


def settings_for(
    migration_url: str | None,
    runtime_url: str | None = None,
) -> MigrationSettings:
    return IsolatedMigrationSettings(
        migration_database_url=(SecretStr(migration_url) if migration_url is not None else None),
        database_url=SecretStr(runtime_url) if runtime_url is not None else None,
    )


@pytest.mark.parametrize(
    "runtime_url",
    [
        None,
        "postgresql+psycopg://runtime:test@127.0.0.1/runtime_db",
    ],
)
def test_missing_migration_url_is_rejected(runtime_url: str | None) -> None:
    settings = settings_for(None, runtime_url)

    with pytest.raises(ValueError, match="MIGRATION_DATABASE_URL must be configured"):
        create_migration_engine(settings)


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?sslmode=require",
        "?sslmode=verify-full",
    ],
)
def test_remote_migrations_require_verified_tls(query: str) -> None:
    url = f"postgresql+psycopg://migrator:test@database.example/postgres{query}"

    with pytest.raises(ValueError):
        create_migration_engine(settings_for(url))


def test_migration_certificate_must_exist(tmp_path: Path) -> None:
    url = URL.create(
        "postgresql+psycopg",
        username="migrator",
        password="test",
        host="database.example",
        database="postgres",
        query={
            "sslmode": "verify-full",
            "sslrootcert": str(tmp_path / "missing-ca.crt"),
        },
    )

    with pytest.raises(ValueError, match="certificate file was not found"):
        create_migration_engine(settings_for(url.render_as_string(hide_password=False)))


def test_engine_uses_migration_credentials_without_retaining_connections() -> None:
    settings = settings_for(
        migration_url=("postgresql+psycopg://migrator:test@127.0.0.1/migration_db"),
        runtime_url="postgresql+psycopg://runtime:test@127.0.0.1/runtime_db",
    )

    engine = create_migration_engine(settings)

    try:
        assert engine.url.username == "migrator"
        assert engine.url.database == "migration_db"
        assert isinstance(engine.pool, NullPool)
        assert engine.echo is False
        assert engine.sync_engine.hide_parameters is True
    finally:
        asyncio.run(engine.dispose())
