"""Database engine creation and connection security."""

import asyncio
from pathlib import Path

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import MigrationSettings, Settings


def _validate_database_url(value: SecretStr, setting_name: str) -> URL:
    """Validate a database URL without exposing its credentials."""
    try:
        url = make_url(value.get_secret_value())
    except (ArgumentError, ValueError):
        raise ValueError(f"{setting_name} is not a valid database URL.") from None

    if url.drivername != "postgresql+psycopg":
        raise ValueError(f"{setting_name} must use postgresql+psycopg://.")

    if not url.host or not url.database:
        raise ValueError(f"{setting_name} must include a host and database.")

    local_hosts = {"localhost", "127.0.0.1", "::1"}

    if url.host not in local_hosts:
        if url.query.get("sslmode") != "verify-full":
            raise ValueError("Remote databases require sslmode=verify-full.")

        certificate = url.query.get("sslrootcert")
        if not isinstance(certificate, str) or not certificate:
            raise ValueError("Remote databases require sslrootcert.")

        if not Path(certificate).is_file():
            raise ValueError("The database CA certificate file was not found.")

    return url


def create_database_engine(settings: Settings) -> AsyncEngine | None:
    """Create a connection pool without opening a database connection."""
    if settings.database_url is None:
        return None

    url = _validate_database_url(settings.database_url, "DATABASE_URL")

    return create_async_engine(
        url,
        pool_size=settings.db_pool_size,
        max_overflow=0,
        pool_timeout=settings.db_connect_timeout_seconds,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": settings.db_connect_timeout_seconds,
        },
        echo=False,
        hide_parameters=True,
    )


def create_migration_engine(settings: MigrationSettings) -> AsyncEngine:
    """Create an engine using the separate migration credentials."""
    if settings.migration_database_url is None:
        raise ValueError("MIGRATION_DATABASE_URL must be configured.")

    url = _validate_database_url(
        settings.migration_database_url,
        "MIGRATION_DATABASE_URL",
    )

    return create_async_engine(
        url,
        poolclass=NullPool,
        connect_args={
            "connect_timeout": settings.db_connect_timeout_seconds,
        },
        echo=False,
        hide_parameters=True,
    )


async def database_is_ready(
    engine: AsyncEngine | None,
    timeout_seconds: float,
) -> bool:
    """Check database connectivity without exposing connection errors."""
    if engine is None:
        return False

    try:
        async with asyncio.timeout(timeout_seconds):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, TimeoutError):
        return False

    return True
