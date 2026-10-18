"""Database engine creation and connection security."""

import asyncio
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.config import Settings


def create_database_engine(settings: Settings) -> AsyncEngine | None:
    """Create a connection pool without opening a database connection."""
    if settings.database_url is None:
        return None

    try:
        url = make_url(settings.database_url.get_secret_value())
    except (ArgumentError, ValueError):
        raise ValueError("DATABASE_URL is not a valid database URL.") from None

    if url.drivername != "postgresql+psycopg":
        raise ValueError("DATABASE_URL must use postgresql+psycopg://.")

    if not url.host or not url.database:
        raise ValueError("DATABASE_URL must include a host and database.")

    local_hosts = {"localhost", "127.0.0.1", "::1"}

    if url.host not in local_hosts:
        if url.query.get("sslmode") != "verify-full":
            raise ValueError("Remote databases require sslmode=verify-full.")

        certificate = url.query.get("sslrootcert")
        if not isinstance(certificate, str) or not certificate:
            raise ValueError("Remote databases require sslrootcert.")

        if not Path(certificate).is_file():
            raise ValueError("The database CA certificate file was not found.")

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
