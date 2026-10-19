"""Opt-in PostgreSQL fixtures restricted to the local migrated test database."""

import os
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool


@pytest.fixture(scope="module")
def integration_engine() -> Iterator[Engine]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("Set TEST_DATABASE_URL to opt into local PostgreSQL integration tests.")

    try:
        url = make_url(SecretStr(os.environ["TEST_DATABASE_URL"]).get_secret_value())
    except (ArgumentError, ValueError):
        pytest.fail("TEST_DATABASE_URL is invalid.", pytrace=False)

    if (
        url.drivername != "postgresql+psycopg"
        or url.host != "127.0.0.1"
        or url.port != 15432
        or url.database != "askm6_test"
        or url.username != "mazda6_admin"
        or url.query
    ):
        pytest.fail(
            "Integration tests require 127.0.0.1:15432/askm6_test as mazda6_admin "
            "without URL query parameters.",
            pytrace=False,
        )

    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
        echo=False,
        hide_parameters=True,
    )
    try:
        backend = Path(__file__).resolve().parents[2]
        head = ScriptDirectory.from_config(Config(str(backend / "alembic.ini"))).get_current_head()
        assert head is not None, "Create the first migration before running integration tests."
        with engine.connect() as connection:
            identity = connection.execute(text("SELECT current_database(), current_user")).one()
            assert tuple(identity) == ("askm6_test", "mazda6_admin"), (
                "Unexpected database identity."
            )
            revision = connection.scalar(text("SELECT version_num FROM app.alembic_version"))
            assert revision == head, "Apply migrations to the local test database first."
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def app_connection(integration_engine: Engine) -> Iterator[Connection]:
    """Exercise application-role permissions and roll back every test's changes."""
    with integration_engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
            connection.execute(text("SET LOCAL ROLE askm6_app"))
            restricted = connection.scalar(
                text(
                    "SELECT current_user = 'askm6_app' AND NOT rolsuper AND NOT rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            )
            assert restricted is True, "Tests must execute as the restricted application role."
            yield connection
        finally:
            transaction.rollback()


@pytest.fixture
def async_app_connection_factory(
    integration_engine: Engine,
) -> Callable[[], AbstractAsyncContextManager[AsyncConnection]]:
    """Provide asynchronous application connections with automatic rollback."""

    @asynccontextmanager
    async def connect() -> AsyncIterator[AsyncConnection]:
        engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
            echo=False,
            hide_parameters=True,
        )
        try:
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    await connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
                    await connection.execute(text("SET LOCAL ROLE askm6_app"))
                    assert await connection.scalar(text("SELECT current_user")) == "askm6_app"
                    yield connection
                finally:
                    await transaction.rollback()
        finally:
            await engine.dispose()

    return connect
