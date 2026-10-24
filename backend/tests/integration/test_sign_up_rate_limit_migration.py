"""Transactional migration probes on the guarded test database; never commit DDL."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_bytes
from typing import Protocol, cast

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from psycopg.errors import CheckViolation
from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from app.models import AuthRateLimit

pytestmark = pytest.mark.integration


class LimiterMigration(Protocol):
    def upgrade(self) -> None: ...
    def downgrade(self) -> None: ...


def migration() -> LimiterMigration:
    backend = Path(__file__).resolve().parents[2]
    scripts = ScriptDirectory.from_config(Config(str(backend / "alembic.ini")))
    revision = scripts.get_revision("bcae4df0f56a")
    assert revision is not None and revision.down_revision == "0f42bd53f47a"
    return cast(LimiterMigration, revision.module)


@pytest.fixture
def migrator_connection(integration_engine: Engine) -> Iterator[Connection]:
    with integration_engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET LOCAL ROLE askm6_migrator"))
            connection.execute(text("SET LOCAL statement_timeout = '5s'"))
            connection.execute(text("SET LOCAL lock_timeout = '2s'"))
            assert tuple(
                connection.execute(text("SELECT current_database(), current_user")).one()
            ) == ("askm6_test", "askm6_migrator")
            yield connection
        finally:
            transaction.rollback()


def snapshot(connection: Connection) -> tuple[object, ...]:
    return (
        connection.execute(
            text(
                "SELECT relowner, relacl::text FROM pg_class "
                "WHERE oid='app.auth_rate_limits'::regclass"
            )
        ).all(),
        connection.execute(
            text(
                "SELECT attname, attacl::text FROM pg_attribute "
                "WHERE attrelid='app.auth_rate_limits'::regclass AND attnum>0 ORDER BY attnum"
            )
        ).all(),
        connection.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid='app.auth_rate_limits'::regclass ORDER BY conname"
            )
        ).all(),
        connection.execute(
            text(
                "SELECT indexdef FROM pg_indexes WHERE schemaname='app' "
                "AND tablename='auth_rate_limits' ORDER BY indexname"
            )
        ).all(),
    )


def test_downgrade_refuses_sign_up_state_without_losing_data(
    migrator_connection: Connection,
) -> None:
    connection = migrator_connection
    key = token_bytes(32)
    connection.execute(
        insert(AuthRateLimit).values(
            purpose="sign_up",
            key_hash=key,
            request_times=[datetime.now(UTC)],
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    statement = select(AuthRateLimit).where(
        AuthRateLimit.purpose == "sign_up", AuthRateLimit.key_hash == key
    )
    before, structure = connection.execute(statement).one(), snapshot(connection)
    with pytest.raises(IntegrityError) as caught:
        with connection.begin_nested(), Operations.context(MigrationContext.configure(connection)):
            migration().downgrade()
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == "ck_auth_rate_limits_purpose_supported"
    assert connection.execute(statement).one() == before
    assert snapshot(connection) == structure


def test_safe_transition_preserves_old_records_grants_and_indexes(
    migrator_connection: Connection,
) -> None:
    connection = migrator_connection
    if (
        connection.scalar(
            select(AuthRateLimit.key_hash).where(AuthRateLimit.purpose == "sign_up").limit(1)
        )
        is not None
    ):
        pytest.skip("Existing sign-up state prevents the optional transactional round-trip probe.")
    key = token_bytes(32)
    for purpose in ("password_recovery", "sign_in"):
        connection.execute(
            insert(AuthRateLimit).values(
                purpose=purpose,
                key_hash=key,
                request_times=[datetime.now(UTC)],
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
        )
    statement = (
        select(AuthRateLimit).where(AuthRateLimit.key_hash == key).order_by(AuthRateLimit.purpose)
    )
    before, structure = connection.execute(statement).all(), snapshot(connection)
    with Operations.context(MigrationContext.configure(connection)):
        migration().downgrade()
        assert connection.execute(statement).all() == before
        migration().upgrade()
    assert connection.execute(statement).all() == before
    assert snapshot(connection) == structure
