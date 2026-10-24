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


@pytest.fixture(params=["sign_up", "email_confirmation"])
def migration_case(request: pytest.FixtureRequest) -> tuple[str, str, str]:
    if request.param == "sign_up":
        return ("bcae4df0f56a", "sign_up", "ck_auth_rate_limits_purpose_supported")
    return (
        "6ef221a79f00",
        "email_confirmation",
        "ck_auth_rate_limits_purpose_supported_with_sign_up",
    )


def scripts() -> ScriptDirectory:
    backend = Path(__file__).resolve().parents[2]
    return ScriptDirectory.from_config(Config(str(backend / "alembic.ini")))


def migration(revision_id: str) -> LimiterMigration:
    revision = scripts().get_revision(revision_id)
    assert revision is not None
    return cast(LimiterMigration, revision.module)


@pytest.fixture
def migrator_connection(
    integration_engine: Engine, migration_case: tuple[str, str, str]
) -> Iterator[Connection]:
    with integration_engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET LOCAL ROLE askm6_migrator"))
            connection.execute(text("SET LOCAL statement_timeout = '5s'"))
            connection.execute(text("SET LOCAL lock_timeout = '2s'"))
            assert tuple(
                connection.execute(text("SELECT current_database(), current_user")).one()
            ) == ("askm6_test", "askm6_migrator")
            # Exercise each historical migration at its own revision, without
            # changing the recorded head or committing any DDL/data changes.
            if migration_case[0] == "bcae4df0f56a":
                if (
                    connection.scalar(
                        select(AuthRateLimit.key_hash)
                        .where(AuthRateLimit.purpose == "email_confirmation")
                        .limit(1)
                    )
                    is not None
                ):
                    pytest.skip("Existing confirmation state prevents the historical schema probe.")
            with Operations.context(MigrationContext.configure(connection)):
                for revision in scripts().walk_revisions(base=migration_case[0], head="head"):
                    if revision.revision == migration_case[0]:
                        break
                    cast(LimiterMigration, revision.module).downgrade()
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


def test_downgrade_refuses_new_purpose_state_without_losing_data(
    migrator_connection: Connection,
    migration_case: tuple[str, str, str],
) -> None:
    connection = migrator_connection
    revision_id, purpose, previous_constraint = migration_case
    key = token_bytes(32)
    connection.execute(
        insert(AuthRateLimit).values(
            purpose=purpose,
            key_hash=key,
            request_times=[datetime.now(UTC)],
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    statement = select(AuthRateLimit).where(
        AuthRateLimit.purpose == purpose, AuthRateLimit.key_hash == key
    )
    before, structure = connection.execute(statement).one(), snapshot(connection)
    with pytest.raises(IntegrityError) as caught:
        with connection.begin_nested(), Operations.context(MigrationContext.configure(connection)):
            migration(revision_id).downgrade()
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == previous_constraint
    assert connection.execute(statement).one() == before
    assert snapshot(connection) == structure


def test_safe_transition_preserves_old_records_grants_and_indexes(
    migrator_connection: Connection,
    migration_case: tuple[str, str, str],
) -> None:
    connection = migrator_connection
    revision_id, new_purpose, _ = migration_case
    if (
        connection.scalar(
            select(AuthRateLimit.key_hash).where(AuthRateLimit.purpose == new_purpose).limit(1)
        )
        is not None
    ):
        pytest.skip("Existing new-purpose state prevents the transactional round-trip probe.")
    key = token_bytes(32)
    old_purposes: tuple[str, ...] = ("password_recovery", "sign_in")
    if new_purpose == "email_confirmation":
        old_purposes = (*old_purposes, "sign_up")
    for purpose in old_purposes:
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
        migration(revision_id).downgrade()
        assert connection.execute(statement).all() == before
        migration(revision_id).upgrade()
    assert connection.execute(statement).all() == before
    assert snapshot(connection) == structure
