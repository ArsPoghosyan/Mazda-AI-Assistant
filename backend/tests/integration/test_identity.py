"""Exercise migrated identity constraints and permissions on real PostgreSQL."""

from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from uuid import UUID, uuid4

import pytest
from psycopg.errors import CheckViolation, InsufficientPrivilege, NotNullViolation, UniqueViolation
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.models import GuestSession, UserProfile

pytestmark = pytest.mark.integration


def insert_guest(connection: Connection, **overrides: object) -> UUID:
    values: dict[str, object] = {
        "token_hash": token_bytes(32),
        "expires_at": datetime.now(UTC) + timedelta(days=30),
    }
    values.update(overrides)
    guest_id = connection.scalar(insert(GuestSession).values(**values).returning(GuestSession.id))
    assert isinstance(guest_id, UUID)
    return guest_id


def test_guest_can_be_created_read_refreshed_and_deleted(app_connection: Connection) -> None:
    guest_id = insert_guest(app_connection)
    stored = app_connection.execute(
        select(GuestSession.created_at, GuestSession.last_seen_at, GuestSession.expires_at).where(
            GuestSession.id == guest_id
        )
    ).one()
    assert stored.created_at.tzinfo is not None
    assert stored.created_at == stored.last_seen_at < stored.expires_at

    refreshed_at = stored.last_seen_at + timedelta(minutes=1)
    refreshed_expiry = refreshed_at + timedelta(days=30)
    app_connection.execute(
        update(GuestSession)
        .where(GuestSession.id == guest_id)
        .values(last_seen_at=refreshed_at, expires_at=refreshed_expiry)
    )
    refreshed = app_connection.execute(
        select(GuestSession.last_seen_at, GuestSession.expires_at).where(
            GuestSession.id == guest_id
        )
    ).one()
    assert tuple(refreshed) == (refreshed_at, refreshed_expiry)

    app_connection.execute(delete(GuestSession).where(GuestSession.id == guest_id))
    assert app_connection.scalar(select(GuestSession.id).where(GuestSession.id == guest_id)) is None


def test_account_profile_can_be_created_read_and_deleted(app_connection: Connection) -> None:
    account_id = uuid4()
    created_at = app_connection.scalar(
        insert(UserProfile).values(id=account_id).returning(UserProfile.created_at)
    )
    assert isinstance(created_at, datetime)
    assert created_at.tzinfo is not None
    assert (
        app_connection.scalar(select(UserProfile.id).where(UserProfile.id == account_id))
        == account_id
    )
    app_connection.execute(delete(UserProfile).where(UserProfile.id == account_id))
    assert app_connection.scalar(select(UserProfile.id).where(UserProfile.id == account_id)) is None


def test_duplicate_account_identity_is_rejected(app_connection: Connection) -> None:
    account_id = uuid4()
    app_connection.execute(insert(UserProfile).values(id=account_id))
    with pytest.raises(IntegrityError) as error:
        app_connection.execute(insert(UserProfile).values(id=account_id))
    assert isinstance(error.value.orig, UniqueViolation)
    assert error.value.orig.diag.constraint_name == "pk_user_profiles"


def test_duplicate_guest_token_hash_is_rejected(app_connection: Connection) -> None:
    digest = token_bytes(32)
    insert_guest(app_connection, token_hash=digest)
    with pytest.raises(IntegrityError) as error:
        insert_guest(app_connection, token_hash=digest)
    assert isinstance(error.value.orig, UniqueViolation)
    assert error.value.orig.diag.constraint_name == "uq_guest_sessions_token_hash"


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_guest_hash_must_be_exactly_32_bytes(app_connection: Connection, size: int) -> None:
    with pytest.raises(IntegrityError) as error:
        insert_guest(app_connection, token_hash=token_bytes(size))
    assert isinstance(error.value.orig, CheckViolation)
    assert error.value.orig.diag.constraint_name == "ck_guest_sessions_token_hash_length"


@pytest.mark.parametrize(
    ("last_seen_seconds", "expiry_seconds", "constraint"),
    [
        (-1, 3600, "ck_guest_sessions_last_seen_after_creation"),
        (0, 0, "ck_guest_sessions_expiry_after_last_seen"),
        (0, -1, "ck_guest_sessions_expiry_after_last_seen"),
    ],
)
def test_inconsistent_guest_timestamps_are_rejected(
    app_connection: Connection,
    last_seen_seconds: int,
    expiry_seconds: int,
    constraint: str,
) -> None:
    created_at = datetime.now(UTC)
    with pytest.raises(IntegrityError) as error:
        insert_guest(
            app_connection,
            created_at=created_at,
            last_seen_at=created_at + timedelta(seconds=last_seen_seconds),
            expires_at=created_at + timedelta(seconds=expiry_seconds),
        )
    assert isinstance(error.value.orig, CheckViolation)
    assert error.value.orig.diag.constraint_name == constraint


@pytest.mark.parametrize("column", ["token_hash", "expires_at"])
def test_required_guest_fields_cannot_be_null(app_connection: Connection, column: str) -> None:
    with pytest.raises(IntegrityError) as error:
        insert_guest(app_connection, **{column: None})
    assert isinstance(error.value.orig, NotNullViolation)
    assert error.value.orig.diag.column_name == column


@pytest.mark.parametrize("column", ["id", "token_hash", "created_at"])
def test_application_cannot_rewrite_guest_identity(app_connection: Connection, column: str) -> None:
    guest_id = insert_guest(app_connection)
    replacements: dict[str, object] = {
        "id": uuid4(),
        "token_hash": token_bytes(32),
        "created_at": datetime.now(UTC) - timedelta(days=1),
    }
    with pytest.raises(ProgrammingError) as error:
        app_connection.execute(
            update(GuestSession)
            .where(GuestSession.id == guest_id)
            .values({column: replacements[column]})
        )
    assert isinstance(error.value.orig, InsufficientPrivilege)


def test_application_cannot_rewrite_account_identity(app_connection: Connection) -> None:
    account_id = uuid4()
    app_connection.execute(insert(UserProfile).values(id=account_id))
    with pytest.raises(ProgrammingError) as error:
        app_connection.execute(
            update(UserProfile).where(UserProfile.id == account_id).values(id=uuid4())
        )
    assert isinstance(error.value.orig, InsufficientPrivilege)


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT version_num FROM app.alembic_version",
        "INSERT INTO app.alembic_version (version_num) VALUES ('permission-test')",
        "UPDATE app.alembic_version SET version_num = version_num",
        "DELETE FROM app.alembic_version",
        "TRUNCATE TABLE app.guest_sessions",
        "CREATE TABLE app.identity_permission_probe (id integer)",
    ],
)
def test_application_cannot_manage_schema_or_migrations(
    app_connection: Connection, statement: str
) -> None:
    with pytest.raises(ProgrammingError) as error:
        app_connection.execute(text(statement))
    assert isinstance(error.value.orig, InsufficientPrivilege)
