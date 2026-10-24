"""Rolling authentication-limit storage and grants on guarded PostgreSQL."""

from datetime import UTC, datetime, timedelta, timezone
from secrets import token_bytes

import pytest
from psycopg.errors import CheckViolation, InsufficientPrivilege, NotNullViolation, UniqueViolation
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from app.models import AuthRateLimit

pytestmark = pytest.mark.integration


def insert_limit(connection: Connection, **overrides: object) -> bytes:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "purpose": "password_recovery",
        "key_hash": token_bytes(32),
        "request_times": [now],
        "expires_at": now + timedelta(minutes=10),
    }
    values.update(overrides)
    key = connection.scalar(
        insert(AuthRateLimit).values(**values).returning(AuthRateLimit.key_hash)
    )
    assert isinstance(key, bytes)
    return key


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
def test_application_can_insert_lock_read_update_and_delete_window(
    app_connection: Connection,
    purpose: str,
) -> None:
    key = insert_limit(app_connection, purpose=purpose)
    identity = (AuthRateLimit.purpose == purpose, AuthRateLimit.key_hash == key)
    statement = select(AuthRateLimit).where(*identity)
    original = app_connection.execute(statement.with_for_update()).one()
    later = original.request_times[0] + timedelta(seconds=5)
    deadline = later + timedelta(minutes=10)
    app_connection.execute(
        update(AuthRateLimit)
        .where(*identity)
        .values(request_times=[*original.request_times, later], expires_at=deadline)
    )
    updated = app_connection.execute(statement).one()
    assert updated.request_times == [*original.request_times, later]
    assert updated.expires_at == deadline
    assert updated.purpose == purpose
    assert updated.key_hash == key
    assert all(item.utcoffset() == timedelta(0) for item in updated.request_times)
    assert updated.expires_at.utcoffset() == timedelta(0)
    assert (
        app_connection.scalar(
            delete(AuthRateLimit).where(*identity).returning(AuthRateLimit.key_hash)
        )
        == key
    )
    assert app_connection.execute(statement).first() is None


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
def test_duplicate_key_rejects_insert_and_preserves_existing_state(
    app_connection: Connection,
    purpose: str,
) -> None:
    key = insert_limit(app_connection, purpose=purpose)
    statement = select(AuthRateLimit).where(
        AuthRateLimit.purpose == purpose, AuthRateLimit.key_hash == key
    )
    original = app_connection.execute(statement).one()
    with pytest.raises(IntegrityError) as caught:
        with app_connection.begin_nested():
            insert_limit(app_connection, purpose=purpose, key_hash=key)
    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "pk_auth_rate_limits"
    assert app_connection.execute(statement).one() == original


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
@pytest.mark.parametrize("column", ["purpose", "key_hash", "request_times", "expires_at"])
def test_required_fields_reject_null(app_connection: Connection, purpose: str, column: str) -> None:
    values: dict[str, object] = {"purpose": purpose, column: None}
    with pytest.raises(IntegrityError) as caught:
        insert_limit(app_connection, **values)
    assert isinstance(caught.value.orig, NotNullViolation)
    assert caught.value.orig.diag.column_name == column


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
@pytest.mark.parametrize("size", [0, 31, 33])
def test_fingerprint_must_have_32_bytes(
    app_connection: Connection, purpose: str, size: int
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_limit(app_connection, purpose=purpose, key_hash=b"k" * size)
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == "ck_auth_rate_limits_key_hash_length"


@pytest.mark.parametrize("purpose", ["", "sign_out", "SIGN_UP", "sign_up ", "password_reset"])
def test_unsupported_operations_are_rejected(app_connection: Connection, purpose: str) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_limit(app_connection, purpose=purpose)
    assert isinstance(caught.value.orig, CheckViolation)
    assert (
        caught.value.orig.diag.constraint_name
        == "ck_auth_rate_limits_purpose_supported_with_sign_up"
    )


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
@pytest.mark.parametrize("count", [0, 1, 10, 1000])
def test_timestamp_array_size_boundaries_are_accepted(
    app_connection: Connection, purpose: str, count: int
) -> None:
    times = [datetime.now(UTC)] * count
    key = insert_limit(app_connection, purpose=purpose, request_times=times)
    assert (
        app_connection.scalar(
            select(AuthRateLimit.request_times).where(AuthRateLimit.key_hash == key)
        )
        == times
    )


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
def test_timestamp_array_rejects_more_than_1000_entries(
    app_connection: Connection, purpose: str
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_limit(app_connection, purpose=purpose, request_times=[datetime.now(UTC)] * 1001)
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == "ck_auth_rate_limits_request_times_size"


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
def test_timestamp_array_rejects_null_elements(app_connection: Connection, purpose: str) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_limit(app_connection, purpose=purpose, request_times=[None])
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == "ck_auth_rate_limits_request_times_no_nulls"


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
@pytest.mark.parametrize(
    "literal",
    [
        '[0:0]={"2026-10-24 00:00:00+00"}',
        '{{"2026-10-24 00:00:00+00"},{"2026-10-24 00:00:01+00"}}',
    ],
    ids=["zero-based", "multidimensional"],
)
def test_nonstandard_array_shapes_are_rejected(
    app_connection: Connection, purpose: str, literal: str
) -> None:
    with pytest.raises(DBAPIError) as caught:
        app_connection.execute(
            text(
                "INSERT INTO app.auth_rate_limits "
                "(purpose, key_hash, request_times, expires_at) VALUES "
                "(:purpose, :key, CAST(:times AS TIMESTAMPTZ[]), :expiry)"
            ),
            {
                "purpose": purpose,
                "key": token_bytes(32),
                "times": literal,
                "expiry": datetime.now(UTC),
            },
        )
    # PostgreSQL can reject multidimensional input in array_position before
    # evaluating the shape CHECK. Both outcomes reject the invalid row.
    assert getattr(caught.value.orig, "sqlstate", None) in {"23514", "0A000"}


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
def test_timezone_offsets_preserve_the_same_instant(
    app_connection: Connection, purpose: str
) -> None:
    instant = datetime(2026, 10, 24, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    key = insert_limit(
        app_connection,
        purpose=purpose,
        request_times=[instant],
        expires_at=instant + timedelta(minutes=10),
    )
    row = app_connection.execute(select(AuthRateLimit).where(AuthRateLimit.key_hash == key)).one()
    assert row.request_times == [instant.astimezone(UTC)]
    assert row.expires_at == (instant + timedelta(minutes=10)).astimezone(UTC)


@pytest.mark.parametrize("purpose", ["password_recovery", "sign_in", "sign_up"])
@pytest.mark.parametrize("column", ["purpose", "key_hash"])
def test_application_cannot_reassign_key_columns(
    app_connection: Connection, purpose: str, column: str
) -> None:
    key = insert_limit(app_connection, purpose=purpose)
    other_purpose = "sign_in" if purpose == "password_recovery" else "password_recovery"
    value = other_purpose if column == "purpose" else token_bytes(32)
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(
            update(AuthRateLimit).where(AuthRateLimit.key_hash == key).values(**{column: value})
        )
    assert isinstance(caught.value.orig, InsufficientPrivilege)


def test_same_fingerprint_can_hold_independent_state_for_each_operation(
    app_connection: Connection,
) -> None:
    key = insert_limit(app_connection)
    recovery = app_connection.execute(
        select(AuthRateLimit).where(
            AuthRateLimit.purpose == "password_recovery", AuthRateLimit.key_hash == key
        )
    ).one()
    insert_limit(app_connection, purpose="sign_in", key_hash=key, request_times=[])
    sign_in_identity = (AuthRateLimit.purpose == "sign_in", AuthRateLimit.key_hash == key)
    app_connection.execute(
        update(AuthRateLimit).where(*sign_in_identity).values(request_times=[datetime.now(UTC)])
    )
    assert (
        app_connection.scalar(select(AuthRateLimit.purpose).where(*sign_in_identity)) == "sign_in"
    )
    app_connection.execute(delete(AuthRateLimit).where(*sign_in_identity))
    assert (
        app_connection.execute(select(AuthRateLimit).where(AuthRateLimit.key_hash == key)).one()
        == recovery
    )


@pytest.mark.parametrize("privilege", ["UPDATE", "TRUNCATE", "REFERENCES", "TRIGGER"])
def test_application_lacks_extra_table_wide_privileges(
    app_connection: Connection, privilege: str
) -> None:
    assert (
        app_connection.scalar(
            text("SELECT has_table_privilege(current_user, 'app.auth_rate_limits', :privilege)"),
            {"privilege": privilege},
        )
        is False
    )


def test_application_cannot_truncate_limits(app_connection: Connection) -> None:
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(text("TRUNCATE TABLE app.auth_rate_limits"))
    assert isinstance(caught.value.orig, InsufficientPrivilege)


def test_public_has_no_table_grants(app_connection: Connection) -> None:
    assert (
        app_connection.scalar(
            text(
                "SELECT count(*) FROM pg_class AS c "
                "CROSS JOIN LATERAL "
                "aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) AS a "
                "WHERE c.oid = 'app.auth_rate_limits'::regclass AND a.grantee = 0"
            )
        )
        == 0
    )
