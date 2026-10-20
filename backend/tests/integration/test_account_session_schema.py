"""Account-session schema tests against the guarded local test database."""

from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from psycopg.errors import (
    CheckViolation,
    ForeignKeyViolation,
    InsufficientPrivilege,
    NotNullViolation,
    UniqueViolation,
)
from pydantic import SecretStr
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.account_token_encryption import AccountTokenCipher
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration


@pytest.fixture
def cipher() -> AccountTokenCipher:
    return AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))


def insert_account_session(
    connection: Connection,
    cipher: AccountTokenCipher,
    **overrides: object,
) -> tuple[UUID, UUID]:
    user_id = uuid4()
    connection.execute(insert(UserProfile).values(id=user_id))

    now = datetime.now(UTC)
    values: dict[str, object] = {
        "user_id": user_id,
        "token_hash": token_bytes(32),
        "provider_session_id": uuid4(),
        "access_token_ciphertext": cipher.encrypt(SecretStr("synthetic-access")),
        "refresh_token_ciphertext": cipher.encrypt(SecretStr("synthetic-refresh")),
        "access_token_expires_at": now + timedelta(hours=1),
        "idle_expires_at": now + timedelta(days=7),
        "absolute_expires_at": now + timedelta(days=30),
    }
    values.update(overrides)

    session_id = connection.scalar(
        insert(AccountSession).values(**values).returning(AccountSession.id)
    )
    assert isinstance(session_id, UUID)
    return user_id, session_id


def test_session_can_be_created_read_refreshed_and_deleted(
    app_connection: Connection,
    cipher: AccountTokenCipher,
) -> None:
    user_id, session_id = insert_account_session(app_connection, cipher)

    stored = app_connection.execute(
        select(AccountSession).where(AccountSession.id == session_id)
    ).one()

    assert stored.user_id == user_id
    assert len(stored.token_hash) == 32
    assert stored.created_at.tzinfo is not None
    assert stored.created_at == stored.last_seen_at
    assert stored.last_seen_at < stored.idle_expires_at <= stored.absolute_expires_at
    assert cipher.decrypt(stored.access_token_ciphertext).get_secret_value() == "synthetic-access"
    assert cipher.decrypt(stored.refresh_token_ciphertext).get_secret_value() == "synthetic-refresh"

    refreshed_at = stored.last_seen_at + timedelta(minutes=1)
    idle_expiry = min(
        refreshed_at + timedelta(days=7),
        stored.absolute_expires_at,
    )
    access_expiry = refreshed_at + timedelta(hours=1)

    app_connection.execute(
        update(AccountSession)
        .where(AccountSession.id == session_id)
        .values(
            access_token_ciphertext=cipher.encrypt(SecretStr("replacement-access")),
            refresh_token_ciphertext=cipher.encrypt(SecretStr("replacement-refresh")),
            access_token_expires_at=access_expiry,
            last_seen_at=refreshed_at,
            idle_expires_at=idle_expiry,
        )
    )

    refreshed = app_connection.execute(
        select(AccountSession).where(AccountSession.id == session_id)
    ).one()

    assert refreshed.last_seen_at == refreshed_at
    assert refreshed.idle_expires_at == idle_expiry
    assert refreshed.absolute_expires_at == stored.absolute_expires_at
    assert refreshed.access_token_expires_at == access_expiry
    assert (
        cipher.decrypt(refreshed.access_token_ciphertext).get_secret_value() == "replacement-access"
    )
    assert (
        cipher.decrypt(refreshed.refresh_token_ciphertext).get_secret_value()
        == "replacement-refresh"
    )

    app_connection.execute(delete(AccountSession).where(AccountSession.id == session_id))
    assert (
        app_connection.scalar(select(AccountSession.id).where(AccountSession.id == session_id))
        is None
    )
    assert app_connection.scalar(select(UserProfile.id).where(UserProfile.id == user_id)) == user_id


def test_deleting_account_profile_removes_its_sessions(
    app_connection: Connection,
    cipher: AccountTokenCipher,
) -> None:
    user_id, session_id = insert_account_session(app_connection, cipher)

    app_connection.execute(delete(UserProfile).where(UserProfile.id == user_id))

    assert (
        app_connection.scalar(select(AccountSession.id).where(AccountSession.id == session_id))
        is None
    )


def test_duplicate_session_token_hash_is_rejected(
    app_connection: Connection,
    cipher: AccountTokenCipher,
) -> None:
    digest = token_bytes(32)
    insert_account_session(app_connection, cipher, token_hash=digest)

    with pytest.raises(IntegrityError) as caught:
        insert_account_session(app_connection, cipher, token_hash=digest)

    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "uq_account_sessions_token_hash"


def test_session_requires_an_existing_account(
    app_connection: Connection,
    cipher: AccountTokenCipher,
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_account_session(app_connection, cipher, user_id=uuid4())

    assert isinstance(caught.value.orig, ForeignKeyViolation)
    assert caught.value.orig.diag.constraint_name == "fk_account_sessions_user_id_user_profiles"


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_session_hash_must_be_32_bytes(
    app_connection: Connection,
    cipher: AccountTokenCipher,
    size: int,
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_account_session(
            app_connection,
            cipher,
            token_hash=token_bytes(size),
        )

    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == "ck_account_sessions_token_hash_length"


@pytest.mark.parametrize(
    ("column", "constraint"),
    [
        (
            "access_token_ciphertext",
            "ck_account_sessions_access_ciphertext_size",
        ),
        (
            "refresh_token_ciphertext",
            "ck_account_sessions_refresh_ciphertext_size",
        ),
    ],
)
@pytest.mark.parametrize("size", [0, 12289])
def test_invalid_ciphertext_sizes_are_rejected(
    app_connection: Connection,
    cipher: AccountTokenCipher,
    column: str,
    constraint: str,
    size: int,
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_account_session(
            app_connection,
            cipher,
            **{column: b"x" * size},
        )

    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == constraint


@pytest.mark.parametrize(
    "column",
    [
        "user_id",
        "token_hash",
        "provider_session_id",
        "access_token_ciphertext",
        "refresh_token_ciphertext",
        "access_token_expires_at",
        "created_at",
        "last_seen_at",
        "idle_expires_at",
        "absolute_expires_at",
    ],
)
def test_required_session_fields_cannot_be_null(
    app_connection: Connection,
    cipher: AccountTokenCipher,
    column: str,
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_account_session(
            app_connection,
            cipher,
            **{column: None},
        )

    assert isinstance(caught.value.orig, NotNullViolation)
    assert caught.value.orig.diag.column_name == column


@pytest.mark.parametrize(
    ("last_seen_seconds", "idle_seconds", "absolute_seconds"),
    [
        pytest.param(-1, 3600, 7200, id="activity-before-creation"),
        pytest.param(0, 0, 7200, id="idle-expiry-not-after-activity"),
        pytest.param(0, 7201, 7200, id="idle-expiry-exceeds-absolute"),
        pytest.param(0, 3600, 0, id="absolute-expiry-not-after-creation"),
    ],
)
def test_inconsistent_session_timestamps_are_rejected(
    app_connection: Connection,
    cipher: AccountTokenCipher,
    last_seen_seconds: int,
    idle_seconds: int,
    absolute_seconds: int,
) -> None:
    created_at = datetime.now(UTC)

    with pytest.raises(IntegrityError) as caught:
        insert_account_session(
            app_connection,
            cipher,
            created_at=created_at,
            last_seen_at=created_at + timedelta(seconds=last_seen_seconds),
            idle_expires_at=created_at + timedelta(seconds=idle_seconds),
            absolute_expires_at=created_at + timedelta(seconds=absolute_seconds),
        )

    assert isinstance(caught.value.orig, CheckViolation)


@pytest.mark.parametrize(
    "column",
    [
        "id",
        "user_id",
        "token_hash",
        "provider_session_id",
        "created_at",
        "absolute_expires_at",
    ],
)
def test_application_cannot_rewrite_session_identity_or_absolute_expiry(
    app_connection: Connection,
    cipher: AccountTokenCipher,
    column: str,
) -> None:
    _, session_id = insert_account_session(app_connection, cipher)

    stored = app_connection.execute(
        select(AccountSession).where(AccountSession.id == session_id)
    ).one()

    other_user_id = uuid4()
    if column == "user_id":
        app_connection.execute(insert(UserProfile).values(id=other_user_id))

    replacements: dict[str, object] = {
        "id": uuid4(),
        "user_id": other_user_id,
        "token_hash": token_bytes(32),
        "provider_session_id": uuid4(),
        "created_at": stored.created_at - timedelta(days=1),
        "absolute_expires_at": stored.absolute_expires_at + timedelta(days=1),
    }

    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(
            update(AccountSession)
            .where(AccountSession.id == session_id)
            .values({column: replacements[column]})
        )

    assert isinstance(caught.value.orig, InsufficientPrivilege)


@pytest.mark.parametrize("privilege", ["TRUNCATE", "REFERENCES", "TRIGGER"])
def test_application_has_no_extra_session_table_privileges(
    app_connection: Connection,
    privilege: str,
) -> None:
    allowed = app_connection.scalar(
        text("SELECT has_table_privilege(current_user, 'app.account_sessions', :privilege)"),
        {"privilege": privilege},
    )

    assert allowed is False


@pytest.mark.parametrize("same_account", [True, False])
def test_duplicate_provider_session_preserves_original(
    app_connection: Connection,
    cipher: AccountTokenCipher,
    same_account: bool,
) -> None:
    provider_session_id = uuid4()
    user_id, session_id = insert_account_session(
        app_connection,
        cipher,
        provider_session_id=provider_session_id,
    )
    statement = select(AccountSession).where(AccountSession.id == session_id)
    original = app_connection.execute(statement).one()

    duplicate_user_id = user_id
    if not same_account:
        duplicate_user_id = uuid4()
        app_connection.execute(insert(UserProfile).values(id=duplicate_user_id))

    duplicate = dict(original._mapping)
    duplicate.update(
        id=uuid4(),
        user_id=duplicate_user_id,
        token_hash=token_bytes(32),
    )

    with pytest.raises(IntegrityError) as caught:
        with app_connection.begin_nested():
            app_connection.execute(insert(AccountSession).values(**duplicate))

    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == ("uq_account_sessions_provider_session_id")
    assert app_connection.execute(statement).one() == original
    assert app_connection.scalars(
        select(AccountSession.id).where(AccountSession.provider_session_id == provider_session_id)
    ).all() == [session_id]


def test_same_account_can_have_distinct_provider_sessions(
    app_connection: Connection,
    cipher: AccountTokenCipher,
) -> None:
    first_provider_id = uuid4()
    user_id, first_session_id = insert_account_session(
        app_connection,
        cipher,
        provider_session_id=first_provider_id,
    )
    original = app_connection.execute(
        select(AccountSession).where(AccountSession.id == first_session_id)
    ).one()

    second_session_id = uuid4()
    second_provider_id = uuid4()
    second = dict(original._mapping)
    second.update(
        id=second_session_id,
        provider_session_id=second_provider_id,
        token_hash=token_bytes(32),
    )
    app_connection.execute(insert(AccountSession).values(**second))

    assert set(
        app_connection.scalars(
            select(AccountSession.id).where(AccountSession.user_id == user_id)
        ).all()
    ) == {first_session_id, second_session_id}

    assert set(
        app_connection.scalars(
            select(AccountSession.provider_session_id).where(AccountSession.user_id == user_id)
        ).all()
    ) == {first_provider_id, second_provider_id}
