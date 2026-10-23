"""OAuth attempt constraints and grants on guarded local PostgreSQL."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_bytes, token_urlsafe
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from psycopg.errors import CheckViolation, InsufficientPrivilege, NotNullViolation, UniqueViolation
from pydantic import SecretStr
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.account_token_encryption import AccountTokenCipher
from app.models import OAuthLoginAttempt

pytestmark = pytest.mark.integration


def insert_attempt(connection: Connection, **overrides: object) -> UUID:
    created_at = datetime.now(UTC)
    values: dict[str, object] = {
        "browser_token_hash": token_bytes(32),
        "pkce_verifier_ciphertext": b"synthetic-ciphertext",
        "created_at": created_at,
        "expires_at": created_at + timedelta(minutes=10),
    }
    values.update(overrides)
    attempt_id = connection.scalar(
        insert(OAuthLoginAttempt).values(**values).returning(OAuthLoginAttempt.id)
    )
    assert isinstance(attempt_id, UUID)
    return attempt_id


def test_application_can_store_read_and_delete_encrypted_attempt(
    app_connection: Connection,
) -> None:
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    verifier = SecretStr(token_urlsafe(32))
    browser_token = token_urlsafe(32)
    browser_hash = sha256(browser_token.encode("ascii")).digest()
    ciphertext = cipher.encrypt(verifier)
    expires_at = datetime.now(UTC) + timedelta(minutes=10)
    # Omit created_at to exercise the database's timestamp default.
    attempt_id = app_connection.scalar(
        insert(OAuthLoginAttempt)
        .values(
            browser_token_hash=browser_hash,
            pkce_verifier_ciphertext=ciphertext,
            expires_at=expires_at,
        )
        .returning(OAuthLoginAttempt.id)
    )
    assert isinstance(attempt_id, UUID)
    row = app_connection.execute(
        select(OAuthLoginAttempt).where(OAuthLoginAttempt.id == attempt_id)
    ).one()

    assert row.browser_token_hash == browser_hash
    assert row.pkce_verifier_ciphertext == ciphertext
    assert browser_token.encode("ascii") != row.browser_token_hash
    assert verifier.get_secret_value().encode("ascii") not in row.pkce_verifier_ciphertext
    assert cipher.decrypt(row.pkce_verifier_ciphertext) == verifier
    assert (row.provider, row.purpose) == ("google", "sign_in")
    assert isinstance(row.created_at, datetime)
    assert row.created_at.utcoffset() == timedelta(0)
    assert row.created_at < row.expires_at == expires_at

    assert (
        app_connection.scalar(
            delete(OAuthLoginAttempt)
            .where(OAuthLoginAttempt.id == attempt_id)
            .returning(OAuthLoginAttempt.id)
        )
        == attempt_id
    )
    assert (
        app_connection.scalar(
            select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == attempt_id)
        )
        is None
    )


def test_duplicate_browser_hash_preserves_original(app_connection: Connection) -> None:
    browser_hash = token_bytes(32)
    attempt_id = insert_attempt(app_connection, browser_token_hash=browser_hash)
    statement = select(OAuthLoginAttempt).where(OAuthLoginAttempt.id == attempt_id)
    original = app_connection.execute(statement).one()

    with pytest.raises(IntegrityError) as caught:
        with app_connection.begin_nested():
            insert_attempt(app_connection, browser_token_hash=browser_hash)

    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "uq_oauth_login_attempts_browser_token_hash"
    assert app_connection.execute(statement).one() == original


@pytest.mark.parametrize(
    "column",
    [
        "id",
        "browser_token_hash",
        "pkce_verifier_ciphertext",
        "provider",
        "purpose",
        "created_at",
        "expires_at",
    ],
)
def test_required_columns_reject_null(app_connection: Connection, column: str) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_attempt(app_connection, **{column: None})

    assert isinstance(caught.value.orig, NotNullViolation)
    assert caught.value.orig.diag.column_name == column


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"browser_token_hash": b"h" * 31}, "browser_token_hash_length"),
        ({"browser_token_hash": b"h" * 33}, "browser_token_hash_length"),
        ({"pkce_verifier_ciphertext": b""}, "pkce_ciphertext_size"),
        ({"pkce_verifier_ciphertext": b"c" * 1025}, "pkce_ciphertext_size"),
        ({"provider": "github"}, "provider_google_only"),
        ({"purpose": "recovery"}, "purpose_sign_in_only"),
    ],
)
def test_invalid_attempt_fields_are_rejected(
    app_connection: Connection,
    overrides: dict[str, object],
    constraint: str,
) -> None:
    with pytest.raises(IntegrityError) as caught:
        insert_attempt(app_connection, **overrides)

    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == f"ck_oauth_login_attempts_{constraint}"


@pytest.mark.parametrize("size", [1, 1024])
def test_ciphertext_size_boundaries_are_accepted(app_connection: Connection, size: int) -> None:
    # The database bounds bytes; cryptographic validity belongs to the service.
    ciphertext = b"c" * size
    attempt_id = insert_attempt(app_connection, pkce_verifier_ciphertext=ciphertext)

    assert (
        app_connection.scalar(
            select(OAuthLoginAttempt.pkce_verifier_ciphertext).where(
                OAuthLoginAttempt.id == attempt_id
            )
        )
        == ciphertext
    )


@pytest.mark.parametrize("offset", [timedelta(0), timedelta(microseconds=-1)])
def test_expiry_must_follow_creation(app_connection: Connection, offset: timedelta) -> None:
    created_at = datetime.now(UTC)
    with pytest.raises(IntegrityError) as caught:
        insert_attempt(app_connection, created_at=created_at, expires_at=created_at + offset)

    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == "ck_oauth_login_attempts_expiry_after_creation"


@pytest.mark.parametrize("column", ["expires_at", "pkce_verifier_ciphertext"])
def test_application_cannot_modify_attempt(app_connection: Connection, column: str) -> None:
    attempt_id = insert_attempt(app_connection)
    replacements: dict[str, object] = {
        "expires_at": datetime.now(UTC) + timedelta(minutes=20),
        "pkce_verifier_ciphertext": b"replacement-ciphertext",
    }
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(
            update(OAuthLoginAttempt)
            .where(OAuthLoginAttempt.id == attempt_id)
            .values(**{column: replacements[column]})
        )

    assert isinstance(caught.value.orig, InsufficientPrivilege)


@pytest.mark.parametrize("privilege", ["TRUNCATE", "REFERENCES", "TRIGGER"])
def test_application_has_no_extra_table_privileges(
    app_connection: Connection, privilege: str
) -> None:
    allowed = app_connection.scalar(
        text("SELECT has_table_privilege(current_user, 'app.oauth_login_attempts', :privilege)"),
        {"privilege": privilege},
    )
    assert allowed is False


def test_application_cannot_truncate_attempts(app_connection: Connection) -> None:
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(text("TRUNCATE TABLE app.oauth_login_attempts"))

    assert isinstance(caught.value.orig, InsufficientPrivilege)
