"""Offline PostgreSQL schema contract for pending Google OAuth attempts."""

import pytest
from sqlalchemy import create_mock_engine
from sqlalchemy.schema import CreateIndex, CreateTable

from app.models import Base, OAuthLoginAttempt

TABLE = Base.metadata.tables["app.oauth_login_attempts"]


def reject_execution(*args: object, **kwargs: object) -> None:
    raise AssertionError("Offline schema tests must not execute database statements.")


POSTGRESQL_DIALECT = create_mock_engine("postgresql+psycopg://", reject_execution).dialect


@pytest.fixture
def ddl() -> str:
    """Compile PostgreSQL DDL without connecting to or changing a database."""
    return str(CreateTable(TABLE).compile(dialect=POSTGRESQL_DIALECT))


def test_pending_attempt_stores_no_plaintext_credentials_or_unverified_owner() -> None:
    table = TABLE

    assert table.fullname == "app.oauth_login_attempts"
    assert table is OAuthLoginAttempt.__table__
    assert set(table.columns.keys()) == {
        "id",
        "browser_token_hash",
        "pkce_verifier_ciphertext",
        "provider",
        "purpose",
        "created_at",
        "expires_at",
    }
    assert not table.foreign_keys


def test_all_attempt_fields_are_required() -> None:
    assert all(column.nullable is False for column in TABLE.columns)


def test_attempt_has_a_uuid_primary_key(ddl: str) -> None:
    assert "id UUID NOT NULL" in ddl
    assert "PRIMARY KEY (id)" in ddl
    default = TABLE.c.id.default
    assert default is not None and default.is_callable


@pytest.mark.parametrize("column", ["browser_token_hash", "pkce_verifier_ciphertext"])
def test_sensitive_fields_use_required_postgresql_binary_storage(ddl: str, column: str) -> None:
    assert f"{column} BYTEA NOT NULL" in ddl


def test_browser_binding_is_unique(ddl: str) -> None:
    assert "UNIQUE (browser_token_hash)" in ddl


@pytest.mark.parametrize(
    "expression",
    [
        "octet_length(browser_token_hash) = 32",
        "octet_length(pkce_verifier_ciphertext) BETWEEN 1 AND 1024",
        "provider = 'google'",
        "purpose = 'sign_in'",
        "expires_at > created_at",
    ],
    ids=["hash-size", "ciphertext-size", "google-only", "sign-in-only", "positive-lifetime"],
)
def test_postgresql_ddl_contains_security_constraints(ddl: str, expression: str) -> None:
    assert f"CHECK ({expression})" in ddl


@pytest.mark.parametrize("column", ["created_at", "expires_at"])
def test_attempt_timestamps_preserve_timezone_information(ddl: str, column: str) -> None:
    assert f"{column} TIMESTAMP WITH TIME ZONE" in ddl


def test_expiry_has_an_index_for_pending_attempt_cleanup() -> None:
    table = TABLE
    expiry_indexes = [
        index for index in table.indexes if list(index.columns.keys()) == ["expires_at"]
    ]
    assert len(expiry_indexes) == 1
    index_ddl = str(CreateIndex(expiry_indexes[0]).compile(dialect=POSTGRESQL_DIALECT))
    assert "ON app.oauth_login_attempts (expires_at)" in index_ddl


def test_creation_uses_database_time_and_expiry_requires_an_explicit_deadline(ddl: str) -> None:
    table = TABLE

    assert "created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL" in ddl
    assert table.c.expires_at.default is None
    assert table.c.expires_at.server_default is None
