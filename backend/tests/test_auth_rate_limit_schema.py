"""Offline PostgreSQL schema contract for rolling authentication limits."""

import pytest
from sqlalchemy import CheckConstraint, DateTime, create_mock_engine
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.schema import CreateIndex, CreateTable

from app.models import AuthRateLimit, Base

TABLE = Base.metadata.tables["app.auth_rate_limits"]


def reject_execution(*args: object, **kwargs: object) -> None:
    raise AssertionError("Offline schema tests must not execute database statements.")


POSTGRESQL_DIALECT = create_mock_engine("postgresql+psycopg://", reject_execution).dialect


@pytest.fixture
def ddl() -> str:
    """Compile the table definition without contacting PostgreSQL."""
    return str(CreateTable(TABLE).compile(dialect=POSTGRESQL_DIALECT))


def test_storage_contains_only_operation_fingerprint_and_window_state() -> None:
    assert TABLE is AuthRateLimit.__table__
    assert TABLE.fullname == "app.auth_rate_limits"
    assert set(TABLE.columns.keys()) == {
        "purpose",
        "key_hash",
        "request_times",
        "expires_at",
    }
    assert not TABLE.foreign_keys


def test_composite_key_is_unique_per_operation_and_fingerprint(ddl: str) -> None:
    assert list(TABLE.primary_key.columns.keys()) == ["purpose", "key_hash"]
    assert "PRIMARY KEY (purpose, key_hash)" in ddl


@pytest.mark.parametrize("column", ["purpose", "key_hash", "request_times", "expires_at"])
def test_all_state_fields_are_required(column: str) -> None:
    assert TABLE.c[column].nullable is False


def test_operation_is_bounded_text_and_fingerprint_is_binary(ddl: str) -> None:
    assert "purpose VARCHAR(32) NOT NULL" in ddl
    assert "key_hash BYTEA NOT NULL" in ddl


def test_individual_attempts_use_a_timezone_aware_timestamp_array(ddl: str) -> None:
    assert "request_times TIMESTAMP WITH TIME ZONE[] NOT NULL" in ddl
    array_type = TABLE.c.request_times.type
    assert isinstance(array_type, ARRAY)
    assert array_type.dimensions == 1
    assert isinstance(array_type.item_type, DateTime)
    assert array_type.item_type.timezone is True


def test_cleanup_deadline_preserves_timezone_information(ddl: str) -> None:
    assert "expires_at TIMESTAMP WITH TIME ZONE NOT NULL" in ddl


@pytest.mark.parametrize(
    ("name", "expression"),
    [
        ("purpose_password_recovery_only", "purpose = 'password_recovery'"),
        ("key_hash_length", "octet_length(key_hash) = 32"),
        ("request_times_size", "cardinality(request_times) <= 1000"),
        (
            "request_times_shape",
            "cardinality(request_times) = 0 OR "
            "(array_ndims(request_times) = 1 AND array_lower(request_times, 1) = 1)",
        ),
        ("request_times_no_nulls", "array_position(request_times, NULL) IS NULL"),
    ],
    ids=["recovery-only", "fingerprint-size", "bounded-history", "array-shape", "no-nulls"],
)
def test_database_constraints_compile_with_stable_names(
    ddl: str, name: str, expression: str
) -> None:
    assert f"CONSTRAINT ck_auth_rate_limits_{name} CHECK ({expression})" in ddl


def test_all_safety_constraints_are_attached_to_the_table() -> None:
    constraints = [item for item in TABLE.constraints if isinstance(item, CheckConstraint)]
    assert len(constraints) == 5


@pytest.mark.parametrize("column", ["purpose", "key_hash", "request_times", "expires_at"])
def test_service_must_supply_explicit_state_without_shared_mutable_defaults(column: str) -> None:
    assert TABLE.c[column].default is None
    assert TABLE.c[column].server_default is None


def test_cleanup_deadline_has_a_nonunique_index() -> None:
    indexes = list(TABLE.indexes)
    assert len(indexes) == 1
    index = indexes[0]
    assert list(index.columns.keys()) == ["expires_at"]
    assert not index.unique
    index_ddl = str(CreateIndex(index).compile(dialect=POSTGRESQL_DIALECT))
    assert index_ddl == (
        "CREATE INDEX ix_auth_rate_limits_expires_at ON app.auth_rate_limits (expires_at)"
    )
