"""Offline schema and least-data contract for Terms acceptance records."""

from sqlalchemy import create_mock_engine
from sqlalchemy.schema import CreateTable

from app.models import Base


def reject_execution(*args: object, **kwargs: object) -> None:
    raise AssertionError("Offline schema tests must not connect to a database.")


DIALECT = create_mock_engine("postgresql+psycopg://", reject_execution).dialect
TABLE = Base.metadata.tables["app.account_terms_acceptances"]


def test_acceptance_stores_only_identity_version_and_server_time() -> None:
    table = TABLE
    assert table.fullname == "app.account_terms_acceptances"
    assert set(table.c.keys()) == {"user_id", "terms_version", "accepted_at"}
    assert set(table.primary_key.columns.keys()) == {"user_id", "terms_version"}
    assert all(not column.nullable for column in table.c)


def test_account_deletion_cascades_and_revision_time_preserves_timezone() -> None:
    table = TABLE
    (foreign_key,) = table.foreign_keys
    assert foreign_key.target_fullname == "app.user_profiles.id"
    assert foreign_key.ondelete == "CASCADE"
    ddl = str(CreateTable(table).compile(dialect=DIALECT))
    assert "TIMESTAMP WITH TIME ZONE DEFAULT statement_timestamp() NOT NULL" in ddl
    assert "terms_version VARCHAR(64) NOT NULL" in ddl
    assert "CHECK (terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')" in ddl
