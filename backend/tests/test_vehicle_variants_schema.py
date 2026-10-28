"""Offline schema contract for the shared vehicle-variant catalogue."""

from sqlalchemy import UniqueConstraint, create_mock_engine
from sqlalchemy.schema import CreateTable

from app.models import Base


def reject_execution(*args: object, **kwargs: object) -> None:
    raise AssertionError("Offline schema tests must not connect to a database.")


DIALECT = create_mock_engine("postgresql+psycopg://", reject_execution).dialect
TABLE = Base.metadata.tables["app.vehicle_variants"]


def test_catalogue_columns_and_only_trim_and_epa_id_optional() -> None:
    assert set(TABLE.c.keys()) == {
        "id",
        "model_year",
        "market",
        "engine",
        "aspiration",
        "transmission",
        "drive",
        "trim_level",
        "epa_vehicle_id",
        "source_note",
    }
    assert {column.name for column in TABLE.c if column.nullable} == {
        "trim_level",
        "epa_vehicle_id",
    }
    assert TABLE.c.id.autoincrement is False


def test_configuration_uniqueness_treats_missing_trim_as_equal() -> None:
    (configuration,) = (
        constraint
        for constraint in TABLE.constraints
        if isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_vehicle_variants_configuration"
    )
    assert [column.name for column in configuration.columns] == [
        "model_year",
        "market",
        "engine",
        "aspiration",
        "transmission",
        "drive",
        "trim_level",
    ]
    ddl = str(CreateTable(TABLE).compile(dialect=DIALECT))
    assert "UNIQUE NULLS NOT DISTINCT (model_year, market, engine" in ddl


def test_allowed_values_are_enforced_by_the_database() -> None:
    ddl = str(CreateTable(TABLE).compile(dialect=DIALECT))
    assert "CHECK (model_year BETWEEN 2018 AND 2021)" in ddl
    assert "CHECK (market = 'US')" in ddl
    assert "CHECK (aspiration IN ('naturally_aspirated', 'turbo'))" in ddl
    assert "CHECK (transmission IN ('6AT', '6MT'))" in ddl
    assert "CHECK (drive = 'FWD')" in ddl
    assert (
        "CHECK (transmission <> '6MT' OR "
        "(aspiration = 'naturally_aspirated' AND model_year IN (2018, 2019)))"
    ) in ddl
