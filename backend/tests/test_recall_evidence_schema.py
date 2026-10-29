"""Offline schema contract for the recall evidence tables."""

from sqlalchemy import create_mock_engine
from sqlalchemy.schema import CreateTable

from app.models import Base


def reject_execution(*args: object, **kwargs: object) -> None:
    raise AssertionError("Offline schema tests must not connect to a database.")


DIALECT = create_mock_engine("postgresql+psycopg://", reject_execution).dialect
SOURCES = Base.metadata.tables["app.evidence_sources"]
CAMPAIGNS = Base.metadata.tables["app.recall_campaigns"]
LISTINGS = Base.metadata.tables["app.recall_applicability"]


def ddl(table: object) -> str:
    return str(CreateTable(table).compile(dialect=DIALECT))  # type: ignore[arg-type]


def test_only_campaign_notes_are_optional() -> None:
    for table in (SOURCES, LISTINGS):
        assert not [column.name for column in table.c if column.nullable]
    assert {column.name for column in CAMPAIGNS.c if column.nullable} == {"notes"}


def test_source_ids_are_fixed_and_campaign_ids_generated() -> None:
    assert SOURCES.c.id.autoincrement is False
    assert "GENERATED ALWAYS AS IDENTITY" in ddl(CAMPAIGNS)


def test_relationships_protect_sources_and_follow_campaigns() -> None:
    (source_fk,) = CAMPAIGNS.c.source_id.foreign_keys
    assert source_fk.target_fullname == "app.evidence_sources.id"
    assert source_fk.ondelete == "RESTRICT"
    (campaign_fk,) = LISTINGS.c.campaign_id.foreign_keys
    assert campaign_fk.target_fullname == "app.recall_campaigns.id"
    assert campaign_fk.ondelete == "CASCADE"


def test_listing_is_keyed_by_campaign_and_nhtsa_model_year() -> None:
    assert [column.name for column in LISTINGS.primary_key.columns] == [
        "campaign_id",
        "make",
        "model",
        "model_year",
    ]
    # Applicability is by model year only, not linked to vehicle configurations.
    assert "vehicle_variant_id" not in LISTINGS.c


def test_database_enforces_evidence_rules() -> None:
    campaigns = ddl(CAMPAIGNS)
    assert "UNIQUE (source_id, campaign_number)" in campaigns
    assert "CHECK (campaign_number ~ '^[0-9]{2}V[0-9]{6}$')" in campaigns
    assert "CHECK (octet_length(record_sha256) = 32)" in campaigns
    assert (
        "CHECK (first_seen_at <= content_updated_at AND content_updated_at <= last_seen_at)"
    ) in campaigns
    assert "CHECK (url ~ '^https://[^[:space:][:cntrl:]]+$')" in ddl(SOURCES)
    listings = ddl(LISTINGS)
    assert "CHECK (model = 'MAZDA6')" in listings
    assert "CHECK (model_year BETWEEN 2018 AND 2021)" in listings
