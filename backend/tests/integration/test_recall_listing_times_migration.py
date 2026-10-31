"""Transactional upgrade probe for per-listing dates; never commits DDL or data."""

from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection, Engine

from app.models import RecallApplicability, RecallCampaign, RecallModelYearCheck
from app.nhtsa_recall_ingestion import apply_recall_batch
from app.nhtsa_recalls import RecallBatch, merge_model_years, parse_model_year_response
from app.recall_evidence import find_recall_evidence, listing_statement

pytestmark = pytest.mark.integration

REVISION = "c7e2d5a8f1b3"
FIXTURES = Path(__file__).parents[1] / "fixtures" / "nhtsa"
FIRST = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
LATER = FIRST + timedelta(days=14)
REIMPORT = LATER + timedelta(days=7)
NA_2018_MANUAL, NA_2019_AUTO = 1, 5


class Migration(Protocol):
    def upgrade(self) -> None: ...
    def downgrade(self) -> None: ...


def migration() -> Migration:
    backend = Path(__file__).resolve().parents[2]
    scripts = ScriptDirectory.from_config(Config(str(backend / "alembic.ini")))
    revision = scripts.get_revision(REVISION)
    assert revision is not None
    return cast(Migration, revision.module)


@pytest.fixture
def before_listing_times(integration_engine: Engine) -> Iterator[Connection]:
    """The schema just before this migration, inside a transaction that is rolled back."""
    with integration_engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET LOCAL ROLE askm6_migrator"))
            connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
            connection.execute(text("SET LOCAL statement_timeout = '5s'"))
            connection.execute(text("SET LOCAL lock_timeout = '2s'"))
            assert tuple(
                connection.execute(text("SELECT current_database(), current_user")).one()
            ) == ("askm6_test", "askm6_migrator")
            if connection.scalar(select(RecallCampaign.id).limit(1)) is not None:
                pytest.skip("Existing recall data prevents the isolated migration probe.")
            with Operations.context(MigrationContext.configure(connection)):
                migration().downgrade()
            yield connection
        finally:
            transaction.rollback()


def recorded_batch() -> RecallBatch:
    return merge_model_years(
        [2018, 2019],
        {
            year: parse_model_year_response(
                200, (FIXTURES / f"recalls_mazda6_{year}.json").read_bytes(), year
            )
            for year in (2018, 2019)
        },
    )


def listing_dates(connection: Connection) -> list[tuple[int, object, object]]:
    rows = connection.execute(
        select(
            RecallApplicability.model_year,
            RecallApplicability.first_listed_at,
            RecallApplicability.last_listed_at,
        ).order_by(RecallApplicability.model_year)
    ).all()
    return [(row[0], row[1], row[2]) for row in rows]


def test_upgrade_leaves_partially_dropped_listings_unconfirmed(
    before_listing_times: Connection,
) -> None:
    connection = before_listing_times
    # Old-format state: listed for 2018 and 2019 on FIRST. A newer import (LATER)
    # confirmed 2018, which refreshed the whole campaign, and listed nothing for 2019.
    campaign_id = connection.scalar(
        insert(RecallCampaign)
        .values(
            source_id=1,
            campaign_number="19V497000",
            report_received_on=date(2019, 6, 27),
            manufacturer="Synthetic",
            component="ENGINE",
            summary="Synthetic summary.",
            consequence="Synthetic consequence.",
            remedy="Synthetic remedy.",
            notes=None,
            park_it=False,
            park_outside=False,
            over_the_air_update=False,
            record_sha256=bytes(32),
            first_seen_at=FIRST,
            content_updated_at=FIRST,
            last_seen_at=LATER,
        )
        .returning(RecallCampaign.id)
    )
    for year in (2018, 2019):
        connection.execute(
            text(
                "INSERT INTO app.recall_applicability (campaign_id, make, model, model_year) "
                "VALUES (:campaign_id, 'MAZDA', 'MAZDA6', :year)"
            ),
            {"campaign_id": campaign_id, "year": year},
        )
    for year, listed in ((2018, 1), (2019, 0)):
        connection.execute(
            insert(RecallModelYearCheck).values(
                source_id=1,
                make="MAZDA",
                model="MAZDA6",
                model_year=year,
                checked_at=LATER,
                campaigns_listed=listed,
            )
        )

    with Operations.context(MigrationContext.configure(connection)):
        migration().upgrade()

    # No date is inferred from campaign-level times.
    assert listing_dates(connection) == [(2018, None, None), (2019, None, None)]

    connection.execute(text("SET LOCAL ROLE askm6_app"))
    dropped = find_recall_evidence(connection, NA_2019_AUTO)
    assert (dropped.status, dropped.campaigns) == ("none_listed", ())
    assert [(f.campaign_number, f.last_listed_at) for f in dropped.previously_listed] == [
        ("19V497000", None)
    ]
    assert "19V497000 (last-listed date unknown)" in listing_statement(dropped)

    # The check says NHTSA listed one campaign, but no listing is confirmed yet.
    still_listed = find_recall_evidence(connection, NA_2018_MANUAL)
    assert (still_listed.status, still_listed.campaigns) == ("unverified", ())
    assert "must be re-imported" in listing_statement(still_listed)


def test_reimport_after_upgrade_confirms_only_what_nhtsa_lists(
    before_listing_times: Connection,
) -> None:
    connection = before_listing_times
    with Operations.context(MigrationContext.configure(connection)):
        migration().upgrade()

    apply_recall_batch(connection, recorded_batch(), seen_at=LATER)
    # Simulate listings recorded before per-year dates existed.
    connection.execute(
        text("UPDATE app.recall_applicability SET first_listed_at = NULL, last_listed_at = NULL")
    )
    newer = recorded_batch()
    newer.listings["19V497000"] = frozenset({2018})  # dropped from 2019
    apply_recall_batch(connection, newer, seen_at=REIMPORT)

    connection.execute(text("SET LOCAL ROLE askm6_app"))
    reduced_2019 = find_recall_evidence(connection, NA_2019_AUTO)
    assert (reduced_2019.status, reduced_2019.campaigns) == ("none_listed", ())
    assert [f.last_listed_at for f in reduced_2019.previously_listed] == [None]
    confirmed_2018 = find_recall_evidence(connection, NA_2018_MANUAL)
    assert confirmed_2018.status == "campaigns_listed"
    assert {f.campaign_number for f in confirmed_2018.campaigns} == {"19V497000", "21V875000"}
    assert all(f.last_listed_at == REIMPORT for f in confirmed_2018.campaigns)
