"""Idempotent NHTSA recall ingestion against guarded local PostgreSQL."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.models import RecallApplicability, RecallCampaign
from app.nhtsa_recall_import import ImportTargetError, apply_in_transaction
from app.nhtsa_recall_ingestion import IngestionReport, apply_recall_batch
from app.nhtsa_recalls import RecallBatch, fingerprint, merge_model_years, parse_model_year_response

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nhtsa"
FIRST_RUN = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
LATER_RUN = FIRST_RUN + timedelta(days=7)


def recorded_batch() -> RecallBatch:
    return merge_model_years(
        [2018, 2019, 2020, 2021],
        {
            2018: parse_model_year_response(
                200, (FIXTURES / "recalls_mazda6_2018.json").read_bytes(), 2018
            ),
            2019: parse_model_year_response(
                200, (FIXTURES / "recalls_mazda6_2019.json").read_bytes(), 2019
            ),
            2020: [],
            2021: [],
        },
    )


def campaign_times(connection: Connection, number: str) -> tuple[datetime, datetime, datetime]:
    row = connection.execute(
        select(
            RecallCampaign.first_seen_at,
            RecallCampaign.content_updated_at,
            RecallCampaign.last_seen_at,
        ).where(RecallCampaign.campaign_number == number)
    ).one()
    return row[0], row[1], row[2]


def test_first_run_stores_campaigns_and_model_years(owner_connection: Connection) -> None:
    report = apply_recall_batch(owner_connection, recorded_batch(), seen_at=FIRST_RUN)
    assert (report.added, report.changed, report.unchanged) == (2, 0, 0)
    assert report.listings_added == 3
    assert report.not_seen == ()

    # The website's role can read what ingestion wrote.
    owner_connection.execute(text("SET LOCAL ROLE askm6_app"))
    listings = owner_connection.execute(
        select(RecallCampaign.campaign_number, RecallApplicability.model_year)
        .join(RecallApplicability)
        .order_by(RecallCampaign.campaign_number, RecallApplicability.model_year)
    ).all()
    assert [tuple(row) for row in listings] == [
        ("19V497000", 2018),
        ("19V497000", 2019),
        ("21V875000", 2018),
    ]
    assert campaign_times(owner_connection, "19V497000") == (FIRST_RUN,) * 3


def test_second_identical_run_changes_nothing_but_last_seen(
    owner_connection: Connection,
) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=FIRST_RUN)
    report = apply_recall_batch(owner_connection, recorded_batch(), seen_at=LATER_RUN)

    assert (report.added, report.changed, report.unchanged) == (0, 0, 2)
    assert report.listings_added == 0
    assert campaign_times(owner_connection, "19V497000") == (FIRST_RUN, FIRST_RUN, LATER_RUN)
    assert len(owner_connection.scalars(select(RecallCampaign.id)).all()) == 2


def test_edited_upstream_text_updates_content_and_its_timestamp(
    owner_connection: Connection,
) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=FIRST_RUN)
    batch = recorded_batch()
    original = batch.campaigns["19V497000"]
    edited = replace(original, remedy="Dealers will reprogram the PCM software, free of charge.")
    edited = replace(edited, record_sha256=fingerprint(edited))
    batch.campaigns["19V497000"] = edited

    report = apply_recall_batch(owner_connection, batch, seen_at=LATER_RUN)
    assert (report.added, report.changed, report.unchanged) == (0, 1, 1)
    assert campaign_times(owner_connection, "19V497000") == (FIRST_RUN, LATER_RUN, LATER_RUN)
    stored = owner_connection.execute(
        select(RecallCampaign.remedy, RecallCampaign.record_sha256).where(
            RecallCampaign.campaign_number == "19V497000"
        )
    ).one()
    assert tuple(stored) == (edited.remedy, edited.record_sha256)


def test_campaign_missing_upstream_is_kept_and_reported(owner_connection: Connection) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=FIRST_RUN)
    batch = recorded_batch()
    del batch.campaigns["21V875000"]
    del batch.listings["21V875000"]

    report = apply_recall_batch(owner_connection, batch, seen_at=LATER_RUN)
    assert report.not_seen == ("21V875000",)
    assert campaign_times(owner_connection, "21V875000") == (FIRST_RUN,) * 3


def test_years_outside_the_run_are_not_reported_missing(owner_connection: Connection) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=FIRST_RUN)
    only_2021 = merge_model_years([2021], {2021: []})
    report = apply_recall_batch(owner_connection, only_2021, seen_at=LATER_RUN)
    assert report.not_seen == ()


def test_failure_mid_batch_leaves_no_partial_data(owner_connection: Connection) -> None:
    batch = recorded_batch()
    # Bypass validation to simulate a record the database must refuse.
    batch.campaigns["21V875000"] = replace(batch.campaigns["21V875000"], summary="Bad\nline")

    savepoint = owner_connection.begin_nested()
    with pytest.raises(IntegrityError):
        apply_recall_batch(owner_connection, batch, seen_at=FIRST_RUN)
    savepoint.rollback()
    assert owner_connection.scalar(select(RecallCampaign.id).limit(1)) is None


def test_seen_time_must_carry_a_timezone(owner_connection: Connection) -> None:
    with pytest.raises(ValueError, match="timezone"):
        apply_recall_batch(owner_connection, recorded_batch(), seen_at=datetime(2026, 10, 29))


def run_dry_import(
    integration_engine: Engine, *, role: str | None, database: str = "askm6_test"
) -> IngestionReport:
    """Drive the command's transaction path; never commits to the test database."""

    async def run() -> IngestionReport:
        engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
            hide_parameters=True,
        )
        try:
            async with engine.connect() as connection:
                if role is not None:
                    await connection.execute(text(f"SET ROLE {role}"))
                    await connection.commit()
                return await apply_in_transaction(
                    connection, recorded_batch(), database=database, write=False
                )
        finally:
            await engine.dispose()

    return asyncio.run(run(), loop_factory=asyncio.SelectorEventLoop)


def stored_campaigns(integration_engine: Engine) -> int:
    with integration_engine.connect() as connection:
        return connection.scalar(select(func.count()).select_from(RecallCampaign)) or 0


def test_dry_run_reports_changes_but_saves_nothing(integration_engine: Engine) -> None:
    report = run_dry_import(integration_engine, role="askm6_migrator")
    assert (report.added, report.listings_added) == (2, 3)
    assert stored_campaigns(integration_engine) == 0


@pytest.mark.parametrize(
    ("role", "database"),
    [(None, "askm6_test"), ("askm6_migrator", "mazda6")],
    ids=["admin-identity", "other-database"],
)
def test_unexpected_identity_stops_before_writing(
    integration_engine: Engine, role: str | None, database: str
) -> None:
    with pytest.raises(ImportTargetError):
        run_dry_import(integration_engine, role=role, database=database)
    assert stored_campaigns(integration_engine) == 0
