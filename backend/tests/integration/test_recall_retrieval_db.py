"""Recall retrieval as the website role, against guarded local PostgreSQL."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import insert, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import ProgrammingError

from app.models import RecallModelYearCheck
from app.nhtsa_recall_ingestion import apply_recall_batch
from app.nhtsa_recalls import (
    RecallBatch,
    fingerprint,
    merge_model_years,
    parse_model_year_response,
)
from app.recall_evidence import UnknownVehicleVariant, find_recall_evidence, listing_statement

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nhtsa"
CHECKED = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
LATER = CHECKED + timedelta(days=7)
# Catalogue IDs from the vehicle_variants seed.
NA_2018_MANUAL, NA_2019_AUTO, NA_2020_AUTO, FAMILY_2021 = 1, 5, 7, 9


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


def as_website(connection: Connection) -> Connection:
    connection.execute(text("SET LOCAL ROLE askm6_app"))
    return connection


def test_2018_lists_both_campaigns_newest_first(owner_connection: Connection) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    evidence = find_recall_evidence(as_website(owner_connection), NA_2018_MANUAL)

    assert evidence.status == "campaigns_listed"
    assert [fact.campaign_number for fact in evidence.campaigns] == ["21V875000", "19V497000"]
    assert evidence.campaigns[1].nhtsa_url == "https://www.nhtsa.gov/recalls?nhtsaId=19V497000"
    assert evidence.checked_at == CHECKED
    assert evidence.source_publisher == "US National Highway Traffic Safety Administration"
    assert evidence.requires_urgent_safety_message is False


def test_2019_lists_only_its_own_campaign(owner_connection: Connection) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    evidence = find_recall_evidence(as_website(owner_connection), NA_2019_AUTO)
    assert [fact.campaign_number for fact in evidence.campaigns] == ["19V497000"]


def test_family_car_gets_a_dated_empty_listing(owner_connection: Connection) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    evidence = find_recall_evidence(as_website(owner_connection), FAMILY_2021)

    assert (evidence.model_year, evidence.status, evidence.campaigns) == (2021, "none_listed", ())
    assert evidence.checked_at == CHECKED
    statement = listing_statement(evidence)
    assert "as of 2026-10-29" in statement
    assert "not proof that no recalls apply" in statement


def test_before_any_import_the_year_is_not_checked(owner_connection: Connection) -> None:
    evidence = find_recall_evidence(as_website(owner_connection), FAMILY_2021)
    assert (evidence.status, evidence.checked_at) == ("not_checked", None)


def test_campaigns_never_leak_between_model_years(owner_connection: Connection) -> None:
    batch = recorded_batch()
    template = batch.campaigns["19V497000"]
    synthetic = replace(template, campaign_number="99V000021", summary="Synthetic 2021 only.")
    batch.campaigns["99V000021"] = replace(synthetic, record_sha256=fingerprint(synthetic))
    batch.listings["99V000021"] = frozenset({2021})
    apply_recall_batch(owner_connection, batch, seen_at=CHECKED)
    website = as_website(owner_connection)

    family = find_recall_evidence(website, FAMILY_2021)
    assert [fact.campaign_number for fact in family.campaigns] == ["99V000021"]
    for variant_id in (NA_2018_MANUAL, NA_2019_AUTO, NA_2020_AUTO):
        numbers = [
            fact.campaign_number for fact in find_recall_evidence(website, variant_id).campaigns
        ]
        assert "99V000021" not in numbers


def test_park_outside_campaign_raises_the_urgent_flag(owner_connection: Connection) -> None:
    batch = recorded_batch()
    template = batch.campaigns["19V497000"]
    fire = replace(template, campaign_number="99V000020", park_outside=True)
    batch.campaigns["99V000020"] = replace(fire, record_sha256=fingerprint(fire))
    batch.listings["99V000020"] = frozenset({2020})
    apply_recall_batch(owner_connection, batch, seen_at=CHECKED)
    website = as_website(owner_connection)

    assert find_recall_evidence(website, NA_2020_AUTO).requires_urgent_safety_message is True
    assert find_recall_evidence(website, FAMILY_2021).requires_urgent_safety_message is False


def test_unknown_variant_is_refused(owner_connection: Connection) -> None:
    with pytest.raises(UnknownVehicleVariant):
        find_recall_evidence(as_website(owner_connection), 999)


def test_website_cannot_write_check_records(app_connection: Connection) -> None:
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(
            insert(RecallModelYearCheck).values(
                source_id=1,
                make="MAZDA",
                model="MAZDA6",
                model_year=2021,
                checked_at=CHECKED,
                campaigns_listed=0,
            )
        )
    assert isinstance(caught.value.orig, InsufficientPrivilege)


def test_fully_emptied_year_keeps_old_campaign_only_as_previous(
    owner_connection: Connection,
) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    # A newer check of 2019 lists nothing.
    apply_recall_batch(owner_connection, merge_model_years([2019], {2019: []}), seen_at=LATER)
    evidence = find_recall_evidence(as_website(owner_connection), NA_2019_AUTO)

    assert (evidence.status, evidence.campaigns, evidence.checked_at) == (
        "none_listed",
        (),
        LATER,
    )
    assert [(fact.campaign_number, fact.last_listed_at) for fact in evidence.previously_listed] == [
        ("19V497000", CHECKED)
    ]
    statement = listing_statement(evidence)
    assert "NHTSA lists 1 recall" not in statement
    assert "as of 2026-11-05" in statement
    assert "19V497000 (last listed 2026-10-29)" in statement


def test_partially_reduced_year_separates_current_and_previous(
    owner_connection: Connection,
) -> None:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    newer = recorded_batch()
    newer.listings["19V497000"] = frozenset({2019})  # dropped from 2018 only
    apply_recall_batch(owner_connection, newer, seen_at=LATER)
    website = as_website(owner_connection)

    reduced = find_recall_evidence(website, NA_2018_MANUAL)
    assert [fact.campaign_number for fact in reduced.campaigns] == ["21V875000"]
    assert reduced.campaigns[0].last_listed_at == LATER
    assert [fact.campaign_number for fact in reduced.previously_listed] == ["19V497000"]
    assert "NHTSA lists 1 recall campaign for the 2018 Mazda 6" in listing_statement(reduced)

    # The same campaign is still current where NHTSA still lists it.
    still_listed = find_recall_evidence(website, NA_2019_AUTO)
    assert [fact.campaign_number for fact in still_listed.campaigns] == ["19V497000"]
    assert still_listed.previously_listed == ()
