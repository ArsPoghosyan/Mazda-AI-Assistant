"""Recall evidence tables: seed source, constraints, relationships and grants."""

from datetime import UTC, date, datetime, timedelta

import pytest
from psycopg.errors import (
    CheckViolation,
    ForeignKeyViolation,
    GeneratedAlways,
    InsufficientPrivilege,
    NotNullViolation,
    UniqueViolation,
)
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from app.models import EvidenceSource, RecallApplicability, RecallCampaign

pytestmark = pytest.mark.integration

SEEN = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
CAMPAIGN: dict[str, object] = {
    "source_id": 1,
    "campaign_number": "99V000001",
    "report_received_on": date(2026, 1, 15),
    "manufacturer": "Synthetic Test Manufacturer",
    "component": "ENGINE",
    "summary": "Synthetic integration-test summary.",
    "consequence": "Synthetic consequence.",
    "remedy": "Synthetic remedy.",
    "notes": None,
    "park_it": False,
    "park_outside": False,
    "over_the_air_update": False,
    "record_sha256": bytes(32),
    "first_seen_at": SEEN,
    "content_updated_at": SEEN,
    "last_seen_at": SEEN,
}
LISTING = {"make": "MAZDA", "model": "MAZDA6"}


def add_campaign(connection: Connection, **overrides: object) -> int:
    campaign_id = connection.scalar(
        insert(RecallCampaign).values(**{**CAMPAIGN, **overrides}).returning(RecallCampaign.id)
    )
    assert isinstance(campaign_id, int)
    return campaign_id


def add_listing(connection: Connection, campaign_id: int, model_year: int) -> None:
    connection.execute(
        insert(RecallApplicability).values(
            campaign_id=campaign_id, model_year=model_year, **LISTING
        )
    )


def test_nhtsa_is_the_only_seeded_source(app_connection: Connection) -> None:
    rows = app_connection.execute(
        select(
            EvidenceSource.id,
            EvidenceSource.slug,
            EvidenceSource.url,
            EvidenceSource.terms_url,
            EvidenceSource.terms_checked_on,
        )
    ).all()
    assert [tuple(row) for row in rows] == [
        (
            1,
            "nhtsa_recalls",
            "https://api.nhtsa.gov/recalls/recallsByVehicle",
            "https://www.nhtsa.gov/about-nhtsa/terms-use",
            date(2026, 10, 29),
        )
    ]


def test_recall_tables_start_empty(app_connection: Connection) -> None:
    # Campaigns arrive only through the ingestion command, never the migration.
    assert app_connection.scalar(select(RecallCampaign.id).limit(1)) is None
    assert app_connection.scalar(select(RecallApplicability.campaign_id).limit(1)) is None


@pytest.mark.parametrize(
    "statement",
    [
        insert(EvidenceSource).values(
            id=2,
            slug="other",
            name="Other",
            publisher="Other",
            url="https://example.test",
            terms_url="https://example.test/terms",
            terms_note="Synthetic",
            terms_checked_on=date(2026, 10, 29),
        ),
        update(EvidenceSource).where(EvidenceSource.id == 1).values(name="Changed"),
        delete(EvidenceSource).where(EvidenceSource.id == 1),
        insert(RecallCampaign).values(**CAMPAIGN),
        update(RecallCampaign).values(summary="Changed"),
        delete(RecallCampaign),
        insert(RecallApplicability).values(campaign_id=1, model_year=2021, **LISTING),
        delete(RecallApplicability),
    ],
    ids=[
        "source-insert",
        "source-update",
        "source-delete",
        "campaign-insert",
        "campaign-update",
        "campaign-delete",
        "listing-insert",
        "listing-delete",
    ],
)
def test_runtime_role_cannot_change_evidence(app_connection: Connection, statement: object) -> None:
    with pytest.raises(ProgrammingError) as caught:
        app_connection.execute(statement)  # type: ignore[call-overload]
    assert isinstance(caught.value.orig, InsufficientPrivilege)


def test_one_campaign_can_list_several_model_years(owner_connection: Connection) -> None:
    campaign_id = add_campaign(owner_connection)
    add_listing(owner_connection, campaign_id, 2018)
    add_listing(owner_connection, campaign_id, 2019)

    # Read back as the website would, with its restricted role.
    owner_connection.execute(text("SET LOCAL ROLE askm6_app"))
    years = owner_connection.scalars(
        select(RecallApplicability.model_year)
        .join(RecallCampaign)
        .where(RecallCampaign.campaign_number == "99V000001")
        .order_by(RecallApplicability.model_year)
    ).all()
    assert years == [2018, 2019]
    assert (
        owner_connection.scalar(
            select(RecallCampaign.campaign_number)
            .join(RecallApplicability)
            .where(RecallApplicability.model_year == 2021)
        )
        is None
    )


def test_database_generates_campaign_ids(owner_connection: Connection) -> None:
    with pytest.raises(DBAPIError) as caught:
        owner_connection.execute(insert(RecallCampaign).values(id=1, **CAMPAIGN))
    assert isinstance(caught.value.orig, GeneratedAlways)


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("campaign_number", "19V497", "campaign_number_format"),
        ("campaign_number", "19v497000", "campaign_number_format"),
        ("campaign_number", "19E497000", "campaign_number_format"),
        ("manufacturer", "", "manufacturer_format"),
        ("component", "ENGINE\tFUEL", "component_format"),
        ("summary", "", "summary_format"),
        ("summary", "First line\nsecond line", "summary_format"),
        ("consequence", "", "consequence_format"),
        ("remedy", "Remedy\r", "remedy_format"),
        ("notes", "", "notes_format"),
        ("record_sha256", bytes(31), "record_sha256_length"),
        ("first_seen_at", SEEN + timedelta(seconds=1), "seen_times_ordered"),
        ("last_seen_at", SEEN - timedelta(seconds=1), "seen_times_ordered"),
    ],
)
def test_invalid_campaigns_are_rejected(
    owner_connection: Connection, column: str, value: object, constraint: str
) -> None:
    with pytest.raises(IntegrityError) as caught:
        add_campaign(owner_connection, **{column: value})
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == f"ck_recall_campaigns_{constraint}"


def test_safety_flags_cannot_be_left_unknown(owner_connection: Connection) -> None:
    with pytest.raises(IntegrityError) as caught:
        add_campaign(owner_connection, park_it=None)
    assert isinstance(caught.value.orig, NotNullViolation)


def test_campaign_is_stored_once_per_source(owner_connection: Connection) -> None:
    add_campaign(owner_connection)
    with pytest.raises(IntegrityError) as caught:
        add_campaign(owner_connection)
    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "uq_recall_campaigns_source_campaign"


def test_campaign_requires_a_known_source(owner_connection: Connection) -> None:
    with pytest.raises(IntegrityError) as caught:
        add_campaign(owner_connection, source_id=999)
    assert isinstance(caught.value.orig, ForeignKeyViolation)


def test_source_with_campaigns_cannot_be_deleted(owner_connection: Connection) -> None:
    add_campaign(owner_connection)
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(delete(EvidenceSource).where(EvidenceSource.id == 1))
    assert isinstance(caught.value.orig, ForeignKeyViolation)


def test_deleting_a_campaign_removes_its_listings(owner_connection: Connection) -> None:
    campaign_id = add_campaign(owner_connection)
    add_listing(owner_connection, campaign_id, 2018)
    owner_connection.execute(delete(RecallCampaign).where(RecallCampaign.id == campaign_id))
    assert (
        owner_connection.scalar(
            select(RecallApplicability.model_year).where(
                RecallApplicability.campaign_id == campaign_id
            )
        )
        is None
    )


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("make", "Mazda", "make_supported"),
        ("model", "MAZDA3", "model_supported"),
        ("model", "MAZDA 6", "model_supported"),
        ("model_year", 2017, "model_year_supported"),
        ("model_year", 2022, "model_year_supported"),
    ],
)
def test_invalid_listings_are_rejected(
    owner_connection: Connection, column: str, value: object, constraint: str
) -> None:
    campaign_id = add_campaign(owner_connection)
    listing = {"campaign_id": campaign_id, "model_year": 2021, **LISTING, column: value}
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(insert(RecallApplicability).values(**listing))
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == f"ck_recall_applicability_{constraint}"


def test_listing_is_stored_once(owner_connection: Connection) -> None:
    campaign_id = add_campaign(owner_connection)
    add_listing(owner_connection, campaign_id, 2021)
    with pytest.raises(IntegrityError) as caught:
        add_listing(owner_connection, campaign_id, 2021)
    assert isinstance(caught.value.orig, UniqueViolation)
    assert caught.value.orig.diag.constraint_name == "pk_recall_applicability"


def test_listing_requires_an_existing_campaign(owner_connection: Connection) -> None:
    with pytest.raises(IntegrityError) as caught:
        add_listing(owner_connection, 999_999, 2021)
    assert isinstance(caught.value.orig, ForeignKeyViolation)


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("slug", "NHTSA", "slug_format"),
        ("url", "http://example.test", "url_https"),
        ("terms_url", "https://example.test/a b", "terms_url_https"),
        ("terms_note", "", "terms_note_format"),
    ],
)
def test_invalid_sources_are_rejected(
    owner_connection: Connection, column: str, value: object, constraint: str
) -> None:
    source = {
        "id": 2,
        "slug": "synthetic_source",
        "name": "Synthetic source",
        "publisher": "Synthetic publisher",
        "url": "https://example.test",
        "terms_url": "https://example.test/terms",
        "terms_note": "Synthetic",
        "terms_checked_on": date(2026, 10, 29),
        column: value,
    }
    with pytest.raises(IntegrityError) as caught:
        owner_connection.execute(insert(EvidenceSource).values(**source))
    assert isinstance(caught.value.orig, CheckViolation)
    assert caught.value.orig.diag.constraint_name == f"ck_evidence_sources_{constraint}"
