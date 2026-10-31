"""Look up stored NHTSA recall evidence for one catalogue vehicle (exact SQL, no search)."""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.engine import Connection

from app.models import (
    EvidenceSource,
    RecallApplicability,
    RecallCampaign,
    RecallModelYearCheck,
    VehicleVariant,
)
from app.nhtsa_recall_ingestion import SOURCE_SLUG
from app.nhtsa_recalls import MAKE, MODEL

# Shown with every result: a model-year listing is not a check of one car.
LIMITATION = (
    "NHTSA lists recalls by model year, not by individual vehicle. Check a specific "
    "car by its VIN at https://www.nhtsa.gov/recalls."
)

ListingStatus = Literal["campaigns_listed", "none_listed", "not_checked", "unverified"]


class UnknownVehicleVariant(LookupError):
    """The requested variant is not in the verified catalogue."""


@dataclass(frozen=True)
class RecallFact:
    campaign_number: str
    report_received_on: date
    component: str
    summary: str
    consequence: str
    remedy: str
    notes: str | None
    park_it: bool
    park_outside: bool
    over_the_air_update: bool
    nhtsa_url: str
    # When NHTSA last listed this campaign for this model year; None if listed
    # before per-year dates were recorded and not confirmed since.
    last_listed_at: datetime | None


@dataclass(frozen=True)
class RecallEvidence:
    model_year: int
    status: ListingStatus
    # Listed by the latest check of this model year.
    campaigns: tuple[RecallFact, ...]
    # When NHTSA was last checked for this model year; None if never checked.
    checked_at: datetime | None
    source_name: str
    source_publisher: str
    source_url: str
    # Not confirmed by the latest check (or date unknown); kept, never shown as current.
    previously_listed: tuple[RecallFact, ...] = ()
    limitation: str = LIMITATION

    @property
    def requires_urgent_safety_message(self) -> bool:
        """NHTSA's "do not drive" or "park outside" flags must lead the answer.

        Previously listed campaigns count too: leaving a listing does not prove a fix.
        """
        return any(
            fact.park_it or fact.park_outside for fact in (*self.campaigns, *self.previously_listed)
        )


def nhtsa_recall_url(campaign_number: str) -> str:
    return f"https://www.nhtsa.gov/recalls?nhtsaId={campaign_number}"


def find_recall_evidence(connection: Connection, variant_id: int) -> RecallEvidence:
    """Return NHTSA campaigns listed for the variant's model year, with provenance."""
    model_year = connection.scalar(
        select(VehicleVariant.model_year).where(VehicleVariant.id == variant_id)
    )
    if model_year is None:
        raise UnknownVehicleVariant("Vehicle variant is not in the catalogue.")

    source = connection.execute(
        select(
            EvidenceSource.id,
            EvidenceSource.name,
            EvidenceSource.publisher,
            EvidenceSource.url,
        ).where(EvidenceSource.slug == SOURCE_SLUG)
    ).one()

    rows = connection.execute(
        select(
            RecallCampaign.campaign_number,
            RecallCampaign.report_received_on,
            RecallCampaign.component,
            RecallCampaign.summary,
            RecallCampaign.consequence,
            RecallCampaign.remedy,
            RecallCampaign.notes,
            RecallCampaign.park_it,
            RecallCampaign.park_outside,
            RecallCampaign.over_the_air_update,
            RecallApplicability.last_listed_at,
        )
        .join(RecallApplicability)
        .where(
            RecallCampaign.source_id == source.id,
            RecallApplicability.make == MAKE,
            RecallApplicability.model == MODEL,
            RecallApplicability.model_year == model_year,
        )
        .order_by(RecallCampaign.report_received_on.desc(), RecallCampaign.campaign_number)
    ).all()
    facts = [
        RecallFact(
            campaign_number=row.campaign_number,
            report_received_on=row.report_received_on,
            component=row.component,
            summary=row.summary,
            consequence=row.consequence,
            remedy=row.remedy,
            notes=row.notes,
            park_it=row.park_it,
            park_outside=row.park_outside,
            over_the_air_update=row.over_the_air_update,
            nhtsa_url=nhtsa_recall_url(row.campaign_number),
            last_listed_at=row.last_listed_at,
        )
        for row in rows
    ]

    check = connection.execute(
        select(RecallModelYearCheck.checked_at, RecallModelYearCheck.campaigns_listed).where(
            RecallModelYearCheck.source_id == source.id,
            RecallModelYearCheck.make == MAKE,
            RecallModelYearCheck.model == MODEL,
            RecallModelYearCheck.model_year == model_year,
        )
    ).one_or_none()
    checked_at = check.checked_at if check is not None else None

    # A listing counts as current only if the latest check of this year confirmed
    # it; an unknown date is never assumed to be current.
    def confirmed(fact: RecallFact) -> bool:
        return (
            checked_at is not None
            and fact.last_listed_at is not None
            and fact.last_listed_at >= checked_at
        )

    current = [fact for fact in facts if confirmed(fact)]
    status: ListingStatus
    if check is None:
        status = "not_checked"
    elif len(current) != check.campaigns_listed:
        # Stored listings disagree with what the check recorded (for example dates
        # still unknown from before per-year dates); say nothing until re-imported.
        status = "unverified"
    elif current:
        status = "campaigns_listed"
    else:
        status = "none_listed"

    campaigns = tuple(current) if status == "campaigns_listed" else ()
    previously_listed = tuple(
        sorted(
            (fact for fact in facts if fact not in campaigns),
            key=lambda fact: (
                fact.last_listed_at is None,
                -(fact.last_listed_at.timestamp() if fact.last_listed_at else 0),
                fact.campaign_number,
            ),
        )
    )

    return RecallEvidence(
        model_year=model_year,
        status=status,
        campaigns=campaigns,
        checked_at=checked_at,
        source_name=source.name,
        source_publisher=source.publisher,
        source_url=source.url,
        previously_listed=previously_listed,
    )


def _previous_statement(previous: tuple[RecallFact, ...]) -> str:
    if not previous:
        return ""
    details = ", ".join(
        f"{fact.campaign_number} (last listed {fact.last_listed_at.date().isoformat()})"
        if fact.last_listed_at is not None
        else f"{fact.campaign_number} (last-listed date unknown)"
        for fact in previous
    )
    if len(previous) == 1:
        return (
            " 1 recall campaign listed earlier was not confirmed by the latest listing: "
            f"{details}. That does not show it was withdrawn or fixed."
        )
    return (
        f" {len(previous)} recall campaigns listed earlier were not confirmed by the latest "
        f"listing: {details}. That does not show they were withdrawn or fixed."
    )


def listing_statement(evidence: RecallEvidence) -> str:
    """Fixed wording for what the listing does and does not show; never "no recalls"."""
    vehicle = f"{evidence.model_year} Mazda 6"
    as_of = (
        f"as of {evidence.checked_at.date().isoformat()}"
        if evidence.checked_at is not None
        else "(date of the last check unknown)"
    )
    previous = _previous_statement(evidence.previously_listed)
    if evidence.status == "campaigns_listed":
        count = len(evidence.campaigns)
        noun = "campaign" if count == 1 else "campaigns"
        return (
            f"NHTSA lists {count} recall {noun} for the {vehicle} {as_of}.{previous} {LIMITATION}"
        )
    if evidence.status == "none_listed":
        return (
            f"NHTSA's model-year listing showed no recall campaigns for the {vehicle} "
            f"{as_of}.{previous} That is not proof that no recalls apply. {LIMITATION}"
        )
    if evidence.status == "unverified":
        return (
            f"Stored NHTSA recall data for the {vehicle} is incomplete and must be "
            f"re-imported before anything can be said about recalls. {LIMITATION}"
        )
    return (
        f"NHTSA recall data for the {vehicle} has not been checked yet, so nothing can "
        f"be said about recalls. {LIMITATION}"
    )
