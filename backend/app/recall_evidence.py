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

ListingStatus = Literal["campaigns_listed", "none_listed", "not_checked"]


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


@dataclass(frozen=True)
class RecallEvidence:
    model_year: int
    status: ListingStatus
    campaigns: tuple[RecallFact, ...]
    # When NHTSA was last checked for this model year; None if never checked.
    checked_at: datetime | None
    source_name: str
    source_publisher: str
    source_url: str
    limitation: str = LIMITATION

    @property
    def requires_urgent_safety_message(self) -> bool:
        """NHTSA's "do not drive" or "park outside" flags must lead the answer."""
        return any(fact.park_it or fact.park_outside for fact in self.campaigns)


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
    campaigns = tuple(
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
        )
        for row in rows
    )

    checked_at = connection.scalar(
        select(RecallModelYearCheck.checked_at).where(
            RecallModelYearCheck.source_id == source.id,
            RecallModelYearCheck.make == MAKE,
            RecallModelYearCheck.model == MODEL,
            RecallModelYearCheck.model_year == model_year,
        )
    )
    status: ListingStatus
    if campaigns:
        status = "campaigns_listed"
    elif checked_at is not None:
        status = "none_listed"
    else:
        status = "not_checked"

    return RecallEvidence(
        model_year=model_year,
        status=status,
        campaigns=campaigns,
        checked_at=checked_at,
        source_name=source.name,
        source_publisher=source.publisher,
        source_url=source.url,
    )


def listing_statement(evidence: RecallEvidence) -> str:
    """Fixed wording for what the listing does and does not show; never "no recalls"."""
    vehicle = f"{evidence.model_year} Mazda 6"
    as_of = (
        f"as of {evidence.checked_at.date().isoformat()}"
        if evidence.checked_at is not None
        else "(date of the last check unknown)"
    )
    if evidence.status == "campaigns_listed":
        count = len(evidence.campaigns)
        noun = "campaign" if count == 1 else "campaigns"
        return f"NHTSA lists {count} recall {noun} for the {vehicle} {as_of}. {LIMITATION}"
    if evidence.status == "none_listed":
        return (
            f"NHTSA's model-year listing showed no recall campaigns for the {vehicle} "
            f"{as_of}. That is not proof that no recalls apply. {LIMITATION}"
        )
    return (
        f"NHTSA recall data for the {vehicle} has not been checked yet, so nothing can "
        f"be said about recalls. {LIMITATION}"
    )
