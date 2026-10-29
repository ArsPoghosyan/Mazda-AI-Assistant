"""Store a validated NHTSA recall batch idempotently, inside the caller's transaction."""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection

from app.models import EvidenceSource, RecallApplicability, RecallCampaign
from app.nhtsa_recalls import MAKE, MODEL, RecallBatch, RecallRecord

SOURCE_SLUG = "nhtsa_recalls"


class StaleBatchError(RuntimeError):
    """A newer import already stored evidence; applying this batch would undo it."""


@dataclass(frozen=True)
class IngestionReport:
    added: int
    changed: int
    unchanged: int
    listings_added: int
    # Stored (campaign, model year) listings for the requested years that NHTSA
    # did not list this run. They are kept: one missing response is not proof
    # of withdrawal.
    not_seen: tuple[tuple[str, int], ...]


def _content(record: RecallRecord) -> dict[str, object]:
    return {
        "report_received_on": record.report_received_on,
        "manufacturer": record.manufacturer,
        "component": record.component,
        "summary": record.summary,
        "consequence": record.consequence,
        "remedy": record.remedy,
        "notes": record.notes,
        "park_it": record.park_it,
        "park_outside": record.park_outside,
        "over_the_air_update": record.over_the_air_update,
        "record_sha256": record.record_sha256,
    }


def apply_recall_batch(
    connection: Connection,
    batch: RecallBatch,
    *,
    seen_at: datetime,
) -> IngestionReport:
    """Insert new campaigns, update changed ones and mark every listed one as seen.

    seen_at is when the batch was fetched, so evidence time never moves backward.
    """
    if seen_at.tzinfo is None:
        raise ValueError("seen_at must be timezone-aware.")

    # One import at a time; readers are not blocked.
    connection.execute(
        text(
            "LOCK TABLE app.recall_campaigns, app.recall_applicability IN SHARE ROW EXCLUSIVE MODE"
        )
    )
    source_id = connection.execute(
        select(EvidenceSource.id).where(EvidenceSource.slug == SOURCE_SLUG)
    ).scalar_one()

    # Under the lock: refuse a batch fetched before the newest stored evidence,
    # so a slow import cannot overwrite newer content or safety flags.
    newest = connection.scalar(
        select(func.max(RecallCampaign.last_seen_at)).where(RecallCampaign.source_id == source_id)
    )
    if newest is not None and newest > seen_at:
        raise StaleBatchError("A newer import already ran; this batch is out of date.")

    stored = {
        number: (campaign_id, digest)
        for campaign_id, number, digest in connection.execute(
            select(
                RecallCampaign.id,
                RecallCampaign.campaign_number,
                RecallCampaign.record_sha256,
            ).where(
                RecallCampaign.source_id == source_id,
                RecallCampaign.campaign_number.in_(batch.campaigns),
            )
        )
    }

    added = changed = unchanged = 0
    campaign_ids: dict[str, int] = {}
    for number, record in sorted(batch.campaigns.items()):
        if number not in stored:
            campaign_ids[number] = connection.execute(
                insert(RecallCampaign)
                .values(
                    source_id=source_id,
                    campaign_number=number,
                    first_seen_at=seen_at,
                    content_updated_at=seen_at,
                    last_seen_at=seen_at,
                    **_content(record),
                )
                .returning(RecallCampaign.id)
            ).scalar_one()
            added += 1
            continue

        campaign_id, digest = stored[number]
        campaign_ids[number] = campaign_id
        if digest == record.record_sha256:
            values: dict[str, object] = {"last_seen_at": seen_at}
            unchanged += 1
        else:
            values = {**_content(record), "content_updated_at": seen_at, "last_seen_at": seen_at}
            changed += 1
        connection.execute(
            update(RecallCampaign).where(RecallCampaign.id == campaign_id).values(**values)
        )

    listings = [
        {"campaign_id": campaign_ids[number], "make": MAKE, "model": MODEL, "model_year": year}
        for number, years in sorted(batch.listings.items())
        for year in sorted(years)
    ]
    listings_added = 0
    if listings:
        # RETURNING lists only rows actually inserted; rowcount is unreliable here.
        listings_added = len(
            connection.execute(
                pg_insert(RecallApplicability)
                .values(listings)
                .on_conflict_do_nothing()
                .returning(RecallApplicability.campaign_id)
            ).all()
        )

    listed_now = {(number, year) for number, years in batch.listings.items() for year in years}
    stored_listings = connection.execute(
        select(RecallCampaign.campaign_number, RecallApplicability.model_year)
        .join(RecallApplicability)
        .where(
            RecallCampaign.source_id == source_id,
            RecallApplicability.make == MAKE,
            RecallApplicability.model == MODEL,
            RecallApplicability.model_year.in_(batch.model_years),
        )
        .order_by(RecallCampaign.campaign_number, RecallApplicability.model_year)
    ).all()

    return IngestionReport(
        added=added,
        changed=changed,
        unchanged=unchanged,
        listings_added=listings_added,
        not_seen=tuple(
            (number, year) for number, year in stored_listings if (number, year) not in listed_now
        ),
    )
