"""Recall evidence wording and safety flags, without a database."""

import re
from dataclasses import replace
from datetime import UTC, date, datetime

import pytest

from app.recall_evidence import (
    LIMITATION,
    RecallEvidence,
    RecallFact,
    listing_statement,
    nhtsa_recall_url,
)

CHECKED = datetime(2026, 10, 29, 18, 44, tzinfo=UTC)
FACT = RecallFact(
    campaign_number="19V497000",
    report_received_on=date(2019, 6, 27),
    component="ENGINE",
    summary="Synthetic summary.",
    consequence="Synthetic consequence.",
    remedy="Synthetic remedy.",
    notes=None,
    park_it=False,
    park_outside=False,
    over_the_air_update=False,
    nhtsa_url=nhtsa_recall_url("19V497000"),
    last_listed_at=CHECKED,
)
EARLIER = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def evidence(**changes: object) -> RecallEvidence:
    base = RecallEvidence(
        model_year=2021,
        status="none_listed",
        campaigns=(),
        checked_at=CHECKED,
        source_name="NHTSA recalls API",
        source_publisher="US National Highway Traffic Safety Administration",
        source_url="https://api.nhtsa.gov/recalls/recallsByVehicle",
    )
    return replace(base, **changes)  # type: ignore[arg-type]


# Phrases that would turn missing evidence into a false all-clear.
FALSE_ALL_CLEAR = re.compile(
    r"\b(has|have|there are) no recalls\b|\bno open recalls\b|\brecall-free\b", re.IGNORECASE
)


def test_recall_links_point_to_the_nhtsa_campaign_page() -> None:
    assert nhtsa_recall_url("19V497000") == "https://www.nhtsa.gov/recalls?nhtsaId=19V497000"


def test_empty_listing_is_dated_and_never_an_all_clear() -> None:
    statement = listing_statement(evidence())
    assert "showed no recall campaigns for the 2021 Mazda 6 as of 2026-10-29" in statement
    assert "not proof that no recalls apply" in statement
    assert statement.endswith(LIMITATION)
    assert not FALSE_ALL_CLEAR.search(statement)


def test_unchecked_year_says_nothing_about_recalls() -> None:
    statement = listing_statement(evidence(status="not_checked", checked_at=None))
    assert "has not been checked yet" in statement
    assert "as of" not in statement
    assert not FALSE_ALL_CLEAR.search(statement)


@pytest.mark.parametrize(("count", "noun"), [(1, "campaign"), (2, "campaigns")])
def test_listed_campaigns_are_counted_with_the_limitation(count: int, noun: str) -> None:
    statement = listing_statement(
        evidence(model_year=2018, status="campaigns_listed", campaigns=(FACT,) * count)
    )
    assert f"NHTSA lists {count} recall {noun} for the 2018 Mazda 6 as of 2026-10-29." in statement
    assert statement.endswith(LIMITATION)


def test_missing_check_date_is_admitted_not_invented() -> None:
    statement = listing_statement(
        evidence(status="campaigns_listed", campaigns=(FACT,), checked_at=None)
    )
    assert "(date of the last check unknown)" in statement


@pytest.mark.parametrize(
    ("park_it", "park_outside", "urgent"),
    [(False, False, False), (True, False, True), (False, True, True)],
)
def test_park_flags_require_an_urgent_safety_message(
    park_it: bool, park_outside: bool, urgent: bool
) -> None:
    flagged = replace(FACT, park_it=park_it, park_outside=park_outside)
    result = evidence(status="campaigns_listed", campaigns=(FACT, flagged))
    assert result.requires_urgent_safety_message is urgent


def test_every_result_carries_the_vin_limitation() -> None:
    assert evidence().limitation == LIMITATION
    assert "not by individual vehicle" in LIMITATION
    assert "https://www.nhtsa.gov/recalls" in LIMITATION


def test_previously_listed_campaign_is_dated_and_not_presented_as_current() -> None:
    dropped = replace(FACT, last_listed_at=EARLIER)
    statement = listing_statement(evidence(previously_listed=(dropped,)))
    assert statement.startswith(
        "NHTSA's model-year listing showed no recall campaigns for the 2021 Mazda 6 "
        "as of 2026-10-29."
    )
    assert (
        "1 recall campaign listed earlier was not in the latest listing: "
        "19V497000 (last listed 2026-10-01). That does not show it was withdrawn or fixed."
    ) in statement
    assert "NHTSA lists 1 recall" not in statement
    assert not FALSE_ALL_CLEAR.search(statement)


def test_reduced_listing_counts_only_current_campaigns() -> None:
    current = replace(FACT, campaign_number="21V875000")
    dropped = replace(FACT, last_listed_at=EARLIER)
    statement = listing_statement(
        evidence(
            model_year=2018,
            status="campaigns_listed",
            campaigns=(current,),
            previously_listed=(dropped,),
        )
    )
    assert "NHTSA lists 1 recall campaign for the 2018 Mazda 6 as of 2026-10-29." in statement
    assert "19V497000 (last listed 2026-10-01)" in statement


def test_previously_listed_park_flag_still_requires_urgency() -> None:
    dropped_fire = replace(FACT, park_outside=True, last_listed_at=EARLIER)
    assert evidence(previously_listed=(dropped_fire,)).requires_urgent_safety_message is True
