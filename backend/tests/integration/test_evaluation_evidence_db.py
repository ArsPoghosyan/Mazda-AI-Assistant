"""Score the evaluation set's structured evidence against the recorded NHTSA snapshot."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import insert, text
from sqlalchemy.engine import Connection

from app.evaluation import (
    EvalCase,
    EvalVehicle,
    ExpectedRecalls,
    check_case_evidence,
    forbidden_phrases_in,
    load_evaluation_set,
    matching_variants,
)
from app.models import VehicleVariant
from app.nhtsa_recall_ingestion import apply_recall_batch
from app.nhtsa_recalls import RecallBatch, merge_model_years, parse_model_year_response
from app.recall_evidence import find_recall_evidence, listing_statement

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nhtsa"
CHECKED = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


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


@pytest.fixture
def website(owner_connection: Connection) -> Connection:
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    owner_connection.execute(text("SET LOCAL ROLE askm6_app"))
    return owner_connection


def test_every_case_matches_the_stored_evidence(website: Connection) -> None:
    cases = load_evaluation_set().cases
    results = [check_case_evidence(website, case) for case in cases]
    failures = {result.case_id: result.problems for result in results if not result.passed}

    assert failures == {}
    # Not vacuous: recall and catalogue lookups were really scored.
    assert sum(case.expected_recalls is not None for case in cases) >= 8
    assert sum(case.expected_catalogue is not None for case in cases) >= 6


def test_fixed_recall_wording_never_trips_a_forbidden_phrase(website: Connection) -> None:
    # The chatbot will quote listing_statement verbatim, so it must pass every recall case.
    for case in load_evaluation_set().cases:
        if case.expected_recalls is None or case.vehicle is None:
            continue
        for variant_id, _ in matching_variants(website, case.vehicle):
            statement = listing_statement(find_recall_evidence(website, variant_id))
            assert forbidden_phrases_in(statement, case) == (), case.id


def case_named(case_id: str) -> EvalCase:
    return next(case for case in load_evaluation_set().cases if case.id == case_id)


def test_wrong_expectation_is_reported(website: Connection) -> None:
    wrong = case_named("recall-2021-fuel-pump").model_copy(
        update={
            "vehicle": EvalVehicle(model_year=2021),
            "expected_recalls": ExpectedRecalls(
                status="campaigns_listed", campaigns=("21V875000",)
            ),
        }
    )
    result = check_case_evidence(website, wrong)

    assert not result.passed
    # Both 2021 catalogue rows (non-turbo and turbo) are checked and reported.
    assert len(result.problems) == 2
    assert all("none_listed" in problem for problem in result.problems)


def test_vehicle_outside_the_catalogue_is_reported(website: Connection) -> None:
    case = case_named("recall-2021-family-car").model_copy(
        update={"vehicle": EvalVehicle(model_year=2021, transmission="6MT")}
    )
    assert check_case_evidence(website, case).problems == ("vehicle matches no catalogue row",)


def test_catalogue_mismatch_is_reported(website: Connection) -> None:
    case = case_named("fact-2021-manual").model_copy(update={"expected_catalogue": (43300,)})
    (problem,) = check_case_evidence(website, case).problems
    assert problem == "catalogue rows [43300, 43301], expected [43300]"


def test_catalogue_row_without_epa_id_is_reported(owner_connection: Connection) -> None:
    # The schema allows a catalogue row with no EPA record; it must not crash scoring.
    owner_connection.execute(
        insert(VehicleVariant).values(
            id=11,
            model_year=2021,
            market="US",
            engine="2.5L_I4_SKYACTIV_G",
            aspiration="naturally_aspirated",
            transmission="6AT",
            drive="FWD",
            trim_level="Touring",
            epa_vehicle_id=None,
            source_note="Synthetic test row",
        )
    )
    apply_recall_batch(owner_connection, recorded_batch(), seen_at=CHECKED)
    owner_connection.execute(text("SET LOCAL ROLE askm6_app"))

    drive = check_case_evidence(owner_connection, case_named("fact-2021-drive"))
    assert drive.problems == ("catalogue rows without an EPA ID: variants [11]",)
    # Recall checks still cover the unsourced row, labelled by variant ID.
    assert check_case_evidence(owner_connection, case_named("recall-2021-family-car")).passed
