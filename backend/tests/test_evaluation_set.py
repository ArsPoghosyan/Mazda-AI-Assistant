"""The automotive evaluation set loads, is balanced and rejects inconsistent cases."""

import json
from collections import Counter
from typing import Any

import pytest
from pydantic import ValidationError

from app.evaluation import (
    DEFAULT_SET,
    EvalCase,
    EvaluationSet,
    forbidden_phrases_in,
    load_evaluation_set,
)


def answer_case(**changes: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "id": "recall-2018-example",
        "category": "recall",
        "question": "Are there any recalls on my 2018 Mazda 6?",
        "vehicle": {"model_year": 2018},
        "expected_behavior": "answer",
        "expected_recalls": {"status": "campaigns_listed", "campaigns": ["19V497000"]},
        "urgent_safety": False,
        "required_points": ["Lists the campaign."],
        "rationale": "Example.",
        "verified_on": "2026-11-02",
    }
    case.update(changes)
    return case


def validate(case: dict[str, Any]) -> EvalCase:
    return EvalCase.model_validate_json(json.dumps(case))


def test_committed_set_loads() -> None:
    evaluation = load_evaluation_set()
    assert evaluation.format_version == 1
    assert DEFAULT_SET.name == "automotive_v1.json"


def test_committed_set_has_30_to_50_cases_across_every_category() -> None:
    cases = load_evaluation_set().cases
    counts = Counter(case.category for case in cases)

    assert 30 <= len(cases) <= 50
    assert set(counts) == {
        "recall",
        "vehicle_fact",
        "abstain",
        "clarify",
        "refuse",
        "safety",
        "injection",
    }
    assert min(counts.values()) >= 3


def test_required_points_never_contain_their_own_forbidden_phrases() -> None:
    # A reply that literally makes every required point must still pass.
    for case in load_evaluation_set().cases:
        assert forbidden_phrases_in(" ".join(case.required_points), case) == (), case.id


def test_abstain_and_refuse_cases_cite_no_evidence() -> None:
    for case in load_evaluation_set().cases:
        if case.expected_behavior in ("abstain", "refuse", "safety_first"):
            assert case.expected_recalls is None, case.id
            assert case.expected_catalogue is None, case.id


def test_valid_example_case_passes() -> None:
    assert validate(answer_case()).id == "recall-2018-example"


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "Recall 2018"},
        {"category": "weather"},
        {"expected_behavior": "refuse"},
        {"expected_recalls": None},
        {"vehicle": None},
        {"vehicle": {"model_year": 2015}},
        {"vehicle": {"model_year": 2021, "transmission": "CVT"}},
        {"expected_recalls": {"status": "campaigns_listed", "campaigns": []}},
        {"expected_recalls": {"status": "none_listed", "campaigns": ["19V497000"]}},
        {"expected_recalls": {"status": "not_checked", "campaigns": []}},
        {"expected_recalls": {"status": "campaigns_listed", "campaigns": ["19-497"]}},
        {
            "expected_recalls": {
                "status": "campaigns_listed",
                "campaigns": ["19V497000", "19V497000"],
            }
        },
        {"required_points": []},
        {"required_points": ["  "]},
        {"question": "Recalls?\u0000"},
        {"verified_on": "yesterday"},
        {"invented_field": True},
    ],
)
def test_inconsistent_cases_are_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        validate(answer_case(**changes))


def test_abstain_case_cannot_name_evidence() -> None:
    with pytest.raises(ValidationError, match="Only answer and clarify"):
        validate(
            answer_case(
                category="abstain",
                expected_behavior="abstain",
                expected_recalls=None,
                expected_catalogue=[43300],
            )
        )


def test_safety_case_must_be_urgent() -> None:
    with pytest.raises(ValidationError, match="urgent"):
        validate(
            answer_case(
                category="safety",
                expected_behavior="safety_first",
                expected_recalls=None,
                urgent_safety=False,
            )
        )


def test_vehicle_fact_needs_catalogue_rows() -> None:
    with pytest.raises(ValidationError, match="catalogue"):
        validate(answer_case(category="vehicle_fact"))


def test_duplicate_case_ids_are_rejected() -> None:
    document = {
        "format_version": 1,
        "recall_snapshot": "test",
        "cases": [answer_case(), answer_case()],
    }
    with pytest.raises(ValidationError, match="repeat"):
        EvaluationSet.model_validate_json(json.dumps(document))


def test_unknown_format_version_is_rejected() -> None:
    document = {"format_version": 2, "recall_snapshot": "test", "cases": [answer_case()]}
    with pytest.raises(ValidationError):
        EvaluationSet.model_validate_json(json.dumps(document))


def phrases_case(*phrases: str) -> EvalCase:
    return validate(answer_case(forbidden_phrases=list(phrases)))


@pytest.mark.parametrize(
    ("reply", "found"),
    [
        ("Check the oil grade in your automobile's manual.", ()),
        ("Use Mobil 1.", ("Mobil",)),
        ("MOBIL works.", ("Mobil",)),
        ("It is not safe to drive.", ()),
        ("It is safe to drive.", ("is safe to drive",)),
        ("It is\nsafe  to drive.", ("is safe to drive",)),
        ("Use 0W-20 oil.", ("0W-20",)),
        ("Use 10W-20 oil.", ()),
    ],
)
def test_forbidden_phrases_match_whole_words(reply: str, found: tuple[str, ...]) -> None:
    case = phrases_case("Mobil", "is safe to drive", "0W-20")
    assert forbidden_phrases_in(reply, case) == found
