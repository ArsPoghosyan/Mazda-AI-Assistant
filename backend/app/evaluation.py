"""Automotive evaluation set: schema, loader and structured-evidence checks.

The set is written before the chatbot so expected behaviour cannot be bent to fit
its answers. Graded answers come later; for now only evidence lookups are scored.
"""

import re
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.engine import Connection

from app.models import VehicleVariant
from app.recall_evidence import find_recall_evidence

DEFAULT_SET = Path(__file__).resolve().parents[1] / "evals" / "automotive_v1.json"

Category = Literal["recall", "vehicle_fact", "abstain", "clarify", "refuse", "safety", "injection"]
Behavior = Literal["answer", "abstain", "clarify", "refuse", "safety_first"]

# What a correct reply does for each category. Injection cases either refuse the
# instruction or answer the real question from stored evidence, ignoring the attack.
ALLOWED_BEHAVIORS: dict[str, frozenset[str]] = {
    "recall": frozenset({"answer"}),
    "vehicle_fact": frozenset({"answer"}),
    "abstain": frozenset({"abstain"}),
    "clarify": frozenset({"clarify"}),
    "refuse": frozenset({"refuse"}),
    "safety": frozenset({"safety_first"}),
    "injection": frozenset({"answer", "refuse"}),
}

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _plain(text: str) -> str:
    if _CONTROL.search(text):
        raise ValueError("Text must not contain control characters.")
    return text


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EvalVehicle(_Strict):
    """The vehicle selected in the conversation; unset fields mean the user did not say."""

    model_year: int = Field(ge=2018, le=2021)
    aspiration: Literal["naturally_aspirated", "turbo"] | None = None
    transmission: Literal["6AT", "6MT"] | None = None


class ExpectedRecalls(_Strict):
    """What find_recall_evidence must return for every catalogue match of the vehicle."""

    status: Literal["campaigns_listed", "none_listed"]
    # Newest report first, as retrieval orders them.
    campaigns: tuple[str, ...] = Field(max_length=20)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if any(re.fullmatch(r"[0-9]{2}V[0-9]{6}", number) is None for number in self.campaigns):
            raise ValueError("Campaign numbers must look like 19V497000.")
        if len(set(self.campaigns)) != len(self.campaigns):
            raise ValueError("Campaign numbers must not repeat.")
        if (self.status == "campaigns_listed") != bool(self.campaigns):
            raise ValueError("Only campaigns_listed has campaigns.")
        return self


class EvalCase(_Strict):
    id: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$", max_length=64)
    category: Category
    question: str = Field(min_length=1, max_length=500)
    vehicle: EvalVehicle | None
    expected_behavior: Behavior
    expected_recalls: ExpectedRecalls | None = None
    # EPA vehicle IDs of every catalogue row matching the vehicle.
    expected_catalogue: tuple[int, ...] | None = Field(default=None, min_length=1)
    urgent_safety: bool
    # Points a correct reply must make; graded once the chatbot exists.
    required_points: tuple[str, ...] = Field(min_length=1, max_length=8)
    # Phrases a reply must never contain, matched by forbidden_phrases_in.
    forbidden_phrases: tuple[str, ...] = Field(default=(), max_length=10)
    rationale: str = Field(min_length=1, max_length=600)
    verified_on: date

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        for text in (self.question, self.rationale, *self.required_points, *self.forbidden_phrases):
            _plain(text)
        if any(not point.strip() for point in (*self.required_points, *self.forbidden_phrases)):
            raise ValueError("Points and phrases must not be blank.")
        if self.expected_behavior not in ALLOWED_BEHAVIORS[self.category]:
            raise ValueError(f"{self.category} cases cannot expect {self.expected_behavior}.")
        has_evidence = self.expected_recalls is not None or self.expected_catalogue is not None
        # Every answer rests on stored evidence; only answers and clarifications cite any.
        if self.expected_behavior == "answer" and not has_evidence:
            raise ValueError("An answer case must name its expected evidence.")
        if has_evidence and self.expected_behavior not in ("answer", "clarify"):
            raise ValueError("Only answer and clarify cases may name evidence.")
        if has_evidence and self.vehicle is None:
            raise ValueError("Evidence is looked up by vehicle, so a vehicle is required.")
        if self.category == "recall" and self.expected_recalls is None:
            raise ValueError("A recall case must name its expected recalls.")
        if self.category == "vehicle_fact" and self.expected_catalogue is None:
            raise ValueError("A vehicle fact case must name its catalogue rows.")
        if self.expected_behavior == "safety_first" and not self.urgent_safety:
            raise ValueError("Safety-first cases are urgent by definition.")
        if self.expected_catalogue is not None and len(set(self.expected_catalogue)) != len(
            self.expected_catalogue
        ):
            raise ValueError("Catalogue rows must not repeat.")
        return self


class EvaluationSet(_Strict):
    format_version: Literal[1]
    # Where the recall expectations come from; live NHTSA data may differ later.
    recall_snapshot: str = Field(min_length=1, max_length=200)
    cases: tuple[EvalCase, ...] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        repeated = [case_id for case_id, n in Counter(c.id for c in self.cases).items() if n > 1]
        if repeated:
            raise ValueError(f"Case IDs repeat: {', '.join(sorted(repeated))}.")
        return self


def load_evaluation_set(path: Path = DEFAULT_SET) -> EvaluationSet:
    return EvaluationSet.model_validate_json(path.read_bytes())


@dataclass(frozen=True)
class EvidenceCheck:
    case_id: str
    problems: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.problems


def matching_variants(connection: Connection, vehicle: EvalVehicle) -> list[tuple[int, int | None]]:
    """(variant ID, EPA vehicle ID or None) for every catalogue row the vehicle could be."""
    query = select(VehicleVariant.id, VehicleVariant.epa_vehicle_id).where(
        VehicleVariant.model_year == vehicle.model_year
    )
    if vehicle.aspiration is not None:
        query = query.where(VehicleVariant.aspiration == vehicle.aspiration)
    if vehicle.transmission is not None:
        query = query.where(VehicleVariant.transmission == vehicle.transmission)
    rows = connection.execute(query.order_by(VehicleVariant.id))
    return [(row.id, row.epa_vehicle_id) for row in rows]


def _label(variant_id: int, epa_id: int | None) -> str:
    return f"EPA {epa_id}" if epa_id is not None else f"variant {variant_id}"


def check_case_evidence(connection: Connection, case: EvalCase) -> EvidenceCheck:
    """Compare stored evidence for the case's vehicle with what the case expects."""
    if case.vehicle is None:
        return EvidenceCheck(case.id, ())
    variants = matching_variants(connection, case.vehicle)
    if not variants:
        return EvidenceCheck(case.id, ("vehicle matches no catalogue row",))

    problems: list[str] = []
    if case.expected_catalogue is not None:
        # Catalogue expectations name EPA records; a row without one cannot be checked.
        unsourced = [variant_id for variant_id, epa_id in variants if epa_id is None]
        found = sorted(epa_id for _, epa_id in variants if epa_id is not None)
        if unsourced:
            problems.append(f"catalogue rows without an EPA ID: variants {unsourced}")
        elif found != sorted(case.expected_catalogue):
            problems.append(f"catalogue rows {found}, expected {sorted(case.expected_catalogue)}")

    if case.expected_recalls is not None:
        expected = case.expected_recalls
        # A model-year listing must not depend on engine or gearbox: check every match.
        for variant_id, epa_id in variants:
            label = _label(variant_id, epa_id)
            evidence = find_recall_evidence(connection, variant_id)
            numbers = tuple(fact.campaign_number for fact in evidence.campaigns)
            if evidence.status != expected.status or numbers != expected.campaigns:
                problems.append(
                    f"{label}: {evidence.status} {list(numbers)}, "
                    f"expected {expected.status} {list(expected.campaigns)}"
                )
            if evidence.requires_urgent_safety_message != case.urgent_safety:
                problems.append(f"{label}: urgent flag disagrees")
    return EvidenceCheck(case.id, tuple(problems))


def forbidden_phrases_in(reply: str, case: EvalCase) -> tuple[str, ...]:
    """Forbidden phrases the reply contains, matched as whole words, ignoring case and spacing.

    Whole-word matching keeps "Mobil" from matching "automobile". It cannot see
    negation ("is not safe to drive"), so phrases are written as definite claims.
    """
    return tuple(
        phrase
        for phrase in case.forbidden_phrases
        if re.search(
            r"(?<!\w)" + r"\s+".join(map(re.escape, phrase.split())) + r"(?!\w)",
            reply,
            re.IGNORECASE,
        )
    )
