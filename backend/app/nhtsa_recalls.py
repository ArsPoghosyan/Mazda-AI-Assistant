"""Fetch and validate NHTSA's Mazda 6 recall listings for supported model years."""

import asyncio
import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta

import httpx2
from pydantic import BaseModel, ConfigDict, Field, ValidationError

NHTSA_RECALLS_URL = "https://api.nhtsa.gov/recalls/recallsByVehicle"
MAKE = "MAZDA"
MODEL = "MAZDA6"
SUPPORTED_YEARS = range(2018, 2022)

_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_RESULTS = 100
_CAMPAIGN_NUMBER = re.compile(r"[0-9]{2}V[0-9]{6}")
# NHTSA writes dates day/month/year, e.g. 27/06/2019.
_REPORT_DATE = re.compile(r"[0-9]{2}/[0-9]{2}/[0-9]{4}")
# Stored text limits match the database CHECK constraints.
_TEXT_LIMITS = {
    "manufacturer": 120,
    "component": 300,
    "summary": 4000,
    "consequence": 2000,
    "remedy": 2000,
    "notes": 2000,
}


class NhtsaRecallError(RuntimeError):
    """NHTSA's response could not be retrieved or trusted; nothing should be stored."""


class _UpstreamRecall(BaseModel):
    """One record exactly as NHTSA sends it; unknown fields fail closed."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    manufacturer: str = Field(alias="Manufacturer")
    campaign_number: str = Field(alias="NHTSACampaignNumber")
    park_it: bool = Field(alias="parkIt")
    park_outside: bool = Field(alias="parkOutSide")
    over_the_air_update: bool = Field(alias="overTheAirUpdate")
    report_received_date: str = Field(alias="ReportReceivedDate")
    component: str = Field(alias="Component")
    summary: str = Field(alias="Summary")
    consequence: str = Field(alias="Consequence")
    remedy: str = Field(alias="Remedy")
    notes: str | None = Field(default=None, alias="Notes")
    model_year: str = Field(alias="ModelYear")
    make: str = Field(alias="Make")
    model: str = Field(alias="Model")


class _UpstreamResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    count: int = Field(alias="Count", ge=0, le=_MAX_RESULTS)
    message: str = Field(alias="Message", max_length=200)
    results: list[_UpstreamRecall] = Field(max_length=_MAX_RESULTS)


@dataclass(frozen=True)
class RecallRecord:
    """Cleaned campaign content ready for storage."""

    campaign_number: str
    report_received_on: date
    manufacturer: str
    component: str
    summary: str
    consequence: str
    remedy: str
    notes: str | None
    park_it: bool
    park_outside: bool
    over_the_air_update: bool
    record_sha256: bytes


@dataclass(frozen=True)
class RecallBatch:
    """Everything one run retrieved, merged across the requested model years."""

    model_years: tuple[int, ...]
    campaigns: dict[str, RecallRecord]
    listings: dict[str, frozenset[int]]

    @property
    def empty_years(self) -> tuple[int, ...]:
        listed = {year for years in self.listings.values() for year in years}
        return tuple(year for year in self.model_years if year not in listed)


def _clean_text(value: str | None, field: str, *, optional: bool = False) -> str | None:
    """Collapse whitespace and reject hidden characters or oversized text."""
    text = " ".join((value or "").split())
    if not text:
        if optional:
            return None
        raise NhtsaRecallError(f"NHTSA record has an empty {field}.")
    if any(unicodedata.category(character)[0] == "C" for character in text):
        raise NhtsaRecallError(f"NHTSA record {field} contains control characters.")
    if len(text) > _TEXT_LIMITS[field]:
        raise NhtsaRecallError(f"NHTSA record {field} is too long.")
    return text


def _required_text(value: str, field: str) -> str:
    text = _clean_text(value, field)
    assert text is not None
    return text


def _report_date(value: str) -> date:
    if not _REPORT_DATE.fullmatch(value):
        raise NhtsaRecallError("NHTSA record has an unexpected report date format.")
    try:
        parsed = datetime.strptime(value, "%d/%m/%Y").date()
    except ValueError:
        raise NhtsaRecallError("NHTSA record has an invalid report date.") from None
    if not date(1966, 1, 1) <= parsed <= datetime.now(UTC).date() + timedelta(days=1):
        raise NhtsaRecallError("NHTSA record has an implausible report date.")
    return parsed


def fingerprint(record: RecallRecord) -> bytes:
    """Hash the stored content (not the model year) to detect real upstream edits."""
    content = {
        "campaign_number": record.campaign_number,
        "report_received_on": record.report_received_on.isoformat(),
        "manufacturer": record.manufacturer,
        "component": record.component,
        "summary": record.summary,
        "consequence": record.consequence,
        "remedy": record.remedy,
        "notes": record.notes,
        "park_it": record.park_it,
        "park_outside": record.park_outside,
        "over_the_air_update": record.over_the_air_update,
    }
    canonical = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).digest()


def _clean_record(upstream: _UpstreamRecall, model_year: int) -> RecallRecord:
    # Never accept another vehicle's data, even if NHTSA's filter misbehaves.
    if (upstream.make, upstream.model, upstream.model_year) != (MAKE, MODEL, str(model_year)):
        raise NhtsaRecallError("NHTSA returned a record for a different vehicle.")
    if not _CAMPAIGN_NUMBER.fullmatch(upstream.campaign_number):
        raise NhtsaRecallError("NHTSA record has an unexpected campaign number.")

    record = RecallRecord(
        campaign_number=upstream.campaign_number,
        report_received_on=_report_date(upstream.report_received_date),
        manufacturer=_required_text(upstream.manufacturer, "manufacturer"),
        component=_required_text(upstream.component, "component"),
        summary=_required_text(upstream.summary, "summary"),
        consequence=_required_text(upstream.consequence, "consequence"),
        remedy=_required_text(upstream.remedy, "remedy"),
        notes=_clean_text(upstream.notes, "notes", optional=True),
        park_it=upstream.park_it,
        park_outside=upstream.park_outside,
        over_the_air_update=upstream.over_the_air_update,
        record_sha256=b"",
    )
    return replace(record, record_sha256=fingerprint(record))


def parse_model_year_response(status_code: int, body: bytes, model_year: int) -> list[RecallRecord]:
    """Validate one recallsByVehicle response body for one model year."""
    try:
        payload = _UpstreamResponse.model_validate_json(body)
    except ValidationError:
        raise NhtsaRecallError("NHTSA response did not match the expected format.") from None

    if payload.count != len(payload.results):
        raise NhtsaRecallError("NHTSA response count does not match its results.")
    # NHTSA answers an empty model year with HTTP 400 and a zero-result body.
    if status_code == 400 and payload.count != 0:
        raise NhtsaRecallError("NHTSA rejected the request.")

    return [_clean_record(upstream, model_year) for upstream in payload.results]


async def fetch_model_year(client: httpx2.AsyncClient, model_year: int) -> list[RecallRecord]:
    """Download one bounded response from the fixed NHTSA endpoint."""
    if model_year not in SUPPORTED_YEARS:
        raise ValueError("Model year is outside the supported range.")

    body = bytearray()
    try:
        async with asyncio.timeout(_TIMEOUT_SECONDS):
            async with client.stream(
                "GET",
                NHTSA_RECALLS_URL,
                params={"make": MAKE, "model": MODEL, "modelYear": str(model_year)},
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                auth=None,
                follow_redirects=False,
                timeout=_TIMEOUT_SECONDS,
            ) as response:
                if response.status_code not in (200, 400):
                    raise NhtsaRecallError("NHTSA recalls are unavailable.")

                content_type = (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                )
                if content_type != "application/json":
                    raise NhtsaRecallError("NHTSA returned an unexpected content type.")

                content_encoding = (
                    response.headers.get("content-encoding", "identity").strip().lower()
                )
                if content_encoding not in ("", "identity"):
                    raise NhtsaRecallError("NHTSA returned an unsupported encoding.")

                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise NhtsaRecallError("NHTSA response is too large.")
                    body.extend(chunk)
                status_code = response.status_code
    except (httpx2.HTTPError, TimeoutError):
        raise NhtsaRecallError("NHTSA recalls are unavailable.") from None

    return parse_model_year_response(status_code, bytes(body), model_year)


def merge_model_years(
    model_years: Iterable[int], per_year: dict[int, list[RecallRecord]]
) -> RecallBatch:
    """Combine years; one campaign may be listed for several model years."""
    campaigns: dict[str, RecallRecord] = {}
    listings: dict[str, set[int]] = {}
    for model_year, records in per_year.items():
        for record in records:
            known = campaigns.setdefault(record.campaign_number, record)
            if known.record_sha256 != record.record_sha256:
                raise NhtsaRecallError("NHTSA listed one campaign with conflicting content.")
            listings.setdefault(record.campaign_number, set()).add(model_year)

    return RecallBatch(
        model_years=tuple(sorted(set(model_years))),
        campaigns=campaigns,
        listings={number: frozenset(years) for number, years in listings.items()},
    )


async def fetch_recalls(
    client: httpx2.AsyncClient,
    model_years: Iterable[int],
    *,
    pause_seconds: float = 1.0,
) -> RecallBatch:
    """Fetch every requested year before anything is written; a pause keeps load low."""
    years = sorted(set(model_years))
    per_year: dict[int, list[RecallRecord]] = {}
    for index, model_year in enumerate(years):
        if index:
            await asyncio.sleep(pause_seconds)
        per_year[model_year] = await fetch_model_year(client, model_year)
    return merge_model_years(years, per_year)
