"""NHTSA recall fetching and validation, using recorded responses and no network."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import date
from pathlib import Path

import httpx2
import pytest

from app.nhtsa_recalls import (
    NhtsaRecallError,
    RecallRecord,
    fetch_model_year,
    fetch_recalls,
    fingerprint,
    merge_model_years,
    parse_model_year_response,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nhtsa"
BODY_2018 = (FIXTURES / "recalls_mazda6_2018.json").read_bytes()
BODY_2019 = (FIXTURES / "recalls_mazda6_2019.json").read_bytes()
BODY_EMPTY = (FIXTURES / "recalls_mazda6_2021_http400.json").read_bytes()
EXPECTED_URL = (
    "https://api.nhtsa.gov/recalls/recallsByVehicle?make=MAZDA&model=MAZDA6&modelYear={year}"
)


class ResponseStream(httpx2.AsyncByteStream):
    """Provide a response body in small chunks."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for offset in range(0, len(self.body), 4096):
            yield self.body[offset : offset + 4096]


def make_response(
    body: bytes,
    *,
    status_code: int = 200,
    content_type: str = "application/json;charset=UTF-8",
    encoding: str = "identity",
) -> httpx2.Response:
    return httpx2.Response(
        status_code,
        headers={"Content-Type": content_type, "Content-Encoding": encoding},
        stream=ResponseStream(body),
    )


def run_fetch(
    handler: Callable[[httpx2.Request], httpx2.Response], model_year: int = 2018
) -> list[RecallRecord]:
    async def fetch() -> list[RecallRecord]:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), trust_env=False
        ) as client:
            return await fetch_model_year(client, model_year)

    return asyncio.run(fetch())


def first_record(**changes: object) -> bytes:
    """The 2018 fixture with its first record edited."""
    payload = json.loads(BODY_2018)
    payload["results"] = [{**payload["results"][0], **changes}]
    payload["Count"] = 1
    return json.dumps(payload).encode()


def test_fetch_requests_only_the_fixed_nhtsa_url() -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return make_response(BODY_2018)

    run_fetch(handler)
    (request,) = requests
    assert request.method == "GET"
    assert str(request.url) == EXPECTED_URL.format(year=2018)
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers


def test_recorded_2018_response_is_cleaned() -> None:
    records = run_fetch(lambda request: make_response(BODY_2018))
    assert [record.campaign_number for record in records] == ["21V875000", "19V497000"]
    fuel_pump, stall = records
    # Day/month/year: 12/11/2021 is 12 November, 27/06/2019 is 27 June.
    assert fuel_pump.report_received_on == date(2021, 11, 12)
    assert stall.report_received_on == date(2019, 6, 27)
    assert stall.component == "ENGINE"
    assert "  " not in stall.remedy
    assert stall.remedy.startswith("Mazda will notify owners, and dealers will reprogram")
    assert (stall.park_it, stall.park_outside, stall.over_the_air_update) == (False,) * 3
    assert len(stall.record_sha256) == 32


def test_http_400_with_zero_results_means_an_empty_model_year() -> None:
    assert run_fetch(lambda request: make_response(BODY_EMPTY, status_code=400), 2021) == []


def test_http_400_with_results_is_an_error() -> None:
    with pytest.raises(NhtsaRecallError, match="rejected"):
        run_fetch(lambda request: make_response(BODY_2018, status_code=400))


@pytest.mark.parametrize(
    "response",
    [
        make_response(BODY_2018, status_code=500),
        make_response(b"", status_code=301),
        make_response(BODY_2018, content_type="text/html"),
        make_response(BODY_2018, encoding="gzip"),
        make_response(b"[" * (256 * 1024 + 1)),
        make_response(b"not json"),
        make_response(b'{"Count": 0, "Message": "ok"}'),
        make_response(b'{"Count": 1, "Message": "ok", "results": []}'),
    ],
    ids=[
        "server-error",
        "redirect",
        "content-type",
        "encoding",
        "oversized",
        "invalid-json",
        "missing-results",
        "count-mismatch",
    ],
)
def test_untrustworthy_responses_are_rejected(response: httpx2.Response) -> None:
    with pytest.raises(NhtsaRecallError):
        run_fetch(lambda request: response)


def test_network_failure_is_reported_safely() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ReadTimeout("timed out", request=request)

    with pytest.raises(NhtsaRecallError, match="unavailable"):
        run_fetch(handler)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"Model": "MAZDA3"}, "different vehicle"),
        ({"ModelYear": "2019"}, "different vehicle"),
        ({"Make": "Mazda"}, "different vehicle"),
        ({"NHTSACampaignNumber": "19E497000"}, "campaign number"),
        ({"ReportReceivedDate": "2019-06-27"}, "date format"),
        ({"ReportReceivedDate": "31/02/2019"}, "invalid report date"),
        ({"ReportReceivedDate": "01/01/2999"}, "implausible"),
        ({"Summary": "   "}, "empty summary"),
        ({"Summary": "Hidden​character"}, "control characters"),
        ({"Remedy": "x" * 2001}, "too long"),
        ({"parkIt": "false"}, "expected format"),
        ({"Unexpected": "field"}, "expected format"),
    ],
)
def test_invalid_records_are_rejected(changes: dict[str, object], message: str) -> None:
    with pytest.raises(NhtsaRecallError, match=message):
        parse_model_year_response(200, first_record(**changes), 2018)


def test_missing_field_is_rejected() -> None:
    payload = json.loads(BODY_2018)
    del payload["results"][0]["parkIt"]
    with pytest.raises(NhtsaRecallError, match="expected format"):
        parse_model_year_response(200, json.dumps(payload).encode(), 2018)


def test_whitespace_is_collapsed_and_empty_notes_become_none() -> None:
    (record,) = parse_model_year_response(
        200, first_record(Summary="Line one\r\n\tline  two", Notes=""), 2018
    )
    assert record.summary == "Line one line two"
    assert record.notes is None


def test_fingerprint_follows_content_not_model_year() -> None:
    (from_2018,) = [
        record
        for record in parse_model_year_response(200, BODY_2018, 2018)
        if record.campaign_number == "19V497000"
    ]
    (from_2019,) = parse_model_year_response(200, BODY_2019, 2019)
    assert from_2018.record_sha256 == from_2019.record_sha256

    edited = replace(from_2018, remedy=from_2018.remedy + " Updated.")
    assert fingerprint(edited) != from_2018.record_sha256


def test_one_campaign_listed_for_two_years_is_merged() -> None:
    batch = merge_model_years(
        [2018, 2019, 2020],
        {
            2018: parse_model_year_response(200, BODY_2018, 2018),
            2019: parse_model_year_response(200, BODY_2019, 2019),
            2020: [],
        },
    )
    assert sorted(batch.campaigns) == ["19V497000", "21V875000"]
    assert batch.listings == {
        "19V497000": frozenset({2018, 2019}),
        "21V875000": frozenset({2018}),
    }
    assert batch.empty_years == (2020,)


def test_conflicting_content_for_one_campaign_is_rejected() -> None:
    (original,) = parse_model_year_response(200, BODY_2019, 2019)
    conflicting = replace(original, record_sha256=bytes(32))
    with pytest.raises(NhtsaRecallError, match="conflicting"):
        merge_model_years([2018, 2019], {2018: [conflicting], 2019: [original]})


def test_fetch_recalls_requests_each_year_once_in_order() -> None:
    bodies = {
        "2018": (200, BODY_2018),
        "2019": (200, BODY_2019),
        "2020": (400, BODY_EMPTY),
        "2021": (400, BODY_EMPTY),
    }
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        year = request.url.params["modelYear"]
        seen.append(year)
        status, body = bodies[year]
        return make_response(body, status_code=status)

    async def fetch() -> object:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), trust_env=False
        ) as client:
            return await fetch_recalls(client, [2021, 2018, 2019, 2020, 2018], pause_seconds=0)

    batch = asyncio.run(fetch())
    assert seen == ["2018", "2019", "2020", "2021"]
    assert batch.empty_years == (2020, 2021)  # type: ignore[attr-defined]


def test_unsupported_model_year_is_not_requested() -> None:
    with pytest.raises(ValueError):
        run_fetch(lambda request: make_response(BODY_2018), 2017)
