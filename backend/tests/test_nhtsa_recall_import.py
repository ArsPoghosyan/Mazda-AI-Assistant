"""Import command arguments, target guard and output wording."""

from datetime import date

import pytest
from pydantic import SecretStr

from app.nhtsa_recall_import import (
    ImportTargetError,
    describe,
    local_import_target,
    main,
    parse_years,
)
from app.nhtsa_recall_ingestion import IngestionReport
from app.nhtsa_recalls import RecallBatch, RecallRecord

LOCAL = "postgresql+psycopg://askm6_migrator:example@127.0.0.1:15432/mazda6"


@pytest.mark.parametrize(
    ("value", "years"),
    [("2021", (2021,)), ("2018-2021", (2018, 2019, 2020, 2021)), ("2019-2020", (2019, 2020))],
)
def test_years_accept_one_year_or_a_range(value: str, years: tuple[int, ...]) -> None:
    assert parse_years(value) == years


@pytest.mark.parametrize("value", ["2017", "2022", "2021-2018", "2018-2022", "abc", "", "2018-"])
def test_years_outside_the_supported_range_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        parse_years(value)


def test_local_database_is_accepted() -> None:
    assert local_import_target(SecretStr(LOCAL)).database == "mazda6"


@pytest.mark.parametrize(
    "url",
    [
        LOCAL.replace("127.0.0.1", "db.example.supabase.co"),
        LOCAL.replace("15432", "5432"),
        LOCAL.replace("/mazda6", "/postgres"),
        LOCAL.replace("/mazda6", "/askm6_test"),
        LOCAL.replace("askm6_migrator", "askm6_app"),
        LOCAL.replace("askm6_migrator", "mazda6_admin"),
        LOCAL.replace("postgresql+psycopg", "postgresql+asyncpg"),
        LOCAL + "?host=10.0.0.5",
        "not a url",
    ],
    ids=[
        "remote-host",
        "port",
        "database",
        "test-database",
        "app-role",
        "admin",
        "driver",
        "query",
        "invalid",
    ],
)
def test_any_other_database_is_refused(url: str) -> None:
    with pytest.raises(ImportTargetError):
        local_import_target(SecretStr(url))


def test_refusal_message_does_not_echo_credentials() -> None:
    url = LOCAL.replace("127.0.0.1", "db.example.supabase.co").replace("example@", "s3cret@")
    with pytest.raises(ImportTargetError) as caught:
        local_import_target(SecretStr(url))
    assert "s3cret" not in str(caught.value)


def test_command_requires_an_explicit_database_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.setattr("sys.argv", ["nhtsa_recall_import"])
    assert main() == 1
    assert "MIGRATION_DATABASE_URL" in capsys.readouterr().err


def test_command_refuses_a_remote_target_before_any_request(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", LOCAL.replace("127.0.0.1", "db.example.test"))
    monkeypatch.setattr("sys.argv", ["nhtsa_recall_import", "--write"])

    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("The command must not fetch before checking its target.")

    monkeypatch.setattr("app.nhtsa_recall_import.fetch_recalls", no_network)
    assert main() == 1
    assert "local mazda6 database" in capsys.readouterr().err


def make_record(number: str, *, park_it: bool = False) -> RecallRecord:
    return RecallRecord(
        campaign_number=number,
        report_received_on=date(2019, 6, 27),
        manufacturer="Synthetic",
        component="ENGINE",
        summary="Synthetic summary.",
        consequence="Synthetic consequence.",
        remedy="Synthetic remedy.",
        notes=None,
        park_it=park_it,
        park_outside=False,
        over_the_air_update=False,
        record_sha256=bytes(32),
    )


def test_summary_flags_urgent_campaigns_and_never_claims_no_recalls() -> None:
    batch = RecallBatch(
        model_years=(2018, 2021),
        campaigns={"19V000001": make_record("19V000001", park_it=True)},
        listings={"19V000001": frozenset({2018})},
    )
    report = IngestionReport(
        added=1, changed=0, unchanged=0, listings_added=1, not_seen=(("19V000002", 2019),)
    )
    summary = describe(batch, report, database="mazda6", write=False)
    assert "2018: 1, 2021: 0" in summary
    assert "Stored listings not seen this run (kept): 19V000002 (2019)." in summary
    assert "Park-it / park-outside campaigns: 19V000001." in summary
    assert "not proof that no recalls exist" in summary
    assert "nothing saved" in summary
    assert "no recalls." not in summary.lower()


def test_failure_during_commit_is_reported_as_uncertain(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", LOCAL)
    monkeypatch.setattr("sys.argv", ["nhtsa_recall_import", "--write"])

    async def lost_connection(*args: object, **kwargs: object) -> None:
        raise TimeoutError

    monkeypatch.setattr("app.nhtsa_recall_import.run_import", lost_connection)
    assert main() == 1
    error = capsys.readouterr().err
    assert "may or may not have been saved" in error
    assert "Re-run the import to check" in error
