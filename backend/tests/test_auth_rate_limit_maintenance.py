"""Target guards, lifecycle and private CLI output for local maintenance."""

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.pool import NullPool

from app import auth_rate_limit_maintenance as maintenance
from app.config import Settings

CANARY = "synthetic-private-database-value"


def settings_for(**changes: object) -> Settings:
    parameters: dict[str, object] = {
        "drivername": "postgresql+psycopg",
        "username": "askm6_app",
        "password": CANARY,
        "host": "127.0.0.1",
        "port": 15432,
        "database": "mazda6",
    }
    parameters.update(changes)
    url = URL.create(**parameters)  # type: ignore[arg-type]
    # No .env reads: only the database setting participates in this command.
    return Settings.model_construct(
        database_url=SecretStr(url.render_as_string(hide_password=False))
    )


@dataclass
class MaintenanceCase:
    settings: Settings
    engine: MagicMock
    connection: MagicMock
    result: MagicMock
    factory: MagicMock
    deleter: AsyncMock
    events: list[str]


@pytest.fixture
def case(monkeypatch: pytest.MonkeyPatch) -> MaintenanceCase:
    events: list[str] = []
    engine = MagicMock(spec=AsyncEngine)
    connection = MagicMock(spec=AsyncConnection)
    result = MagicMock()
    result.one.return_value = ("mazda6", "askm6_app", True)

    @asynccontextmanager
    async def connect() -> AsyncIterator[AsyncConnection]:
        events.append("connect")
        try:
            yield cast(AsyncConnection, connection)
        finally:
            events.append("release")

    async def preflight(*args: object, **kwargs: object) -> MagicMock:
        events.append("identity")
        return result

    async def delete_batch(*args: object, **kwargs: object) -> int:
        events.append("cleanup")
        return 3

    async def dispose() -> None:
        events.append("dispose")

    engine.connect.side_effect = connect
    engine.dispose = AsyncMock(side_effect=dispose)
    connection.execute = AsyncMock(side_effect=preflight)
    factory = MagicMock(return_value=engine)
    deleter = AsyncMock(side_effect=delete_batch)
    monkeypatch.setattr(maintenance, "create_async_engine", factory)
    monkeypatch.setattr(maintenance, "commit_expired_auth_rate_limit_cleanup", deleter)
    return MaintenanceCase(settings_for(), engine, connection, result, factory, deleter, events)


@pytest.mark.parametrize(
    "changes",
    [
        {"drivername": "postgresql"},
        {"drivername": "postgresql+asyncpg"},
        {"host": "db.example.test"},
        {"host": "localhost"},
        {"host": "::1"},
        {"host": None},
        {"port": None},
        {"port": 5432},
        {"database": "postgres"},
        {"database": None},
        {"username": "mazda6_admin"},
        {"username": "askm6_migrator"},
        {"username": None},
        {"query": {"hostaddr": "198.51.100.25"}},
        {"query": {"service": "other-database"}},
        {"query": {"options": "-c role=mazda6_admin"}},
    ],
)
def test_unsafe_url_is_rejected_before_engine_creation(
    case: MaintenanceCase, changes: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match="restricted local database target"):
        asyncio.run(
            maintenance.cleanup_local(settings_for(**changes), batch_size=100, timeout_seconds=5)
        )
    case.factory.assert_not_called()
    case.deleter.assert_not_called()


@pytest.mark.parametrize("url", [None, CANARY])
def test_missing_or_malformed_url_has_no_database_side_effects(
    case: MaintenanceCase, url: str | None
) -> None:
    settings = Settings.model_construct(database_url=None if url is None else SecretStr(url))
    with pytest.raises((ValueError, SQLAlchemyError)):
        asyncio.run(maintenance.cleanup_local(settings, batch_size=100, timeout_seconds=5))
    case.factory.assert_not_called()


@pytest.mark.parametrize("batch", [0, -1, 1001, True, False, 1.5, "100", None])
def test_bad_batch_is_rejected_before_engine_creation(case: MaintenanceCase, batch: object) -> None:
    with pytest.raises(ValueError, match="Cleanup batch size"):
        asyncio.run(
            maintenance.cleanup_local(case.settings, batch_size=cast(int, batch), timeout_seconds=5)
        )
    case.factory.assert_not_called()


@pytest.mark.parametrize(
    "timeout", [0, -1, 30.01, float("nan"), float("inf"), True, False, "5", None]
)
def test_bad_timeout_is_rejected_before_engine_creation(
    case: MaintenanceCase, timeout: object
) -> None:
    with pytest.raises(ValueError, match="Cleanup timeout"):
        asyncio.run(
            maintenance.cleanup_local(
                case.settings, batch_size=100, timeout_seconds=cast(float, timeout)
            )
        )
    case.factory.assert_not_called()


@pytest.mark.parametrize("database", ["mazda6", "askm6_test"])
def test_target_identity_and_lifecycle_before_committed_count(
    case: MaintenanceCase, monkeypatch: pytest.MonkeyPatch, database: str
) -> None:
    case.result.one.return_value = (database, "askm6_app", True)
    monkeypatch.setenv("PGHOSTADDR", "198.51.100.25")
    assert (
        asyncio.run(
            maintenance.cleanup_local(
                settings_for(database=database), batch_size=7, timeout_seconds=2.5
            )
        )
        == 3
    )
    assert case.events == ["connect", "identity", "release", "cleanup", "dispose"]
    case.deleter.assert_awaited_once_with(case.engine, batch_size=7, timeout_seconds=2.5)
    case.engine.dispose.assert_awaited_once()
    parameters = case.factory.call_args.kwargs
    assert parameters["poolclass"] is NullPool
    assert parameters["hide_parameters"] is True and parameters["echo"] is False
    assert parameters["connect_args"] == {"hostaddr": "127.0.0.1", "connect_timeout": 5}


@pytest.mark.parametrize(
    "identity",
    [
        ("postgres", "askm6_app", True),
        ("mazda6", "mazda6_admin", False),
        ("mazda6", "askm6_app", False),
    ],
)
def test_live_identity_mismatch_disposes_without_cleanup(
    case: MaintenanceCase, identity: tuple[str, str, bool]
) -> None:
    case.result.one.return_value = identity
    with pytest.raises(ValueError, match="Unexpected database identity"):
        asyncio.run(maintenance.cleanup_local(case.settings, batch_size=100, timeout_seconds=5))
    case.deleter.assert_not_called()
    case.engine.dispose.assert_awaited_once()
    assert case.events[-2:] == ["release", "dispose"]


@pytest.mark.parametrize("phase", ["connect", "identity", "cleanup", "dispose"])
def test_database_or_disposal_failure_propagates_without_retry(
    case: MaintenanceCase, phase: str
) -> None:
    failure = SQLAlchemyError(CANARY)
    if phase == "connect":
        case.engine.connect.side_effect = failure
    elif phase == "identity":
        case.connection.execute.side_effect = failure
    elif phase == "cleanup":
        case.deleter.side_effect = failure
    else:
        case.engine.dispose.side_effect = failure
    with pytest.raises(SQLAlchemyError):
        asyncio.run(maintenance.cleanup_local(case.settings, batch_size=100, timeout_seconds=5))
    case.factory.assert_called_once()
    case.engine.dispose.assert_awaited_once()
    assert case.deleter.await_count == (1 if phase in {"cleanup", "dispose"} else 0)


@pytest.mark.parametrize("phase", ["connect", "identity", "cleanup"])
def test_total_deadline_cancels_preflight_or_cleanup_and_disposes(
    case: MaintenanceCase, phase: str
) -> None:
    async def check() -> None:
        cancelled = asyncio.Event()

        async def block(*args: object, **kwargs: object) -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        @asynccontextmanager
        async def connect() -> AsyncIterator[AsyncConnection]:
            await block()
            yield cast(AsyncConnection, case.connection)

        if phase == "connect":
            case.engine.connect.side_effect = connect
        elif phase == "identity":
            case.connection.execute.side_effect = block
        else:
            case.deleter.side_effect = block
        async with asyncio.timeout(2):
            with pytest.raises(TimeoutError):
                await maintenance.cleanup_local(case.settings, batch_size=100, timeout_seconds=0.03)
        assert cancelled.is_set()
        case.engine.dispose.assert_awaited_once()
        assert case.deleter.await_count == (1 if phase == "cleanup" else 0)

    asyncio.run(check())


def test_external_cancellation_is_preserved_and_disposes(case: MaintenanceCase) -> None:
    async def check() -> None:
        entered = asyncio.Event()

        async def block(*args: object, **kwargs: object) -> None:
            entered.set()
            await asyncio.Event().wait()

        case.deleter.side_effect = block
        task = asyncio.create_task(
            maintenance.cleanup_local(case.settings, batch_size=100, timeout_seconds=5)
        )
        try:
            async with asyncio.timeout(2):
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            case.engine.dispose.assert_awaited_once()
            case.deleter.assert_awaited_once()
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(check())


def cli(monkeypatch: pytest.MonkeyPatch, arguments: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["maintenance", *arguments])
    return maintenance.main()


@pytest.mark.parametrize("arguments", [[], ["--batch-size", "1", "--timeout-seconds", "0.5"]])
def test_cli_prints_only_committed_count(
    case: MaintenanceCase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    monkeypatch.setattr(maintenance, "Settings", MagicMock(return_value=case.settings))
    runner = AsyncMock(return_value=7)
    monkeypatch.setattr(maintenance, "cleanup_local", runner)
    assert cli(monkeypatch, arguments) == 0
    output = capsys.readouterr()
    assert output.out == "Cleanup committed: 7 expired rows deleted.\n" and output.err == ""
    runner.assert_awaited_once_with(
        case.settings, batch_size=1 if arguments else 100, timeout_seconds=0.5 if arguments else 5
    )
    case.factory.assert_not_called()


@pytest.mark.parametrize(
    "error", [SQLAlchemyError, TimeoutError, ValueError, RuntimeError, OSError]
)
def test_cli_masks_failures_and_reports_uncertain_outcome(
    case: MaintenanceCase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: type[Exception],
) -> None:
    monkeypatch.setattr(maintenance, "Settings", MagicMock(return_value=case.settings))
    runner = AsyncMock(side_effect=error(CANARY))
    monkeypatch.setattr(maintenance, "cleanup_local", runner)
    assert cli(monkeypatch, []) == 1
    output = capsys.readouterr()
    assert output.out == "" and "uncertain outcome" in output.err
    assert CANARY not in output.err and "Traceback" not in output.err
    runner.assert_awaited_once()


@pytest.mark.parametrize("interrupt", [False, True])
def test_cli_configuration_failure_or_keyboard_interrupt_does_not_run_cleanup(
    case: MaintenanceCase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    interrupt: bool,
) -> None:
    failure = KeyboardInterrupt(CANARY) if interrupt else ValueError(CANARY)
    monkeypatch.setattr(maintenance, "Settings", MagicMock(side_effect=failure))
    runner = AsyncMock()
    monkeypatch.setattr(maintenance, "cleanup_local", runner)
    assert cli(monkeypatch, []) == (130 if interrupt else 1)
    output = capsys.readouterr()
    assert output.out == "" and "uncertain" in output.err and CANARY not in output.err
    runner.assert_not_called()
    case.factory.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--batch-size", "0"],
        ["--batch-size", "1001"],
        ["--batch-size", "nan"],
        ["--timeout-seconds", "0"],
        ["--timeout-seconds", "-1"],
        ["--timeout-seconds", "31"],
        ["--timeout-seconds", "nan"],
        ["--timeout-seconds", "inf"],
        ["--unknown"],
        ["extra"],
    ],
)
def test_cli_rejects_bad_arguments_before_loading_private_settings(
    case: MaintenanceCase, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    settings = MagicMock(return_value=case.settings)
    monkeypatch.setattr(maintenance, "Settings", settings)
    with pytest.raises(SystemExit) as error:
        cli(monkeypatch, arguments)
    assert error.value.code == 2
    settings.assert_not_called()
    case.factory.assert_not_called()


def test_cli_help_does_not_load_settings_or_connect(
    case: MaintenanceCase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = MagicMock(return_value=case.settings)
    monkeypatch.setattr(maintenance, "Settings", settings)
    with pytest.raises(SystemExit) as error:
        cli(monkeypatch, ["--help"])
    assert error.value.code == 0
    assert "--batch-size" in capsys.readouterr().out
    settings.assert_not_called()
    case.factory.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [["--database-url", CANARY], ["--batch-size", CANARY], ["--timeout-seconds", CANARY]],
)
def test_cli_argument_errors_do_not_echo_potential_credentials(
    case: MaintenanceCase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    settings = MagicMock(return_value=case.settings)
    monkeypatch.setattr(maintenance, "Settings", settings)
    with pytest.raises(SystemExit) as error:
        cli(monkeypatch, arguments)
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == "" and "Invalid maintenance arguments" in output.err
    assert CANARY not in output.err and "Traceback" not in output.err
    settings.assert_not_called()
    case.factory.assert_not_called()


def test_module_help_runs_in_a_fresh_process_without_private_configuration() -> None:
    environment = dict(os.environ)
    environment["DATABASE_URL"] = CANARY
    environment["AUTH_RATE_LIMIT_HMAC_SECRET"] = CANARY
    result = subprocess.run(
        [sys.executable, "-m", "app.auth_rate_limit_maintenance", "--help"],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and result.stderr == ""
    assert "--batch-size" in result.stdout and CANARY not in result.stdout
    assert "recovery/sign-in/sign-up" in result.stdout
