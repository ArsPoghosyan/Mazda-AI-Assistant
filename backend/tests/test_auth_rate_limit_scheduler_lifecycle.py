"""Application lifespan owns and stops housekeeping before engine disposal."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncEngine

from app import auth_rate_limit_scheduler as scheduler
from app.config import Settings
from app.main import create_app

FUNCTIONS = {
    "limiter": "commit_expired_auth_rate_limit_cleanup",
    "oauth": "commit_expired_oauth_login_attempt_cleanup",
    "guest": "commit_expired_guest_session_cleanup",
    "account": "commit_expired_account_session_cleanup",
}


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def settings(*, enabled: bool) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "turnstile_secret_key": None,
            "auth_rate_limit_cleanup_enabled": enabled,
        }
    )


@pytest.mark.parametrize(("enabled", "has_engine"), [(False, True), (True, False)])
def test_no_task_when_disabled_or_database_is_unconfigured(
    monkeypatch: pytest.MonkeyPatch, enabled: bool, has_engine: bool
) -> None:
    engine = MagicMock(spec=AsyncEngine) if has_engine else None
    monkeypatch.setattr("app.main.create_database_engine", Mock(return_value=engine))
    spawn = Mock(side_effect=AssertionError("No task expected."))
    monkeypatch.setattr(scheduler, "create_task", spawn)
    application = create_app(settings(enabled=enabled))
    with TestClient(application) as browser:
        assert browser.get("/api/v1/health").status_code == 200
    spawn.assert_not_called()
    assert application.state.database_engine is None
    if engine is not None:
        engine.dispose.assert_awaited_once()


@pytest.mark.parametrize("phase", ["waiting", "limiter", "oauth", "guest", "account"])
def test_shutdown_cancels_scheduling_before_disposing_engine(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    events: list[str] = []
    entered = asyncio.Event()
    engine = MagicMock(spec=AsyncEngine)

    async def dispose() -> None:
        events.append("engine-disposed")

    engine.dispose.side_effect = dispose
    monkeypatch.setattr("app.main.create_database_engine", Mock(return_value=engine))

    async def pending() -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            events.append("cleanup-stopped")

    async def wait(interval: int) -> None:
        assert interval == 300
        if phase == "waiting":
            await pending()

    async def batch(*args: object, **kwargs: object) -> int:
        await pending()
        return 0

    helpers = {
        name: AsyncMock(side_effect=batch if phase == name else None, return_value=0)
        for name in FUNCTIONS
    }
    monkeypatch.setattr(scheduler, "sleep", wait)
    for name, helper in helpers.items():
        monkeypatch.setattr(scheduler, FUNCTIONS[name], helper)
    application = create_app(settings(enabled=True))

    async def ready() -> None:
        await asyncio.wait_for(entered.wait(), 2)

    with TestClient(application) as browser:
        assert browser.portal is not None
        browser.portal.call(ready)
        assert browser.get("/api/v1/health").status_code == 200
        engine.dispose.assert_not_awaited()
    assert events == ["cleanup-stopped", "engine-disposed"]
    assert application.state.database_engine is None
    phases = ["waiting", *FUNCTIONS]
    for name, helper in helpers.items():
        if phases.index(name) <= phases.index(phase):
            helper.assert_awaited_once_with(engine, batch_size=100, timeout_seconds=5)
        else:
            helper.assert_not_awaited()


@pytest.mark.parametrize("operation", ["limiter", "oauth", "guest", "account"])
def test_cleanup_failure_does_not_stop_health_or_shutdown(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, operation: str
) -> None:
    engine = MagicMock(spec=AsyncEngine)
    monkeypatch.setattr("app.main.create_database_engine", Mock(return_value=engine))
    completed = asyncio.Event()
    waits = 0

    async def wait(interval: int) -> None:
        nonlocal waits
        waits += 1
        if waits > 1:
            completed.set()
            await asyncio.Event().wait()

    helpers = {name: AsyncMock(return_value=0) for name in FUNCTIONS}
    failed = helpers[operation]
    failed.side_effect = RuntimeError("private-database-detail")
    monkeypatch.setattr(scheduler, "sleep", wait)
    for name, helper in helpers.items():
        monkeypatch.setattr(scheduler, FUNCTIONS[name], helper)

    async def ready() -> None:
        await asyncio.wait_for(completed.wait(), 2)

    with TestClient(create_app(settings(enabled=True))) as browser:
        assert browser.portal is not None
        browser.portal.call(ready)
        assert browser.get("/api/v1/health").status_code == 200
        for helper in helpers.values():
            helper.assert_awaited_once()
    engine.dispose.assert_awaited_once()
    assert "private-database-detail" not in caplog.text
