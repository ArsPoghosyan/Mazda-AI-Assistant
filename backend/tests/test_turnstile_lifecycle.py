"""Application-owned Turnstile resources without live HTTP or database access."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.config import Settings
from app.main import create_app


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "turnstile_secret_key": "synthetic-turnstile-secret",
            "turnstile_allowed_hostnames": ("example.test",),
            "turnstile_timeout_seconds": 5,
        }
    )


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    database = MagicMock(spec=AsyncEngine)
    monkeypatch.setattr(
        "app.main.create_database_engine",
        Mock(return_value=database),
    )
    return database


@pytest.fixture
def transport() -> httpx2.MockTransport:
    def reject_network(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("Lifecycle tests must not make network requests.")

    return httpx2.MockTransport(reject_network)


def install_client_factory(
    monkeypatch: pytest.MonkeyPatch,
    factory: Mock,
) -> None:
    monkeypatch.setattr(
        "app.main.httpx2",
        SimpleNamespace(
            AsyncClient=factory,
            Limits=httpx2.Limits,
        ),
    )


def assert_resources_cleared(application: FastAPI) -> None:
    assert application.state.turnstile_client is None
    assert application.state.account_auth_client is None
    assert application.state.account_key_cache is None
    assert application.state.database_engine is None


@pytest.mark.parametrize(
    "updates",
    [
        {"turnstile_secret_key": None},
        {"turnstile_allowed_hostnames": ()},
        {
            "turnstile_secret_key": None,
            "turnstile_allowed_hostnames": (),
        },
    ],
)
def test_incomplete_configuration_creates_no_http_client(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    updates: dict[str, object],
) -> None:
    factory = Mock(side_effect=AssertionError("No HTTP client should be created."))
    install_client_factory(monkeypatch, factory)
    application = create_app(settings.model_copy(update=updates))

    with TestClient(application) as browser:
        assert application.state.turnstile_client is None
        assert browser.get("/api/v1/health").status_code == 200
        engine.dispose.assert_not_awaited()

    factory.assert_not_called()
    engine.dispose.assert_awaited_once()
    assert_resources_cleared(application)


def test_turnstile_without_supabase_starts_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    transport: httpx2.MockTransport,
) -> None:
    http_client = httpx2.AsyncClient(transport=transport, trust_env=False)
    factory = Mock(return_value=http_client)
    install_client_factory(monkeypatch, factory)
    application = create_app(settings)

    with TestClient(application) as browser:
        assert application.state.turnstile_client is http_client
        assert application.state.account_auth_client is None
        assert application.state.account_key_cache is None
        assert not http_client.is_closed

        for _ in range(2):
            assert browser.get("/api/v1/health").status_code == 200
            assert application.state.turnstile_client is http_client

        engine.dispose.assert_not_awaited()

    factory.assert_called_once()
    assert factory.call_args.kwargs["timeout"] == settings.turnstile_timeout_seconds
    assert factory.call_args.kwargs["follow_redirects"] is False
    assert factory.call_args.kwargs["trust_env"] is False
    assert http_client.is_closed
    engine.dispose.assert_awaited_once()
    assert_resources_cleared(application)


def test_supabase_and_turnstile_use_separate_clients(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    transport: httpx2.MockTransport,
) -> None:
    configured = settings.model_copy(
        update={"supabase_auth_issuer": "https://auth.example.test/auth/v1"}
    )
    auth_client = httpx2.AsyncClient(transport=transport, trust_env=False)
    turnstile_client = httpx2.AsyncClient(
        transport=transport,
        trust_env=False,
    )
    factory = Mock(side_effect=[auth_client, turnstile_client])
    install_client_factory(monkeypatch, factory)
    fetcher = AsyncMock()
    monkeypatch.setattr("app.main.fetch_account_key_set", fetcher)
    application = create_app(configured)

    with TestClient(application) as browser:
        assert application.state.account_auth_client is auth_client
        assert application.state.turnstile_client is turnstile_client
        assert isinstance(application.state.account_key_cache, AccountKeyCache)
        assert not auth_client.is_closed
        assert not turnstile_client.is_closed
        assert browser.get("/api/v1/health").status_code == 200
        fetcher.assert_not_awaited()

    assert factory.call_count == 2
    assert auth_client.is_closed
    assert turnstile_client.is_closed
    engine.dispose.assert_awaited_once()
    assert_resources_cleared(application)


def test_turnstile_construction_failure_closes_earlier_resources(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    transport: httpx2.MockTransport,
) -> None:
    configured = settings.model_copy(
        update={"supabase_auth_issuer": "https://auth.example.test/auth/v1"}
    )
    auth_client = httpx2.AsyncClient(transport=transport, trust_env=False)
    factory = Mock(
        side_effect=[
            auth_client,
            RuntimeError("Turnstile client construction failed"),
        ]
    )
    install_client_factory(monkeypatch, factory)
    application = create_app(configured)

    with pytest.raises(RuntimeError, match="Turnstile client construction failed"):
        with TestClient(application):
            pytest.fail("Startup should fail before serving requests.")

    assert factory.call_count == 2
    assert auth_client.is_closed
    engine.dispose.assert_awaited_once()
    assert_resources_cleared(application)


def test_turnstile_cleanup_failure_still_disposes_database(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    transport: httpx2.MockTransport,
) -> None:
    http_client = httpx2.AsyncClient(transport=transport, trust_env=False)
    factory = Mock(return_value=http_client)
    install_client_factory(monkeypatch, factory)
    monkeypatch.setattr(
        transport,
        "aclose",
        AsyncMock(side_effect=RuntimeError("Turnstile cleanup failed")),
    )
    application = create_app(settings)

    with pytest.raises(RuntimeError, match="Turnstile cleanup failed"):
        with TestClient(application) as browser:
            assert browser.get("/api/v1/health").status_code == 200

    assert http_client.is_closed
    engine.dispose.assert_awaited_once()
    assert_resources_cleared(application)
