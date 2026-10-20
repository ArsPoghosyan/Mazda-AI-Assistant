"""Application-owned signing-key resources; no live network or database."""

from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_keys import AccountKeyNotFound
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
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_audience": "authenticated",
        }
    )


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    database = MagicMock(spec=AsyncEngine)
    monkeypatch.setattr("app.main.create_database_engine", Mock(return_value=database))
    return database


@pytest.fixture
def transport() -> httpx2.MockTransport:
    def reject_network(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("Lifecycle tests must not make network requests.")

    return httpx2.MockTransport(reject_network)


@pytest.fixture
def http_client(
    monkeypatch: pytest.MonkeyPatch,
    transport: httpx2.MockTransport,
) -> httpx2.AsyncClient:
    client = httpx2.AsyncClient(transport=transport, trust_env=False)
    monkeypatch.setattr("app.main.httpx2.AsyncClient", Mock(return_value=client))
    return client


def test_unconfigured_auth_creates_no_key_resources(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
) -> None:
    factory = Mock(side_effect=AssertionError("Auth client must not be created."))
    fetcher = AsyncMock()
    monkeypatch.setattr("app.main.httpx2.AsyncClient", factory)
    monkeypatch.setattr("app.main.fetch_account_key_set", fetcher)
    application = create_app(settings.model_copy(update={"supabase_auth_issuer": None}))

    with TestClient(application) as client:
        assert application.state.account_key_cache is None
        assert client.get("/api/v1/health").status_code == 200

    factory.assert_not_called()
    fetcher.assert_not_awaited()
    engine.dispose.assert_awaited_once()
    assert application.state.database_engine is None


def test_shared_cache_fetches_lazily_and_resources_close(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    http_client: httpx2.AsyncClient,
) -> None:
    fetcher = AsyncMock(return_value={"keys": []})
    monkeypatch.setattr("app.main.fetch_account_key_set", fetcher)
    application = create_app(settings)

    with TestClient(application) as client:
        cache = cast(AccountKeyCache, application.state.account_key_cache)
        assert isinstance(cache, AccountKeyCache)
        assert not http_client.is_closed
        engine.dispose.assert_not_awaited()

        for _ in range(2):
            assert client.get("/api/v1/health").status_code == 200
            assert application.state.account_key_cache is cache

        fetcher.assert_not_awaited()
        assert client.portal is not None

        for key_id in ("unknown-one", "unknown-two"):
            with pytest.raises(AccountKeyNotFound):
                client.portal.call(cache.get_public_key, key_id)

        fetcher.assert_awaited_once_with(settings, client=http_client)

    assert http_client.is_closed
    engine.dispose.assert_awaited_once()
    assert application.state.account_key_cache is None
    assert application.state.database_engine is None


def test_client_construction_failure_disposes_database(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
) -> None:
    monkeypatch.setattr(
        "app.main.httpx2.AsyncClient",
        Mock(side_effect=RuntimeError("Client construction failed")),
    )
    application = create_app(settings)

    with pytest.raises(RuntimeError, match="Client construction failed"):
        with TestClient(application):
            pytest.fail("Startup should fail before serving requests.")

    engine.dispose.assert_awaited_once()
    assert application.state.account_key_cache is None
    assert application.state.database_engine is None


def test_cache_construction_failure_closes_registered_resources(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    http_client: httpx2.AsyncClient,
) -> None:
    monkeypatch.setattr(
        "app.main.AccountKeyCache",
        Mock(side_effect=RuntimeError("Cache construction failed")),
    )
    application = create_app(settings)

    with pytest.raises(RuntimeError, match="Cache construction failed"):
        with TestClient(application):
            pytest.fail("Startup should fail before serving requests.")

    assert http_client.is_closed
    engine.dispose.assert_awaited_once()
    assert application.state.account_key_cache is None
    assert application.state.database_engine is None


def test_http_cleanup_failure_still_disposes_database_and_clears_state(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    engine: MagicMock,
    transport: httpx2.MockTransport,
    http_client: httpx2.AsyncClient,
) -> None:
    monkeypatch.setattr(
        transport,
        "aclose",
        AsyncMock(side_effect=RuntimeError("HTTP cleanup failed")),
    )
    application = create_app(settings)

    with pytest.raises(RuntimeError, match="HTTP cleanup failed"):
        with TestClient(application) as client:
            assert client.get("/api/v1/health").status_code == 200

    assert http_client.is_closed
    engine.dispose.assert_awaited_once()
    assert application.state.account_key_cache is None
    assert application.state.database_engine is None


def test_database_cleanup_failure_still_closes_http_and_clears_state(
    settings: Settings,
    engine: MagicMock,
    http_client: httpx2.AsyncClient,
) -> None:
    engine.dispose.side_effect = RuntimeError("Database cleanup failed")
    application = create_app(settings)

    with pytest.raises(RuntimeError, match="Database cleanup failed"):
        with TestClient(application) as client:
            assert client.get("/api/v1/health").status_code == 200

    assert http_client.is_closed
    engine.dispose.assert_awaited_once()
    assert application.state.account_key_cache is None
    assert application.state.database_engine is None
