"""HTTP contracts and database pool lifecycle tests."""

from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.main import create_app


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def isolated_settings() -> Settings:
    return IsolatedSettings(database_url=None)


def test_health_contract() -> None:
    with TestClient(create_app(isolated_settings())) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "status": "ok",
        "service": "mazda6-assistant-api",
    }


def test_readiness_without_database_configuration() -> None:
    with TestClient(create_app(isolated_settings())) as client:
        response = client.get("/api/v1/ready")

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json() == {
        "status": "unavailable",
        "service": "mazda6-assistant-api",
    }


@pytest.mark.parametrize(
    ("ready", "expected_status"),
    [(True, 200), (False, 503)],
)
def test_readiness_and_pool_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    ready: bool,
    expected_status: int,
) -> None:
    engine = MagicMock(spec=AsyncEngine)
    factory = Mock(return_value=engine)
    probe = AsyncMock(return_value=ready)

    monkeypatch.setattr("app.main.create_database_engine", factory)
    monkeypatch.setattr("app.main.database_is_ready", probe)

    with TestClient(create_app(isolated_settings())) as client:
        response = client.get("/api/v1/ready")
        health = client.get("/api/v1/health")

        assert health.status_code == 200
        engine.dispose.assert_not_awaited()

    assert response.status_code == expected_status
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json() == {
        "status": "ok" if ready else "unavailable",
        "service": "mazda6-assistant-api",
    }
    factory.assert_called_once()
    probe.assert_awaited_once()
    engine.dispose.assert_awaited_once()
