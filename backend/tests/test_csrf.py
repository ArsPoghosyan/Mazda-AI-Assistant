"""Origin validation before state-changing endpoint execution."""

from collections.abc import Iterator
from typing import cast

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from app.config import Settings
from app.csrf import require_trusted_origin


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def client() -> Iterator[TestClient]:
    application = FastAPI()
    application.state.settings = IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        csrf_trusted_origins=(
            "https://askm6.com",
            "http://localhost:5173",
        ),
    )
    application.state.accepted_requests = 0

    @application.api_route(
        "/protected",
        methods=["POST", "PUT", "PATCH", "DELETE"],
        dependencies=[Depends(require_trusted_origin)],
    )
    async def protected_action() -> dict[str, str]:
        application.state.accepted_requests += 1
        return {"status": "ok"}

    with TestClient(application) as test_client:
        yield test_client


@pytest.mark.parametrize(
    "origin",
    [
        "https://askm6.com",
        "http://localhost:5173",
    ],
)
def test_configured_origin_is_accepted(
    client: TestClient,
    origin: str,
) -> None:
    response = client.post("/protected", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert cast(FastAPI, client.app).state.accepted_requests == 1


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "null",
        "*",
        "https://evil.test",
        "https://askm6.com.evil.test",
        "https://evil.test/https://askm6.com",
        "http://askm6.com",
        "https://askm6.com:444",
        "https://askm6.com/",
        "http://127.0.0.1:5173",
    ],
)
def test_untrusted_origin_is_rejected(
    client: TestClient,
    origin: str,
) -> None:
    response = client.post("/protected", headers={"Origin": origin})

    assert response.status_code == 403
    assert response.headers["Cache-Control"] == "no-store"
    assert cast(FastAPI, client.app).state.accepted_requests == 0


def test_missing_origin_is_rejected(client: TestClient) -> None:
    response = client.post("/protected")

    assert response.status_code == 403
    assert cast(FastAPI, client.app).state.accepted_requests == 0


def test_duplicate_origins_are_rejected(client: TestClient) -> None:
    response = client.post(
        "/protected",
        headers=[
            ("Origin", "https://askm6.com"),
            ("Origin", "https://askm6.com"),
        ],
    )

    assert response.status_code == 403
    assert cast(FastAPI, client.app).state.accepted_requests == 0


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_guard_protects_each_state_changing_method(
    client: TestClient,
    method: str,
) -> None:
    response = client.request(
        method,
        "/protected",
        headers={"Origin": "https://evil.test"},
    )

    assert response.status_code == 403
    assert cast(FastAPI, client.app).state.accepted_requests == 0
