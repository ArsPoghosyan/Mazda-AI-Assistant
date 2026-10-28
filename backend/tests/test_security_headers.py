"""Browser hardening preserves auth semantics and streamed responses."""

from collections.abc import Iterator

import pytest
from fastapi import Response
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from app.config import Settings
from app.main import create_app
from app.security_headers import SECURITY_HEADERS


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(
        IsolatedSettings(
            database_url=None,
            migration_database_url=None,
            supabase_auth_issuer=None,
            csrf_trusted_origins=("https://site.example",),
        )
    )

    @app.get("/stream-fixture")
    def stream() -> StreamingResponse:
        response = StreamingResponse(iter([b"first", b"second"]), media_type="text/plain")
        response.set_cookie("synthetic-one", "one", httponly=True, secure=True)
        response.set_cookie("synthetic-two", "two", httponly=True, secure=True)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/stricter-fixture")
    def stricter() -> Response:
        return Response(headers={"Content-Security-Policy": "default-src 'none'"})

    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize(
    ("method", "path", "origin", "expected"),
    [
        ("GET", "/api/v1/health", None, 200),
        ("GET", "/missing", None, 404),
        ("POST", "/api/v1/health", None, 405),
        ("GET", "/api/v1/account/me", None, 401),
        ("POST", "/api/v1/account/session", "https://evil.example", 403),
        ("POST", "/api/v1/account/session", "https://site.example", 503),
        ("GET", "/api/v1/ready", None, 503),
    ],
)
def test_headers_preserve_status_and_closed_cors(
    client: TestClient, method: str, path: str, origin: str | None, expected: int
) -> None:
    response = client.request(method, path, headers={"Origin": origin} if origin else {})
    assert response.status_code == expected
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert "access-control-allow-origin" not in response.headers
    if expected == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.headers["Cache-Control"] == "no-store"


def test_streaming_and_separate_cookies_are_preserved(client: TestClient) -> None:
    response = client.get("/stream-fixture")
    assert response.content == b"firstsecond"
    assert len(response.headers.get_list("set-cookie")) == 2
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_a_stricter_route_policy_is_preserved(client: TestClient) -> None:
    assert (
        client.get("/stricter-fixture").headers["Content-Security-Policy"] == "default-src 'none'"
    )
