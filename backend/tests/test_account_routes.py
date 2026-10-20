"""Account HTTP contracts and generated-token authentication; no live services."""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings
from app.main import create_app

TOKEN = "test-only-account-token"
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


def make_settings(
    issuer: str | None = "https://auth.example.test/auth/v1",
) -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": issuer,
            "supabase_auth_audience": "authenticated",
        }
    )


@dataclass
class AccountAPI:
    client: TestClient
    settings: Settings
    cache: AccountKeyCache
    authenticate: AsyncMock


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> Iterator[AccountAPI]:
    settings = make_settings()
    authenticate = AsyncMock(
        return_value=VerifiedAccount(
            user_id=USER_ID,
            session_id=SESSION_ID,
            assurance_level="aal1",
        )
    )
    fetcher = AsyncMock(side_effect=AssertionError("HTTP contract tests must not fetch keys."))

    monkeypatch.setattr(
        "app.account_routes.authenticate_account_token",
        authenticate,
    )
    monkeypatch.setattr("app.main.fetch_account_key_set", fetcher)

    application = create_app(settings)

    with TestClient(application) as client:
        yield AccountAPI(
            client=client,
            settings=settings,
            cache=cast(AccountKeyCache, application.state.account_key_cache),
            authenticate=authenticate,
        )

    fetcher.assert_not_awaited()


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
def test_returns_only_verified_account_identity(
    api: AccountAPI,
    scheme: str,
) -> None:
    response = api.client.get(
        "/api/v1/account/me",
        headers={"Authorization": f"{scheme} {TOKEN}"},
        params={"user_id": "33333333-3333-4333-8333-333333333333"},
    )

    assert response.status_code == 200
    assert response.json() == {"user_id": str(USER_ID)}
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers

    api.authenticate.assert_awaited_once_with(
        SecretStr(TOKEN),
        settings=api.settings,
        key_cache=api.cache,
    )


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Basic example",
        "Bearer",
        "Bearer ",
        "Bearer    ",
    ],
)
def test_rejects_missing_or_malformed_authorization(
    api: AccountAPI,
    authorization: str | None,
) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}
    response = api.client.get("/api/v1/account/me", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing account credentials."}
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    api.authenticate.assert_not_awaited()


def test_rejects_duplicate_authorization_headers(api: AccountAPI) -> None:
    response = api.client.get(
        "/api/v1/account/me",
        headers=[
            ("Authorization", f"Bearer {TOKEN}"),
            ("Authorization", f"Bearer {TOKEN}"),
        ],
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    api.authenticate.assert_not_awaited()


def test_does_not_accept_tokens_from_query_parameters_or_cookies(
    api: AccountAPI,
) -> None:
    api.client.cookies.set("access_token", TOKEN)
    api.client.cookies.set("askm6_guest", TOKEN)

    response = api.client.get(
        "/api/v1/account/me",
        params={"access_token": TOKEN, "user_id": str(USER_ID)},
    )

    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    api.authenticate.assert_not_awaited()


def test_invalid_token_returns_generic_401(api: AccountAPI) -> None:
    api.authenticate.side_effect = InvalidAccountToken("Private verification details")

    response = api.client.get(
        "/api/v1/account/me",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing account credentials."}
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    assert "Private verification details" not in response.text
    assert TOKEN not in response.text


def test_verification_failure_returns_generic_503(api: AccountAPI) -> None:
    api.authenticate.side_effect = AccountAuthenticationUnavailable("Private provider details")

    response = api.client.get(
        "/api/v1/account/me",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Account authentication is unavailable."}
    assert response.headers["Cache-Control"] == "no-store"
    assert "WWW-Authenticate" not in response.headers
    assert "Private provider details" not in response.text
    assert TOKEN not in response.text


def test_unconfigured_authentication_returns_503() -> None:
    with TestClient(create_app(make_settings(issuer=None))) as client:
        response = client.get(
            "/api/v1/account/me",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "Account authentication is unavailable."}
    assert response.headers["Cache-Control"] == "no-store"


def test_real_authentication_flow_reuses_keys_and_rejects_forged_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = make_settings()
    signing_key = ec.generate_private_key(ec.SECP256R1())
    key_id = "generated-test-key"

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": key_id,
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )

    download = AsyncMock(return_value={"keys": [public_jwk]})
    monkeypatch.setattr("app.main.fetch_account_key_set", download)

    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": str(settings.supabase_auth_issuer),
        "aud": settings.supabase_auth_audience,
        "iat": now - 1,
        "exp": now + 300,
        "sub": str(USER_ID),
        "session_id": str(SESSION_ID),
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }

    valid_token = jwt.encode(
        claims,
        signing_key,
        algorithm="ES256",
        headers={"kid": key_id},
    )
    forged_token = jwt.encode(
        claims,
        ec.generate_private_key(ec.SECP256R1()),
        algorithm="ES256",
        headers={"kid": key_id},
    )

    with TestClient(create_app(settings)) as client:
        download.assert_not_awaited()

        for _ in range(2):
            response = client.get(
                "/api/v1/account/me",
                headers={"Authorization": f"Bearer {valid_token}"},
            )

            assert response.status_code == 200
            assert response.json() == {"user_id": str(USER_ID)}
            assert response.headers["Cache-Control"] == "no-store"

        rejected = client.get(
            "/api/v1/account/me",
            headers={"Authorization": f"Bearer {forged_token}"},
        )

        assert rejected.status_code == 401
        assert rejected.json() == {"detail": "Invalid or missing account credentials."}
        assert rejected.headers["Cache-Control"] == "no-store"

    download.assert_awaited_once()
