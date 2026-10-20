"""Refresh identity verification with generated keys and mocked provider I/O."""

import json
from base64 import urlsafe_b64encode
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_refresh import (
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
    refresh_account_tokens,
)
from app.account_refresh_verification import verify_refreshed_account_tokens
from app.config import Settings

pytestmark = pytest.mark.anyio

ISSUER = "https://auth.example.test/auth/v1"
KEY_ID = "refresh-test-key"
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
OTHER_ID = UUID("33333333-3333-4333-8333-333333333333")
REFRESH_TOKEN = "synthetic-replacement-refresh"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
        }
    )


@pytest.fixture
def signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def claims() -> dict[str, object]:
    now = int(datetime.now(UTC).timestamp())
    return {
        "iss": ISSUER,
        "aud": "authenticated",
        "iat": now - 1,
        "exp": now + 300,
        "sub": str(USER_ID),
        "session_id": str(SESSION_ID),
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }


@pytest.fixture
def download(signing_key: ec.EllipticCurvePrivateKey) -> AsyncMock:
    numbers = signing_key.public_key().public_numbers()
    return AsyncMock(
        return_value={
            "keys": [
                {
                    "kid": KEY_ID,
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "x": urlsafe_b64encode(numbers.x.to_bytes(32, "big")).decode().rstrip("="),
                    "y": urlsafe_b64encode(numbers.y.to_bytes(32, "big")).decode().rstrip("="),
                }
            ]
        }
    )


@pytest.fixture
def cache(download: AsyncMock) -> AccountKeyCache:
    return AccountKeyCache(download)


def make_pair(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> RefreshedAccountTokens:
    return RefreshedAccountTokens(
        access_token=SecretStr(
            jwt.encode(
                claims,
                signing_key,
                algorithm="ES256",
                headers={"kid": KEY_ID},
            )
        ),
        refresh_token=SecretStr(REFRESH_TOKEN),
    )


@pytest.mark.parametrize("assurance_level", ["aal1", "aal2"])
async def test_accepts_matching_verified_identity(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    download: AsyncMock,
    assurance_level: str,
) -> None:
    claims["aal"] = assurance_level
    tokens = make_pair(signing_key, claims)

    result = await verify_refreshed_account_tokens(
        tokens,
        expected_user_id=USER_ID,
        expected_provider_session_id=SESSION_ID,
        settings=settings,
        key_cache=cache,
    )

    expiry = claims["exp"]
    assert isinstance(expiry, int)

    assert result.account.user_id == USER_ID
    assert result.account.session_id == SESSION_ID
    assert result.account.assurance_level == assurance_level
    assert result.account.access_token_expires_at == datetime.fromtimestamp(expiry, tz=UTC)
    assert result.tokens is tokens
    assert tokens.access_token.get_secret_value() not in repr(result)
    assert REFRESH_TOKEN not in repr(result)
    download.assert_awaited_once()


@pytest.mark.parametrize(
    ("expected_user", "expected_session"),
    [
        (OTHER_ID, SESSION_ID),
        (USER_ID, OTHER_ID),
        (OTHER_ID, OTHER_ID),
    ],
)
async def test_rejects_identity_mismatches(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    expected_user: UUID,
    expected_session: UUID,
) -> None:
    tokens = make_pair(signing_key, claims)

    with pytest.raises(AccountRefreshUnavailable) as caught:
        await verify_refreshed_account_tokens(
            tokens,
            expected_user_id=expected_user,
            expected_provider_session_id=expected_session,
            settings=settings,
            key_cache=cache,
        )

    assert str(caught.value) == "Account refresh is unavailable."


@pytest.mark.parametrize(
    ("claim_name", "invalid_value"),
    [
        ("exp", 0),
        ("iss", "https://other.example.test/auth/v1"),
        ("aud", "another-application"),
    ],
)
async def test_rejects_invalid_signed_claims(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    claim_name: str,
    invalid_value: object,
) -> None:
    claims[claim_name] = invalid_value
    tokens = make_pair(signing_key, claims)

    with pytest.raises(AccountRefreshUnavailable):
        await verify_refreshed_account_tokens(
            tokens,
            expected_user_id=USER_ID,
            expected_provider_session_id=SESSION_ID,
            settings=settings,
            key_cache=cache,
        )


async def test_rejects_a_forged_signature_even_when_ids_match(
    settings: Settings,
    claims: dict[str, object],
    cache: AccountKeyCache,
) -> None:
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    tokens = make_pair(attacker_key, claims)

    with pytest.raises(AccountRefreshUnavailable):
        await verify_refreshed_account_tokens(
            tokens,
            expected_user_id=USER_ID,
            expected_provider_session_id=SESSION_ID,
            settings=settings,
            key_cache=cache,
        )


async def test_signing_key_failure_hides_provider_details(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    download.side_effect = AccountKeyFetchError("Private provider details")
    tokens = make_pair(signing_key, claims)

    with pytest.raises(AccountRefreshUnavailable) as caught:
        await verify_refreshed_account_tokens(
            tokens,
            expected_user_id=USER_ID,
            expected_provider_session_id=SESSION_ID,
            settings=settings,
            key_cache=cache,
        )

    assert str(caught.value) == "Account refresh is unavailable."
    assert "Private provider details" not in str(caught.value)
    download.assert_awaited_once()


async def test_http_exchange_then_verification_uses_signed_identity(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    tokens = make_pair(signing_key, claims)
    payload = {
        "access_token": tokens.access_token.get_secret_value(),
        "refresh_token": REFRESH_TOKEN,
        "token_type": "bearer",
        # Identity must come from the verified JWT, not this JSON field.
        "user": {"id": str(OTHER_ID)},
    }
    response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        trust_env=False,
    ) as client:
        refreshed = await refresh_account_tokens(
            SecretStr("synthetic-old-refresh"),
            settings=settings,
            client=client,
        )
        result = await verify_refreshed_account_tokens(
            refreshed,
            expected_user_id=USER_ID,
            expected_provider_session_id=SESSION_ID,
            settings=settings,
            key_cache=cache,
        )

    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert str(requests[0].url) == (f"{ISSUER}/token?grant_type=refresh_token")
    assert result.account.user_id == USER_ID
    assert result.account.session_id == SESSION_ID
    assert result.tokens.refresh_token.get_secret_value() == REFRESH_TOKEN
    assert response.is_closed
    download.assert_awaited_once()
