"""Offline tests for the complete account-token authentication flow."""

import asyncio
from base64 import urlsafe_b64encode
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_auth import (
    AccountAuthenticationUnavailable,
    authenticate_account_token,
)
from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_tokens import InvalidAccountToken, VerifiedAccount
from app.config import Settings

pytestmark = pytest.mark.anyio

ISSUER = "https://auth.example.test/auth/v1"
KEY_ID = "current-key"
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
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
def token(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> SecretStr:
    return SecretStr(
        jwt.encode(
            claims,
            signing_key,
            algorithm="ES256",
            headers={"kid": KEY_ID},
        )
    )


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


async def test_authenticates_and_reuses_cached_keys(
    settings: Settings,
    token: SecretStr,
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    first = await authenticate_account_token(token, settings=settings, key_cache=cache)
    second = await authenticate_account_token(token, settings=settings, key_cache=cache)

    assert first == VerifiedAccount(
        user_id=USER_ID,
        session_id=SESSION_ID,
        assurance_level="aal1",
    )
    assert second == first
    download.assert_awaited_once()


@pytest.mark.parametrize("raw_token", ["", "not-a-token", "a.b.c"])
async def test_malformed_tokens_do_not_download_keys(
    settings: Settings,
    cache: AccountKeyCache,
    download: AsyncMock,
    raw_token: str,
) -> None:
    with pytest.raises(InvalidAccountToken):
        await authenticate_account_token(SecretStr(raw_token), settings=settings, key_cache=cache)

    download.assert_not_awaited()


async def test_unsupported_algorithm_does_not_download_keys(
    settings: Settings,
    claims: dict[str, object],
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    unsupported = jwt.encode(
        claims,
        "test-only-hmac-key-" * 3,
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )

    with pytest.raises(InvalidAccountToken):
        await authenticate_account_token(SecretStr(unsupported), settings=settings, key_cache=cache)

    download.assert_not_awaited()


async def test_unknown_key_is_invalid_credentials(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    unknown = jwt.encode(
        claims,
        signing_key,
        algorithm="ES256",
        headers={"kid": "unknown-key"},
    )

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        await authenticate_account_token(SecretStr(unknown), settings=settings, key_cache=cache)

    download.assert_awaited_once()


@pytest.mark.parametrize(
    ("claim_name", "incorrect_value"),
    [
        ("exp", 0),
        ("iss", "https://other.example.test/auth/v1"),
        ("aud", "another-application"),
        ("role", "service_role"),
        ("is_anonymous", True),
    ],
)
async def test_rejects_invalid_identity_claims(
    settings: Settings,
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    cache: AccountKeyCache,
    claim_name: str,
    incorrect_value: object,
) -> None:
    claims[claim_name] = incorrect_value
    invalid = jwt.encode(
        claims,
        signing_key,
        algorithm="ES256",
        headers={"kid": KEY_ID},
    )

    with pytest.raises(InvalidAccountToken):
        await authenticate_account_token(SecretStr(invalid), settings=settings, key_cache=cache)


async def test_rejects_signature_from_another_key(
    settings: Settings,
    claims: dict[str, object],
    cache: AccountKeyCache,
) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1())
    forged = jwt.encode(
        claims,
        other_key,
        algorithm="ES256",
        headers={"kid": KEY_ID},
    )

    with pytest.raises(InvalidAccountToken):
        await authenticate_account_token(SecretStr(forged), settings=settings, key_cache=cache)


async def test_fetch_failure_is_unavailability_not_invalid_credentials(
    settings: Settings,
    token: SecretStr,
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    download.side_effect = AccountKeyFetchError("Private provider details")

    with pytest.raises(AccountAuthenticationUnavailable) as caught:
        await authenticate_account_token(token, settings=settings, key_cache=cache)

    assert str(caught.value) == "Account authentication is unavailable."


async def test_malformed_key_set_is_unavailability(
    settings: Settings,
    token: SecretStr,
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    download.return_value = {"keys": [None]}

    with pytest.raises(AccountAuthenticationUnavailable):
        await authenticate_account_token(token, settings=settings, key_cache=cache)


@pytest.mark.parametrize("missing", ["issuer", "cache"])
async def test_missing_configuration_does_not_download_keys(
    settings: Settings,
    token: SecretStr,
    cache: AccountKeyCache,
    download: AsyncMock,
    missing: str,
) -> None:
    selected_cache: AccountKeyCache | None = cache

    if missing == "issuer":
        settings = settings.model_copy(update={"supabase_auth_issuer": None})
    else:
        selected_cache = None

    with pytest.raises(AccountAuthenticationUnavailable):
        await authenticate_account_token(token, settings=settings, key_cache=selected_cache)

    download.assert_not_awaited()


async def test_cancellation_propagates(
    settings: Settings,
    token: SecretStr,
    cache: AccountKeyCache,
    download: AsyncMock,
) -> None:
    download.side_effect = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await authenticate_account_token(token, settings=settings, key_cache=cache)
