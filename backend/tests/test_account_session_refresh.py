"""Stored refresh guards without database or live provider requests."""

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

import app.account_session_refresh as session_refresh
from app.account_key_cache import AccountKeyCache
from app.account_refresh import (
    AccountRefreshRejected,
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
)
from app.account_session_auth import LockedAccountSession
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings

pytestmark = pytest.mark.anyio


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class RefreshMaterial:
    settings: Settings
    session: LockedAccountSession
    cipher: AccountTokenCipher
    cache: AccountKeyCache | None
    download: AsyncMock


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material() -> RefreshMaterial:
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    cipher = AccountTokenCipher(encryption_key)
    now = datetime.now(UTC)

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_audience": "authenticated",
            "supabase_auth_publishable_key": ("sb_publishable_synthetic_test_key"),
            "account_session_encryption_key": encryption_key,
        }
    )
    session = LockedAccountSession(
        session_id=uuid4(),
        user_id=uuid4(),
        provider_session_id=uuid4(),
        access_token_ciphertext=cipher.encrypt(SecretStr("synthetic-old-access")),
        refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-stored-refresh")),
        access_token_expires_at=now - timedelta(seconds=1),
        last_seen_at=now - timedelta(days=1),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
        checked_at=now,
    )
    download = AsyncMock(side_effect=AssertionError("Unexpected signing-key download"))

    return RefreshMaterial(
        settings=settings,
        session=session,
        cipher=cipher,
        cache=AccountKeyCache(download),
        download=download,
    )


@pytest.fixture
def exchange(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mocked = AsyncMock(side_effect=AssertionError("Unexpected provider refresh"))
    monkeypatch.setattr(
        session_refresh,
        "refresh_account_tokens",
        mocked,
    )
    return mocked


async def assert_unavailable_without_provider_call(
    material: RefreshMaterial,
    exchange: AsyncMock,
) -> None:
    client = Mock(spec=httpx2.AsyncClient)

    with pytest.raises(AccountRefreshUnavailable) as caught:
        await session_refresh.refresh_locked_account_tokens(
            material.session,
            settings=material.settings,
            client=cast(httpx2.AsyncClient, client),
            key_cache=material.cache,
        )

    assert str(caught.value) == "Account refresh is unavailable."
    exchange.assert_not_awaited()
    material.download.assert_not_awaited()
    assert client.mock_calls == []


@pytest.mark.parametrize(
    "field",
    [
        "account_session_encryption_key",
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
    ],
)
async def test_missing_configuration_prevents_provider_call(
    material: RefreshMaterial,
    exchange: AsyncMock,
    field: str,
) -> None:
    settings = material.settings.model_copy(update={field: None})

    await assert_unavailable_without_provider_call(
        replace(material, settings=settings),
        exchange,
    )


async def test_missing_key_cache_prevents_provider_call(
    material: RefreshMaterial,
    exchange: AsyncMock,
) -> None:
    await assert_unavailable_without_provider_call(
        replace(material, cache=None),
        exchange,
    )


@pytest.mark.parametrize(
    "ciphertext",
    [b"", b"not-a-fernet-token", b"x" * 12289],
)
async def test_unreadable_refresh_credentials_prevent_provider_call(
    material: RefreshMaterial,
    exchange: AsyncMock,
    ciphertext: bytes,
) -> None:
    session = replace(
        material.session,
        refresh_token_ciphertext=ciphertext,
    )

    await assert_unavailable_without_provider_call(
        replace(material, session=session),
        exchange,
    )


async def test_wrong_encryption_key_prevents_provider_call(
    material: RefreshMaterial,
    exchange: AsyncMock,
) -> None:
    settings = material.settings.model_copy(
        update={"account_session_encryption_key": SecretStr(Fernet.generate_key().decode("ascii"))}
    )

    await assert_unavailable_without_provider_call(
        replace(material, settings=settings),
        exchange,
    )


@pytest.mark.parametrize(
    "plaintext",
    [
        "refresh token",
        "refresh\ttoken",
        "refresh\ntoken",
    ],
)
async def test_malformed_decrypted_credentials_prevent_provider_call(
    material: RefreshMaterial,
    exchange: AsyncMock,
    plaintext: str,
) -> None:
    session = replace(
        material.session,
        refresh_token_ciphertext=material.cipher.encrypt(SecretStr(plaintext)),
    )

    await assert_unavailable_without_provider_call(
        replace(material, session=session),
        exchange,
    )


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


def make_refreshed_tokens(
    material: RefreshMaterial,
    *,
    claim_overrides: dict[str, object] | None = None,
) -> RefreshedAccountTokens:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    now = int(datetime.now(UTC).timestamp())

    claims: dict[str, object] = {
        "iss": str(material.settings.supabase_auth_issuer),
        "aud": material.settings.supabase_auth_audience,
        "iat": now - 1,
        "exp": now + 300,
        "sub": str(material.session.user_id),
        "session_id": str(material.session.provider_session_id),
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }
    if claim_overrides is not None:
        claims.update(claim_overrides)

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": "locked-refresh-test-key",
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )
    material.download.side_effect = None
    material.download.return_value = {"keys": [public_jwk]}

    return RefreshedAccountTokens(
        access_token=SecretStr(
            jwt.encode(
                claims,
                signing_key,
                algorithm="ES256",
                headers={"kid": "locked-refresh-test-key"},
            )
        ),
        refresh_token=SecretStr("synthetic-replacement-refresh"),
    )


def refreshed_response(
    tokens: RefreshedAccountTokens,
) -> httpx2.Response:
    payload = {
        "access_token": tokens.access_token.get_secret_value(),
        "refresh_token": tokens.refresh_token.get_secret_value(),
        "token_type": "bearer",
        # This deliberately differs from the signed account identity.
        "user": {"id": str(uuid4())},
    }
    return httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


async def test_exchanges_stored_refresh_and_verifies_signed_identity(
    material: RefreshMaterial,
) -> None:
    tokens = make_refreshed_tokens(material)
    response = refreshed_response(tokens)
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        trust_env=False,
    ) as client:
        result = await session_refresh.refresh_locked_account_tokens(
            material.session,
            settings=material.settings,
            client=client,
            key_cache=material.cache,
        )

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == (
        f"{material.settings.supabase_auth_issuer}/token?grant_type=refresh_token"
    )

    stored_refresh = material.cipher.decrypt(material.session.refresh_token_ciphertext)
    assert json.loads(request.content) == {"refresh_token": stored_refresh.get_secret_value()}

    publishable_key = material.settings.supabase_auth_publishable_key
    assert publishable_key is not None
    assert request.headers["apikey"] == publishable_key.get_secret_value()

    assert result.account.user_id == material.session.user_id
    assert result.account.session_id == material.session.provider_session_id
    assert result.tokens == tokens
    assert tokens.access_token.get_secret_value() not in repr(result)
    assert tokens.refresh_token.get_secret_value() not in repr(result)
    assert response.is_closed
    material.download.assert_awaited_once()


@pytest.mark.parametrize("claim", ["sub", "session_id"])
async def test_rejects_signed_identity_that_differs_from_stored_session(
    material: RefreshMaterial,
    claim: str,
) -> None:
    tokens = make_refreshed_tokens(
        material,
        claim_overrides={claim: str(uuid4())},
    )
    response = refreshed_response(tokens)
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return response

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        trust_env=False,
    ) as client:
        with pytest.raises(AccountRefreshUnavailable) as caught:
            await session_refresh.refresh_locked_account_tokens(
                material.session,
                settings=material.settings,
                client=client,
                key_cache=material.cache,
            )

    assert str(caught.value) == "Account refresh is unavailable."
    assert len(requests) == 1
    assert response.is_closed
    material.download.assert_awaited_once()


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("rejected", AccountRefreshRejected),
        ("server-error", AccountRefreshUnavailable),
        ("rate-limited", AccountRefreshUnavailable),
        ("timeout", AccountRefreshUnavailable),
        ("cancelled", asyncio.CancelledError),
    ],
)
async def test_provider_failures_propagate_without_retries(
    material: RefreshMaterial,
    failure: str,
    expected_error: type[BaseException],
) -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)

        if failure == "timeout":
            raise httpx2.ReadTimeout(
                "Synthetic provider timeout",
                request=request,
            )
        if failure == "cancelled":
            raise asyncio.CancelledError()

        if failure == "rejected":
            status = 400
            payload = {"error_code": "refresh_token_not_found"}
        elif failure == "rate-limited":
            status = 429
            payload = {"error_code": "over_request_rate_limit"}
        else:
            status = 503
            payload = {"error_code": "unexpected_failure"}

        return httpx2.Response(
            status,
            headers={"Content-Type": "application/json"},
            stream=ResponseStream(json.dumps(payload).encode("utf-8")),
        )

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        trust_env=False,
    ) as client:
        with pytest.raises(expected_error):
            await session_refresh.refresh_locked_account_tokens(
                material.session,
                settings=material.settings,
                client=client,
                key_cache=material.cache,
            )

    assert len(requests) == 1
    material.download.assert_not_awaited()
