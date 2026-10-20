"""Stored access verification with generated keys and no live services."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_auth import AccountAuthenticationUnavailable
from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_session_auth import (
    LockedAccountSession,
    verify_locked_account_access,
)
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings

pytestmark = pytest.mark.anyio

ISSUER = "https://auth.example.test/auth/v1"
KEY_ID = "stored-access-test-key"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class StoredAccessMaterial:
    settings: Settings
    session: LockedAccountSession
    signing_key: ec.EllipticCurvePrivateKey
    claims: dict[str, object]
    cipher: AccountTokenCipher
    cache: AccountKeyCache
    download: AsyncMock


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def material() -> StoredAccessMaterial:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    cipher = AccountTokenCipher(encryption_key)
    user_id = uuid4()
    provider_session_id = uuid4()
    now = datetime.now(UTC).replace(microsecond=0)
    expiry = now + timedelta(minutes=5)

    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": "authenticated",
        "iat": int(now.timestamp()) - 1,
        "exp": int(expiry.timestamp()),
        "sub": str(user_id),
        "session_id": str(provider_session_id),
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }
    token = SecretStr(
        jwt.encode(
            claims,
            signing_key,
            algorithm="ES256",
            headers={"kid": KEY_ID},
        )
    )

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
            "account_session_encryption_key": encryption_key,
        }
    )
    session = LockedAccountSession(
        session_id=uuid4(),
        user_id=user_id,
        provider_session_id=provider_session_id,
        access_token_ciphertext=cipher.encrypt(token),
        refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-refresh")),
        access_token_expires_at=expiry,
        last_seen_at=now - timedelta(days=1),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
        checked_at=now,
    )

    public_jwk = ECAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    public_jwk.update(
        {
            "kid": KEY_ID,
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )
    download = AsyncMock(return_value={"keys": [public_jwk]})

    return StoredAccessMaterial(
        settings=settings,
        session=session,
        signing_key=signing_key,
        claims=claims,
        cipher=cipher,
        cache=AccountKeyCache(download),
        download=download,
    )


def encrypt_claims(
    material: StoredAccessMaterial,
    claims: dict[str, object],
    *,
    signing_key: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    key = material.signing_key if signing_key is None else signing_key
    token = SecretStr(
        jwt.encode(
            claims,
            key,
            algorithm="ES256",
            headers={"kid": KEY_ID},
        )
    )
    return material.cipher.encrypt(token)


async def test_valid_access_does_not_require_decrypting_refresh_credentials(
    material: StoredAccessMaterial,
) -> None:
    session = replace(
        material.session,
        refresh_token_ciphertext=b"unreadable-refresh-ciphertext",
    )

    account = await verify_locked_account_access(
        session,
        settings=material.settings,
        key_cache=material.cache,
    )

    assert account.user_id == session.user_id
    assert account.session_id == session.provider_session_id
    assert account.access_token_expires_at == session.access_token_expires_at
    assert account.assurance_level == "aal1"
    material.download.assert_awaited_once()


@pytest.mark.parametrize(
    "field",
    ["user_id", "provider_session_id", "access_token_expires_at"],
)
async def test_stored_metadata_must_match_verified_claims(
    material: StoredAccessMaterial,
    field: str,
) -> None:
    if field == "user_id":
        session = replace(material.session, user_id=uuid4())
    elif field == "provider_session_id":
        session = replace(material.session, provider_session_id=uuid4())
    else:
        session = replace(
            material.session,
            access_token_expires_at=(
                material.session.access_token_expires_at + timedelta(seconds=1)
            ),
        )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )

    material.download.assert_awaited_once()


@pytest.mark.parametrize("seconds_after_expiry", [0, 1])
async def test_database_check_time_must_precede_access_expiry(
    material: StoredAccessMaterial,
    seconds_after_expiry: int,
) -> None:
    # JWT is valid against the application clock, but the database snapshot
    # reports a check time at or after its expiry.
    session = replace(
        material.session,
        checked_at=(
            material.session.access_token_expires_at + timedelta(seconds=seconds_after_expiry)
        ),
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )


@pytest.mark.parametrize(
    "ciphertext",
    [b"", b"not-a-fernet-token", b"x" * 12289],
)
async def test_unreadable_ciphertext_fails_before_key_download(
    material: StoredAccessMaterial,
    ciphertext: bytes,
) -> None:
    session = replace(
        material.session,
        access_token_ciphertext=ciphertext,
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )

    material.download.assert_not_awaited()


async def test_tampered_ciphertext_is_rejected(
    material: StoredAccessMaterial,
) -> None:
    original = material.session.access_token_ciphertext
    session = replace(
        material.session,
        access_token_ciphertext=original[:-2] + b"AA",
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )

    material.download.assert_not_awaited()


async def test_wrong_encryption_key_is_unavailability(
    material: StoredAccessMaterial,
) -> None:
    settings = material.settings.model_copy(
        update={"account_session_encryption_key": SecretStr(Fernet.generate_key().decode("ascii"))}
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            material.session,
            settings=settings,
            key_cache=material.cache,
        )

    material.download.assert_not_awaited()


@pytest.mark.parametrize(
    "field",
    ["account_session_encryption_key", "supabase_auth_issuer"],
)
async def test_missing_configuration_is_unavailability(
    material: StoredAccessMaterial,
    field: str,
) -> None:
    settings = material.settings.model_copy(update={field: None})

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            material.session,
            settings=settings,
            key_cache=material.cache,
        )

    material.download.assert_not_awaited()


async def test_forged_signature_is_rejected_even_when_ids_match(
    material: StoredAccessMaterial,
) -> None:
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    session = replace(
        material.session,
        access_token_ciphertext=encrypt_claims(
            material,
            material.claims,
            signing_key=attacker_key,
        ),
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("exp", 0),
        ("iss", "https://other.example.test/auth/v1"),
        ("aud", "another-application"),
    ],
)
async def test_invalid_signed_claims_are_rejected(
    material: StoredAccessMaterial,
    field: str,
    invalid_value: object,
) -> None:
    claims = {**material.claims, field: invalid_value}
    session = replace(
        material.session,
        access_token_ciphertext=encrypt_claims(material, claims),
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )


async def test_signing_key_failure_hides_provider_details(
    material: StoredAccessMaterial,
) -> None:
    material.download.side_effect = AccountKeyFetchError("Private provider details")

    with pytest.raises(AccountAuthenticationUnavailable) as caught:
        await verify_locked_account_access(
            material.session,
            settings=material.settings,
            key_cache=material.cache,
        )

    assert str(caught.value) == "Account authentication is unavailable."
    assert "Private provider details" not in str(caught.value)
    material.download.assert_awaited_once()


async def test_missing_key_cache_is_unavailability(
    material: StoredAccessMaterial,
) -> None:
    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            material.session,
            settings=material.settings,
            key_cache=None,
        )

    material.download.assert_not_awaited()


async def test_encrypted_malformed_jwt_is_rejected_without_key_download(
    material: StoredAccessMaterial,
) -> None:
    session = replace(
        material.session,
        access_token_ciphertext=material.cipher.encrypt(SecretStr("not-a-jwt")),
    )

    with pytest.raises(AccountAuthenticationUnavailable):
        await verify_locked_account_access(
            session,
            settings=material.settings,
            key_cache=material.cache,
        )

    material.download.assert_not_awaited()
