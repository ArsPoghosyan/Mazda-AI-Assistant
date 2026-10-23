"""Offline regressions for freshly issued tokens and small provider clock skew."""

import asyncio
import json
from datetime import UTC, datetime, tzinfo
from typing import Self, cast

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict

import app.account_tokens as token_module
from app.account_auth import authenticate_account_token
from app.account_key_cache import AccountKeyCache
from app.account_tokens import InvalidAccountToken, verify_account_token
from app.config import Settings

ISSUER = "https://auth.example.test/auth/v1"
NOW = datetime(2030, 1, 1, tzinfo=UTC)


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz: tzinfo | None = None) -> Self:
        return cls.fromtimestamp(NOW.timestamp(), tz=tz)


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(token_module, "datetime", FixedDateTime)
    monkeypatch.setattr(jwt.api_jwt, "datetime", FixedDateTime)


def make_token(
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    ahead: int = 1,
    overrides: dict[str, object] | None = None,
) -> SecretStr:
    now = int(NOW.timestamp())
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": "authenticated",
        "iat": now + ahead,
        "exp": now + 300,
        "sub": "11111111-1111-4111-8111-111111111111",
        "session_id": "22222222-2222-4222-8222-222222222222",
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }
    claims.update(overrides or {})
    return SecretStr(
        jwt.encode(claims, signing_key, algorithm="ES256", headers={"kid": "clock-test"})
    )


@pytest.mark.parametrize("skew", [None, 0])
def test_account_auth_uses_configured_issued_at_tolerance(skew: int | None) -> None:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signing_key.public_key()))

    async def fetch_keys() -> dict[str, object]:
        return {"keys": [{**public_jwk, "kid": "clock-test", "alg": "ES256", "use": "sig"}]}

    settings = IsolatedSettings.model_validate({"supabase_auth_issuer": ISSUER})
    if skew is not None:
        settings = settings.model_copy(update={"supabase_auth_iat_clock_skew_seconds": skew})

    async def authenticate() -> token_module.VerifiedAccount:
        return await authenticate_account_token(
            make_token(signing_key), settings=settings, key_cache=AccountKeyCache(fetch_keys)
        )

    if skew == 0:
        with pytest.raises(InvalidAccountToken):
            asyncio.run(authenticate())
    else:
        account = asyncio.run(authenticate())
        assert isinstance(account, token_module.VerifiedAccount)
        assert str(account.user_id) == "11111111-1111-4111-8111-111111111111"


@pytest.mark.parametrize("ahead", [-1, 0, 1, 5])
def test_accepts_issued_at_within_five_second_boundary(ahead: int) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    account = verify_account_token(
        make_token(key, ahead=ahead),
        public_key=key.public_key(),
        issuer=ISSUER,
        audience="authenticated",
        issued_at_leeway_seconds=5,
    )
    assert account.access_token_expires_at.timestamp() == NOW.timestamp() + 300


@pytest.mark.parametrize("ahead", [6, 31, 300])
def test_rejects_issued_at_beyond_five_second_boundary(ahead: int) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(InvalidAccountToken):
        verify_account_token(
            make_token(key, ahead=ahead),
            public_key=key.public_key(),
            issuer=ISSUER,
            audience="authenticated",
            issued_at_leeway_seconds=5,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(NOW.timestamp()) - 1},
        {"exp": int(NOW.timestamp())},
        {"nbf": int(NOW.timestamp()) + 1},
        {"exp": int(NOW.timestamp()) + 1},
        {"iat": str(int(NOW.timestamp()))},
        {"iat": True},
        {"iat": NOW.timestamp() + 0.5},
        {"iss": "https://untrusted.example.test/auth/v1"},
        {"aud": "untrusted"},
        {"role": "service_role"},
        {"is_anonymous": True},
    ],
)
def test_clock_tolerance_preserves_other_token_checks(overrides: dict[str, object]) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(InvalidAccountToken):
        verify_account_token(
            make_token(key, ahead=2, overrides=overrides),
            public_key=key.public_key(),
            issuer=ISSUER,
            audience="authenticated",
            issued_at_leeway_seconds=5,
        )


def test_clock_tolerance_does_not_accept_an_invalid_signature() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(InvalidAccountToken):
        verify_account_token(
            make_token(key),
            public_key=other.public_key(),
            issuer=ISSUER,
            audience="authenticated",
            issued_at_leeway_seconds=5,
        )


@pytest.mark.parametrize("value", [-1, 31, True, 0.5])
def test_verifier_rejects_invalid_tolerance(value: object) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="clock skew"):
        verify_account_token(
            make_token(key),
            public_key=key.public_key(),
            issuer=ISSUER,
            audience="authenticated",
            issued_at_leeway_seconds=cast(int, value),
        )


@pytest.mark.parametrize("value", [0, 5, 30])
def test_config_accepts_bounded_tolerance(value: int) -> None:
    settings = IsolatedSettings.model_validate({"supabase_auth_iat_clock_skew_seconds": value})
    assert settings.supabase_auth_iat_clock_skew_seconds == value


@pytest.mark.parametrize("value", [-1, 31])
def test_config_rejects_out_of_range_tolerance(value: int) -> None:
    with pytest.raises(ValidationError):
        IsolatedSettings.model_validate({"supabase_auth_iat_clock_skew_seconds": value})


def test_default_tolerance_is_five_seconds() -> None:
    assert IsolatedSettings.model_validate({}).supabase_auth_iat_clock_skew_seconds == 5


def test_token_rejection_logs_only_a_fixed_category(caplog: pytest.LogCaptureFixture) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    raw_token = make_token(key, ahead=6)
    with pytest.raises(InvalidAccountToken):
        verify_account_token(
            raw_token,
            public_key=key.public_key(),
            issuer=ISSUER,
            audience="authenticated",
            issued_at_leeway_seconds=5,
        )
    assert "issued_at_in_future" in caplog.text
    assert raw_token.get_secret_value() not in caplog.text
    assert "11111111-1111-4111-8111-111111111111" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
