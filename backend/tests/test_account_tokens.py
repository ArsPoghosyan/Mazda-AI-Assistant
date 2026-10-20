"""Offline account-token tests using temporary signing keys."""

import json
from base64 import urlsafe_b64encode
from datetime import UTC, datetime
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr

from app.account_tokens import (
    InvalidAccountToken,
    VerifiedAccount,
    verify_account_token,
)

ISSUER = "https://auth.example.test/auth/v1"
AUDIENCE = "authenticated"
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")


@pytest.fixture
def signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def claims() -> dict[str, object]:
    now = int(datetime.now(UTC).timestamp())

    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now - 1,
        "exp": now + 300,
        "sub": str(USER_ID),
        "session_id": str(SESSION_ID),
        "role": "authenticated",
        "is_anonymous": False,
        "aal": "aal1",
    }


def verify_for_test(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
) -> VerifiedAccount:
    return verify_account_token(
        SecretStr(token),
        public_key=public_key,
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def test_accepts_valid_account_token(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    account = verify_for_test(token, signing_key.public_key())

    assert account == VerifiedAccount(
        user_id=USER_ID,
        session_id=SESSION_ID,
        assurance_level="aal1",
    )


def test_rejects_token_signed_by_another_key(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    token = jwt.encode(claims, signing_key, algorithm="ES256")
    other_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, other_key.public_key())


def test_rejects_expired_token(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    now = int(datetime.now(UTC).timestamp())
    claims["iat"] = now - 120
    claims["exp"] = now - 60

    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


@pytest.mark.parametrize(
    ("claim_name", "incorrect_value"),
    [
        ("iss", "https://another.example.test/auth/v1"),
        ("aud", "another-audience"),
    ],
)
def test_rejects_wrong_issuer_or_audience(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    claim_name: str,
    incorrect_value: str,
) -> None:
    claims[claim_name] = incorrect_value
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


@pytest.mark.parametrize(
    "claim_name",
    [
        "iss",
        "aud",
        "exp",
        "iat",
        "sub",
        "session_id",
        "role",
        "is_anonymous",
        "aal",
    ],
)
def test_rejects_missing_required_claim(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    claim_name: str,
) -> None:
    claims.pop(claim_name)
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


@pytest.mark.parametrize("role", ["anon", "service_role"])
def test_rejects_non_account_role(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    role: str,
) -> None:
    claims["role"] = role
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


def test_rejects_anonymous_identity(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    claims["is_anonymous"] = True
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


@pytest.mark.parametrize(
    ("claim_name", "invalid_value"),
    [
        pytest.param("sub", "not-a-uuid", id="invalid-user-id"),
        pytest.param("sub", 123, id="numeric-user-id"),
        pytest.param("session_id", "not-a-uuid", id="invalid-session-id"),
        pytest.param("session_id", 123, id="numeric-session-id"),
        pytest.param("is_anonymous", "false", id="string-anonymous-flag"),
        pytest.param("is_anonymous", 0, id="numeric-anonymous-flag"),
        pytest.param("aal", "aal3", id="unknown-assurance-level"),
        pytest.param("aal", 2, id="numeric-assurance-level"),
        pytest.param("exp", "4102444800", id="string-expiry"),
        pytest.param("exp", 4102444800.5, id="fractional-expiry"),
        pytest.param("exp", True, id="boolean-expiry"),
        pytest.param("iat", "1", id="string-issued-at"),
        pytest.param("iat", 1.5, id="fractional-issued-at"),
        pytest.param("iat", False, id="boolean-issued-at"),
    ],
)
def test_rejects_malformed_account_claim(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    claim_name: str,
    invalid_value: object,
) -> None:
    claims[claim_name] = invalid_value
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


def test_rejects_payload_changed_without_resigning(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    token = jwt.encode(claims, signing_key, algorithm="ES256")
    header, _, signature = token.split(".")

    changed_claims = {
        **claims,
        "sub": "33333333-3333-4333-8333-333333333333",
    }
    changed_payload = (
        urlsafe_b64encode(json.dumps(changed_claims).encode("utf-8")).rstrip(b"=").decode("ascii")
    )
    tampered_token = f"{header}.{changed_payload}.{signature}"

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(tampered_token, signing_key.public_key())


@pytest.mark.parametrize("algorithm", ["HS256", "none"])
def test_rejects_unsupported_algorithm(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    algorithm: str,
) -> None:
    key = "" if algorithm == "none" else "test-only-signing-key-" * 3
    token = jwt.encode(claims, key, algorithm=algorithm)

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-token",
        "a.b.c",
        "a.b.c.d",
    ],
)
def test_rejects_empty_or_malformed_token(
    signing_key: ec.EllipticCurvePrivateKey,
    token: str,
) -> None:
    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())


def test_rejects_oversized_signed_token(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    claims["padding"] = "x" * 8192
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    assert len(token) > 8192

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(token, signing_key.public_key())
