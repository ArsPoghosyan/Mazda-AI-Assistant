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
    get_account_token_key_id,
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

    expiry = claims["exp"]
    assert isinstance(expiry, int)

    assert account == VerifiedAccount(
        user_id=USER_ID,
        session_id=SESSION_ID,
        assurance_level="aal1",
        access_token_expires_at=datetime.fromtimestamp(expiry, tz=UTC),
    )
    assert account.access_token_expires_at.tzinfo is UTC


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


def token_with_test_header(header: object) -> str:
    """Build a JWT-shaped test value with an intentionally invalid signature."""

    encoded_header = (
        urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("ascii")
    )
    invalid_signature = urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")

    return f"{encoded_header}.e30.{invalid_signature}"


@pytest.mark.parametrize("key_id", ["current-key", "x" * 128])
def test_header_extracts_valid_key_id(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    key_id: str,
) -> None:
    token = jwt.encode(
        claims,
        signing_key,
        algorithm="ES256",
        headers={"kid": key_id},
    )

    assert get_account_token_key_id(SecretStr(token)) == key_id


@pytest.mark.parametrize("missing_field", ["alg", "kid"])
def test_header_rejects_missing_required_fields(missing_field: str) -> None:
    header = {"alg": "ES256", "kid": "current-key"}
    del header[missing_field]
    token = token_with_test_header(header)

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        get_account_token_key_id(SecretStr(token))


@pytest.mark.parametrize(
    ("field_name", "incorrect_value"),
    [
        ("alg", "HS256"),
        ("alg", "RS256"),
        ("alg", "none"),
        ("alg", None),
        ("kid", None),
        ("kid", 123),
        ("kid", ""),
        ("kid", "x" * 129),
        ("jku", "https://untrusted.example.test/keys"),
        ("jwk", {"kty": "EC"}),
        ("x5u", "https://untrusted.example.test/certificate"),
        ("crit", ["unsupported-extension"]),
        ("b64", False),
        ("b64", 1),
        ("b64", "true"),
    ],
)
def test_header_rejects_unsupported_metadata(
    field_name: str,
    incorrect_value: object,
) -> None:
    header: dict[str, object] = {
        "alg": "ES256",
        "kid": "current-key",
    }
    header[field_name] = incorrect_value
    token = token_with_test_header(header)

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        get_account_token_key_id(SecretStr(token))


@pytest.mark.parametrize(
    "token",
    ["", "not-a-token", "a.b.c", "a.b.c.d", "\N{SNOWMAN}"],
)
def test_header_rejects_malformed_token(token: str) -> None:
    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        get_account_token_key_id(SecretStr(token))


@pytest.mark.parametrize("header", [None, [], "not-an-object"])
def test_header_rejects_non_object_json(header: object) -> None:
    token = token_with_test_header(header)

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        get_account_token_key_id(SecretStr(token))


def test_header_rejects_oversized_token() -> None:
    token = token_with_test_header(
        {
            "alg": "ES256",
            "kid": "current-key",
            "padding": "x" * 8192,
        }
    )

    assert len(token) > 8192

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        get_account_token_key_id(SecretStr(token))


def test_deeply_nested_untrusted_token_cannot_authenticate(
    signing_key: ec.EllipticCurvePrivateKey,
) -> None:
    # Stay under the input cap. A parsed header is only a key-selection hint,
    # never authentication, even if the decoder accepts its nested metadata.
    header = b'{"alg":"ES256","kid":"synthetic","extra":' + b"[" * 1100 + b"0"
    header += b"]" * 1100 + b"}"
    encoded = urlsafe_b64encode(header).rstrip(b"=").decode("ascii")
    token = f"{encoded}.e30.AA"
    assert len(token) < 8192
    try:
        assert get_account_token_key_id(SecretStr(token)) == "synthetic"
    except InvalidAccountToken:
        pass
    with pytest.raises(InvalidAccountToken, match="^Invalid account token\\.$"):
        verify_for_test(token, signing_key.public_key())


def test_header_extraction_does_not_establish_authenticity(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
) -> None:
    signed_token = jwt.encode(
        claims,
        signing_key,
        algorithm="ES256",
        headers={"kid": "current-key"},
    )
    header, payload, _ = signed_token.split(".")
    invalid_signature = urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
    tampered_token = f"{header}.{payload}.{invalid_signature}"

    assert get_account_token_key_id(SecretStr(tampered_token)) == "current-key"

    with pytest.raises(InvalidAccountToken, match="Invalid account token"):
        verify_for_test(tampered_token, signing_key.public_key())


@pytest.mark.parametrize(
    "expiry",
    [
        pytest.param(253402300800, id="year-10000"),
        pytest.param(10**30, id="outside-timestamp-range"),
        pytest.param(10**400, id="outside-float-range"),
    ],
)
def test_rejects_unrepresentable_expiry(
    signing_key: ec.EllipticCurvePrivateKey,
    claims: dict[str, object],
    expiry: int,
) -> None:
    claims["exp"] = expiry
    token = jwt.encode(claims, signing_key, algorithm="ES256")

    with pytest.raises(InvalidAccountToken) as caught:
        verify_for_test(token, signing_key.public_key())

    assert str(caught.value) == "Invalid account token."
    assert token not in str(caught.value)
