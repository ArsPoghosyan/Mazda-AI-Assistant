"""Verify managed-account tokens using a trusted public key."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import (
    BaseModel,
    ConfigDict,
    SecretStr,
    StrictBool,
    StrictInt,
    ValidationError,
)

_MAX_TOKEN_CHARACTERS = 8192


class InvalidAccountToken(ValueError):
    """The supplied token cannot establish an account identity."""


@dataclass(frozen=True, slots=True)
class VerifiedAccount:
    """Identity claims verified against the configured authentication provider."""

    user_id: UUID
    session_id: UUID
    assurance_level: Literal["aal1", "aal2"]


class _AccountClaims(BaseModel):
    """Validate the account-specific claims after signature verification."""

    model_config = ConfigDict(
        extra="ignore",
        hide_input_in_errors=True,
    )

    sub: UUID
    session_id: UUID
    role: Literal["authenticated"]
    is_anonymous: StrictBool
    aal: Literal["aal1", "aal2"]
    exp: StrictInt
    iat: StrictInt


def verify_account_token(
    token: SecretStr,
    *,
    public_key: ec.EllipticCurvePublicKey,
    issuer: str,
    audience: str,
) -> VerifiedAccount:
    """Verify an ES256 token and return its account identity."""

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("Account verification requires a P-256 public key.")

    raw_token = token.get_secret_value()

    if not raw_token or len(raw_token) > _MAX_TOKEN_CHARACTERS:
        raise InvalidAccountToken("Invalid account token.")

    try:
        payload = jwt.decode(
            raw_token,
            public_key,
            algorithms=["ES256"],
            issuer=issuer,
            audience=audience,
            options={
                "require": [
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
            },
        )

        claims = _AccountClaims.model_validate(payload)
    except (jwt.InvalidTokenError, ValidationError):
        raise InvalidAccountToken("Invalid account token.") from None

    if claims.is_anonymous:
        raise InvalidAccountToken("Invalid account token.")

    return VerifiedAccount(
        user_id=claims.sub,
        session_id=claims.session_id,
        assurance_level=claims.aal,
    )
