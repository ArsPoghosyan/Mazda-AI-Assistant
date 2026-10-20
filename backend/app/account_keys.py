"""Select trusted account-verification keys from a public JWKS response."""

import re

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

_P256_COORDINATE = re.compile(r"[A-Za-z0-9_-]{43}")


class InvalidAccountKeySet(ValueError):
    """The public-key response is malformed or unsuitable for verification."""


class AccountKeyNotFound(LookupError):
    """The public-key response does not contain the requested key."""


def select_account_public_key(
    jwks: object,
    *,
    key_id: str,
) -> ec.EllipticCurvePublicKey:
    """Select one ES256 public key by its exact key identifier."""

    if not isinstance(jwks, dict):
        raise InvalidAccountKeySet("Invalid account signing key set.")

    keys = jwks.get("keys")

    if not isinstance(keys, list):
        raise InvalidAccountKeySet("Invalid account signing key set.")

    matches = []

    for candidate in keys:
        if not isinstance(candidate, dict):
            raise InvalidAccountKeySet("Invalid account signing key set.")

        if candidate.get("kid") == key_id:
            matches.append(candidate)

    if not matches:
        raise AccountKeyNotFound("Account signing key not found.")

    if len(matches) != 1:
        raise InvalidAccountKeySet("Ambiguous account signing key.")

    selected = matches[0]

    if (
        selected.get("kty") != "EC"
        or selected.get("crv") != "P-256"
        or selected.get("alg", "ES256") != "ES256"
        or selected.get("use", "sig") != "sig"
        or selected.get("key_ops", ["verify"]) != ["verify"]
        or "d" in selected
    ):
        raise InvalidAccountKeySet("Unsupported account signing key.")

    for coordinate_name in ("x", "y"):
        coordinate = selected.get(coordinate_name)

        if not isinstance(coordinate, str) or _P256_COORDINATE.fullmatch(coordinate) is None:
            raise InvalidAccountKeySet("Invalid account signing key.")

    try:
        public_key = jwt.PyJWK.from_dict(
            selected,
            algorithm="ES256",
        ).key
    except (jwt.PyJWTError, TypeError, ValueError):
        raise InvalidAccountKeySet("Invalid account signing key.") from None

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise InvalidAccountKeySet("Unsupported account signing key.")

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise InvalidAccountKeySet("Unsupported account signing key.")

    return public_key
