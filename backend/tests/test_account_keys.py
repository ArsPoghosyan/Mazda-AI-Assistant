"""Offline tests for selecting account-verification public keys."""

from base64 import urlsafe_b64encode

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.account_keys import (
    AccountKeyNotFound,
    InvalidAccountKeySet,
    select_account_public_key,
)


def make_jwk(
    public_key: ec.EllipticCurvePublicKey,
    key_id: str,
) -> dict[str, object]:
    numbers = public_key.public_numbers()

    return {
        "kid": key_id,
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "key_ops": ["verify"],
        "x": urlsafe_b64encode(numbers.x.to_bytes(32, "big")).decode().rstrip("="),
        "y": urlsafe_b64encode(numbers.y.to_bytes(32, "big")).decode().rstrip("="),
    }


@pytest.fixture
def public_key() -> ec.EllipticCurvePublicKey:
    return ec.generate_private_key(ec.SECP256R1()).public_key()


@pytest.fixture
def jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, object]:
    return make_jwk(public_key, "current-key")


def test_selects_matching_key_among_multiple_keys(
    public_key: ec.EllipticCurvePublicKey,
    jwk: dict[str, object],
) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1()).public_key()

    selected = select_account_public_key(
        {"keys": [make_jwk(other_key, "previous-key"), jwk]},
        key_id="current-key",
    )

    assert selected.public_numbers() == public_key.public_numbers()


def test_rejects_unknown_key_id(jwk: dict[str, object]) -> None:
    with pytest.raises(AccountKeyNotFound):
        select_account_public_key({"keys": [jwk]}, key_id="unknown-key")


def test_reports_missing_key_for_empty_set() -> None:
    with pytest.raises(AccountKeyNotFound):
        select_account_public_key({"keys": []}, key_id="current-key")


def test_rejects_duplicate_key_ids(jwk: dict[str, object]) -> None:
    with pytest.raises(InvalidAccountKeySet, match="Ambiguous"):
        select_account_public_key(
            {"keys": [jwk, dict(jwk)]},
            key_id="current-key",
        )


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"keys": {}},
        {"keys": [None]},
    ],
)
def test_rejects_malformed_key_sets(response: object) -> None:
    with pytest.raises(InvalidAccountKeySet):
        select_account_public_key(response, key_id="current-key")


@pytest.mark.parametrize(
    ("field_name", "incorrect_value"),
    [
        ("kty", "RSA"),
        ("crv", "P-384"),
        ("alg", "HS256"),
        ("use", "enc"),
        ("key_ops", ["sign"]),
        ("key_ops", ["verify", "sign"]),
        ("d", "private-key-material"),
    ],
)
def test_rejects_unsuitable_key_metadata(
    jwk: dict[str, object],
    field_name: str,
    incorrect_value: object,
) -> None:
    jwk[field_name] = incorrect_value

    with pytest.raises(InvalidAccountKeySet):
        select_account_public_key({"keys": [jwk]}, key_id="current-key")


@pytest.mark.parametrize(
    ("coordinate_name", "incorrect_value"),
    [
        ("x", None),
        ("y", 123),
        ("x", "short"),
        ("y", "!" * 43),
    ],
)
def test_rejects_malformed_coordinates(
    jwk: dict[str, object],
    coordinate_name: str,
    incorrect_value: object,
) -> None:
    jwk[coordinate_name] = incorrect_value

    with pytest.raises(InvalidAccountKeySet):
        select_account_public_key({"keys": [jwk]}, key_id="current-key")


def test_rejects_coordinates_outside_the_curve(jwk: dict[str, object]) -> None:
    jwk["x"] = "A" * 43
    jwk["y"] = "A" * 43

    with pytest.raises(InvalidAccountKeySet):
        select_account_public_key({"keys": [jwk]}, key_id="current-key")


def test_accepts_missing_optional_metadata(
    public_key: ec.EllipticCurvePublicKey,
    jwk: dict[str, object],
) -> None:
    for field_name in ("alg", "use", "key_ops"):
        del jwk[field_name]

    selected = select_account_public_key(
        {"keys": [jwk]},
        key_id="current-key",
    )

    assert selected.public_numbers() == public_key.public_numbers()
