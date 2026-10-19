"""Guest token tests without database access."""

from base64 import urlsafe_b64decode

import pytest

from app.guest_tokens import generate_guest_token, hash_guest_token


def test_generated_tokens_are_url_safe_and_distinct() -> None:
    first = generate_guest_token()
    second = generate_guest_token()

    assert first != second
    assert len(first) == 43
    assert len(urlsafe_b64decode(first + "=")) == 32


def test_token_verifier_is_stable_and_32_bytes() -> None:
    token = generate_guest_token()
    verifier = hash_guest_token(token)

    assert isinstance(verifier, bytes)
    assert len(verifier) == 32
    assert verifier == hash_guest_token(token)


def test_different_tokens_have_different_verifiers() -> None:
    assert hash_guest_token("A" * 43) != hash_guest_token("B" * 43)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "A" * 42,
        "A" * 44,
        "A" * 42 + "!",
        "A" * 42 + "é",
        "A" * 43 + "\n",
        " " + "A" * 42,
    ],
)
def test_invalid_tokens_are_rejected_without_echoing_them(token: str) -> None:
    with pytest.raises(ValueError) as error:
        hash_guest_token(token)

    assert str(error.value) == "Invalid guest session token."
