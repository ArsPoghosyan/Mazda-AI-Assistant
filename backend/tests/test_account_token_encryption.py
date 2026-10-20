"""Token encryption tests using temporary keys and synthetic credentials."""

from base64 import urlsafe_b64decode, urlsafe_b64encode

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from app.account_token_encryption import (
    AccountTokenCipher,
    InvalidStoredAccountToken,
)


@pytest.fixture
def key() -> SecretStr:
    return SecretStr(Fernet.generate_key().decode("ascii"))


def test_token_round_trip_and_redaction(key: SecretStr) -> None:
    cipher = AccountTokenCipher(key)
    original = "synthetic-provider-token"

    encrypted = cipher.encrypt(SecretStr(original))
    decrypted = cipher.decrypt(encrypted)

    assert isinstance(encrypted, bytes)
    assert original.encode("ascii") not in encrypted
    assert decrypted.get_secret_value() == original
    assert original not in str(decrypted)
    assert original not in repr(decrypted)


def test_encryption_is_randomized(key: SecretStr) -> None:
    cipher = AccountTokenCipher(key)
    token = SecretStr("synthetic-provider-token")

    assert cipher.encrypt(token) != cipher.encrypt(token)


def test_maximum_token_size_round_trips(key: SecretStr) -> None:
    cipher = AccountTokenCipher(key)
    token = SecretStr("x" * 8192)

    assert cipher.decrypt(cipher.encrypt(token)).get_secret_value() == "x" * 8192


def test_wrong_key_is_rejected_without_exposing_token(key: SecretStr) -> None:
    original = "synthetic-provider-token"
    encrypted = AccountTokenCipher(key).encrypt(SecretStr(original))
    other_key = SecretStr(Fernet.generate_key().decode("ascii"))

    with pytest.raises(InvalidStoredAccountToken) as caught:
        AccountTokenCipher(other_key).decrypt(encrypted)

    assert str(caught.value) == "Invalid stored account token."
    assert original not in str(caught.value)
    assert encrypted.decode("ascii") not in str(caught.value)


def test_tampered_ciphertext_is_rejected(key: SecretStr) -> None:
    cipher = AccountTokenCipher(key)
    encrypted = cipher.encrypt(SecretStr("synthetic-provider-token"))
    damaged = bytearray(urlsafe_b64decode(encrypted))
    damaged[-1] ^= 1

    with pytest.raises(InvalidStoredAccountToken):
        cipher.decrypt(urlsafe_b64encode(damaged))


@pytest.mark.parametrize("value", ["", "x" * 8193, "\N{SNOWMAN}"])
def test_invalid_plaintext_is_rejected(key: SecretStr, value: str) -> None:
    with pytest.raises(ValueError, match="^Invalid account token\\.$"):
        AccountTokenCipher(key).encrypt(SecretStr(value))


@pytest.mark.parametrize("value", [b"", b"malformed", b"x" * 12289])
def test_invalid_ciphertext_is_rejected(key: SecretStr, value: bytes) -> None:
    with pytest.raises(InvalidStoredAccountToken):
        AccountTokenCipher(key).decrypt(value)


@pytest.mark.parametrize("plaintext", [b"", b"\xff", b"x" * 8193])
def test_invalid_decrypted_content_is_rejected(
    key: SecretStr,
    plaintext: bytes,
) -> None:
    encrypted = Fernet(key.get_secret_value().encode("ascii")).encrypt(plaintext)

    with pytest.raises(InvalidStoredAccountToken):
        AccountTokenCipher(key).decrypt(encrypted)


@pytest.mark.parametrize("value", ["invalid-key", "\N{SNOWMAN}"])
def test_invalid_key_has_generic_error(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        AccountTokenCipher(SecretStr(value))

    assert str(caught.value) == "Invalid account-session encryption key."
    assert value not in str(caught.value)
