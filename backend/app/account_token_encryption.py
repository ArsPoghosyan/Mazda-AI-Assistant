"""Encryption of provider tokens stored by backend account sessions."""

from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr

_MAX_TOKEN_CHARACTERS = 8192
_MAX_CIPHERTEXT_BYTES = 12288


class InvalidStoredAccountToken(ValueError):
    """Stored token cannot be safely decrypted."""


def _validate_token(value: str) -> None:
    if not value or len(value) > _MAX_TOKEN_CHARACTERS or not value.isascii():
        raise ValueError("Invalid account token.")


class AccountTokenCipher:
    """Encrypt provider tokens using the validated backend-only key."""

    def __init__(self, key: SecretStr) -> None:
        try:
            self._fernet = Fernet(key.get_secret_value().encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("Invalid account-session encryption key.") from None

    def encrypt(self, token: SecretStr) -> bytes:
        raw_token = token.get_secret_value()
        _validate_token(raw_token)
        return self._fernet.encrypt(raw_token.encode("ascii"))

    def decrypt(self, ciphertext: bytes) -> SecretStr:
        if not ciphertext or len(ciphertext) > _MAX_CIPHERTEXT_BYTES:
            raise InvalidStoredAccountToken("Invalid stored account token.")

        try:
            plaintext = self._fernet.decrypt(ciphertext).decode("ascii")
            _validate_token(plaintext)
        except (InvalidToken, ValueError):
            raise InvalidStoredAccountToken("Invalid stored account token.") from None

        return SecretStr(plaintext)
