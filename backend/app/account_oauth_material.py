"""Generate browser binding and encrypted PKCE material for pending OAuth."""

import re
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from hashlib import sha256
from secrets import token_urlsafe

from pydantic import SecretStr

from app.account_token_encryption import AccountTokenCipher, InvalidStoredAccountToken


@dataclass(frozen=True, slots=True)
class OAuthLoginMaterial:
    """Internal values; never serialize this object as an API response."""

    browser_token: SecretStr
    browser_token_hash: bytes = field(repr=False)
    pkce_verifier_ciphertext: bytes = field(repr=False)
    code_challenge: str


def create_oauth_login_material(
    cipher: AccountTokenCipher,
) -> OAuthLoginMaterial:
    """Generate independent secrets and an S256 challenge without persistence."""
    browser_token = token_urlsafe(32)
    verifier = SecretStr(token_urlsafe(32))

    verifier_digest = sha256(verifier.get_secret_value().encode("ascii")).digest()
    challenge = urlsafe_b64encode(verifier_digest).rstrip(b"=").decode("ascii")

    return OAuthLoginMaterial(
        browser_token=SecretStr(browser_token),
        browser_token_hash=sha256(browser_token.encode("ascii")).digest(),
        pkce_verifier_ciphertext=cipher.encrypt(verifier),
        code_challenge=challenge,
    )


class InvalidOAuthLoginMaterial(ValueError):
    """Pending OAuth material is missing, malformed or unreadable."""


def hash_oauth_browser_token(token: str | None) -> bytes:
    """Validate the unchanged cookie value before hashing it for lookup."""
    if token is None or len(token) != 43 or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")

    return sha256(token.encode("ascii")).digest()


def recover_oauth_pkce_verifier(
    ciphertext: bytes,
    *,
    cipher: AccountTokenCipher,
) -> SecretStr:
    """Decrypt and validate the format produced by our own generator."""
    if not 1 <= len(ciphertext) <= 1024:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")

    try:
        verifier = cipher.decrypt(ciphertext)
    except InvalidStoredAccountToken:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.") from None

    raw_verifier = verifier.get_secret_value()
    if len(raw_verifier) != 43 or re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_verifier) is None:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")

    return verifier
