"""Guest bearer-token creation and verifier hashing."""

import hashlib
import re
from secrets import token_urlsafe

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def generate_guest_token() -> str:
    """Generate a URL-safe token containing 32 random bytes."""
    return token_urlsafe(32)


def hash_guest_token(token: str) -> bytes:
    """Validate the token format and produce its database verifier."""
    if _TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("Invalid guest session token.")

    return hashlib.sha256(token.encode("ascii")).digest()
