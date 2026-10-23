"""Bounded Google callback parsing without exposing callback credentials."""

import re
from urllib.parse import parse_qsl

from fastapi import HTTPException, Request, status
from pydantic import SecretStr

_MAX_QUERY_BYTES = 4 * 1024


def google_callback_request_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Google sign-in was rejected.",
        headers={"Cache-Control": "no-store"},
    )


def read_google_callback_code(request: Request) -> SecretStr:
    """Read one opaque code without consuming an attempt or contacting Supabase."""
    raw_query = request.scope.get("query_string", b"")

    if (
        not isinstance(raw_query, bytes)
        or not raw_query
        or len(raw_query) > _MAX_QUERY_BYTES
        or any(byte < 33 or byte > 126 for byte in raw_query)
    ):
        raise google_callback_request_error()

    query = raw_query.decode("ascii")
    if re.search(r"%(?![0-9A-Fa-f]{2})", query):
        raise google_callback_request_error()

    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="ascii",
            errors="strict",
            max_num_fields=1,
        )
    except (ValueError, UnicodeError):
        raise google_callback_request_error() from None

    if len(pairs) != 1 or pairs[0][0] != "code":
        raise google_callback_request_error()

    code = pairs[0][1]
    if not 1 <= len(code) <= 1024 or any(
        ord(character) < 33 or ord(character) > 126 for character in code
    ):
        raise google_callback_request_error()

    return SecretStr(code)
