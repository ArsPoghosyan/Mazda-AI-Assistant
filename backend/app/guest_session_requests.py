"""Bounded parsing of optional guest-session challenge input."""

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

_MAX_BODY_BYTES = 16 * 1024


class GuestSessionRequest(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
    )

    turnstile_token: SecretStr | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
    )


def guest_request_error(
    status_code: int,
    detail: str,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"Cache-Control": "no-store"},
    )


async def read_guest_challenge(request: Request) -> SecretStr | None:
    """Read optional, bounded JSON without verifying the challenge.

    Empty bodies carry no challenge. The caller must enforce the total
    request deadline; the service decides whether a challenge is required.
    """
    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise guest_request_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Guest-session request is too large.",
            )
        body.extend(chunk)

    if not body:
        return None

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise guest_request_error(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Guest-session input requires JSON.",
        )

    try:
        parsed = GuestSessionRequest.model_validate_json(bytes(body))

        if parsed.turnstile_token is not None:
            parsed.turnstile_token.get_secret_value().encode("utf-8")
    except (ValidationError, UnicodeError, RecursionError):
        raise guest_request_error(
            status.HTTP_400_BAD_REQUEST,
            "Invalid guest-session request.",
        ) from None

    return parsed.turnstile_token
