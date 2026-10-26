"""Bounded explicit Terms acceptance; never accepts an account ID or timestamp."""

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError, field_validator

# This revision identifies the development-stage Terms served at /terms.
# Change it when publishing materially changed Terms; never relabel old records.
CURRENT_TERMS_VERSION = "2026-10-26"
_MAX_BODY_BYTES = 1024


class TermsAcceptanceRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    accepted: StrictBool
    terms_version: str

    @field_validator("accepted")
    @classmethod
    def require_acceptance(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("Explicit Terms acceptance is required.")
        return value

    @field_validator("terms_version")
    @classmethod
    def require_current_version(cls, value: str) -> str:
        if value != CURRENT_TERMS_VERSION:
            raise ValueError("The current Terms revision must be accepted.")
        return value


def _request_error(code: int, detail: str) -> HTTPException:
    return HTTPException(code, detail, headers={"Cache-Control": "no-store"})


async def read_terms_acceptance(request: Request) -> TermsAcceptanceRequest:
    """Parse within a caller-owned deadline, with a limit on actual body bytes."""
    if request.scope.get("query_string", b""):
        raise _request_error(400, "Invalid Terms acceptance request.")
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise _request_error(415, "Terms acceptance requires a JSON request.")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise _request_error(413, "Terms acceptance request is too large.")
        body.extend(chunk)

    try:
        return TermsAcceptanceRequest.model_validate_json(bytes(body))
    except (ValidationError, UnicodeError, RecursionError):
        raise _request_error(400, "Invalid Terms acceptance request.") from None
