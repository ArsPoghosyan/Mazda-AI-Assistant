"""Bounded registration parsing without exposing credential details."""

from fastapi import HTTPException, Request, status
from pydantic import (
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)

from app.account_terms_requests import TermsAcceptanceRequest

_MAX_BODY_BYTES = 16 * 1024


class SignUpCredentials(TermsAcceptanceRequest):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
    )

    email: SecretStr = Field(min_length=1, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=1024)
    captcha_token: SecretStr = Field(min_length=1, max_length=2048)

    @field_validator("captcha_token")
    @classmethod
    def validate_captcha_token(cls, value: SecretStr) -> SecretStr:
        raw_token = value.get_secret_value()

        if any(ord(character) < 33 or ord(character) > 126 for character in raw_token):
            raise ValueError("Invalid CAPTCHA token.")

        return value


def sign_up_request_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"Cache-Control": "no-store"},
    )


async def read_sign_up_credentials(request: Request) -> SignUpCredentials:
    """Read bounded JSON and return masked, structurally valid credentials.

    Does not verify the CAPTCHA, contact Supabase, or create an account.
    The caller must enforce the total request deadline.
    """
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise sign_up_request_error(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Registration requires a JSON request.",
        )

    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise sign_up_request_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Registration request is too large.",
            )

        body.extend(chunk)

    try:
        credentials = SignUpCredentials.model_validate_json(bytes(body))
        credentials.email.get_secret_value().encode("utf-8")
        credentials.password.get_secret_value().encode("utf-8")
    except (ValidationError, UnicodeError, RecursionError):
        raise sign_up_request_error(
            status.HTTP_400_BAD_REQUEST,
            "Invalid registration request.",
        ) from None

    return credentials
