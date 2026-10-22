"""Bounded password-recovery parsing with masked credentials."""

from fastapi import HTTPException, Request, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)

_MAX_BODY_BYTES = 16 * 1024


class PasswordRecoveryCredentials(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
    )

    email: SecretStr = Field(min_length=1, max_length=320)
    captcha_token: SecretStr = Field(min_length=1, max_length=2048)

    @field_validator("captcha_token")
    @classmethod
    def validate_captcha_token(cls, value: SecretStr) -> SecretStr:
        raw_token = value.get_secret_value()

        if any(ord(character) < 33 or ord(character) > 126 for character in raw_token):
            raise ValueError("Invalid CAPTCHA token.")

        return value


def password_recovery_request_error(
    status_code: int,
    detail: str,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"Cache-Control": "no-store"},
    )


async def read_password_recovery_credentials(
    request: Request,
) -> PasswordRecoveryCredentials:
    """Read bounded JSON and return masked, structurally valid credentials.

    Provider delivery and password changes belong to later operations.
    The caller must enforce the total request deadline.
    """
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise password_recovery_request_error(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Password recovery requires a JSON request.",
        )

    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise password_recovery_request_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Password recovery request is too large.",
            )

        body.extend(chunk)

    try:
        credentials = PasswordRecoveryCredentials.model_validate_json(bytes(body))
        credentials.email.get_secret_value().encode("utf-8")
    except (ValidationError, UnicodeError, RecursionError):
        raise password_recovery_request_error(
            status.HTTP_400_BAD_REQUEST,
            "Invalid password recovery request.",
        ) from None

    return credentials
