"""Bounded password-reset parsing with masked credentials."""

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


class PasswordResetCredentials(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
    )

    email: SecretStr = Field(min_length=1, max_length=320)
    code: SecretStr = Field(min_length=6, max_length=10)
    new_password: SecretStr = Field(min_length=1, max_length=1024)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: SecretStr) -> SecretStr:
        raw_code = value.get_secret_value()

        if any(character not in "0123456789" for character in raw_code):
            raise ValueError("Invalid recovery code.")

        return value


def password_reset_request_error(
    status_code: int,
    detail: str,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"Cache-Control": "no-store"},
    )


async def read_password_reset_credentials(
    request: Request,
) -> PasswordResetCredentials:
    """Parse input without verifying recovery proof or changing a password.

    Preserve password characters exactly; Supabase enforces password strength.
    The caller must enforce the total request deadline.
    """
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise password_reset_request_error(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Password reset requires a JSON request.",
        )

    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise password_reset_request_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Password reset request is too large.",
            )

        body.extend(chunk)

    try:
        credentials = PasswordResetCredentials.model_validate_json(bytes(body))
        credentials.email.get_secret_value().encode("utf-8")
        credentials.new_password.get_secret_value().encode("utf-8")
    except (ValidationError, UnicodeError, RecursionError):
        raise password_reset_request_error(
            status.HTTP_400_BAD_REQUEST,
            "Invalid password reset request.",
        ) from None

    return credentials
