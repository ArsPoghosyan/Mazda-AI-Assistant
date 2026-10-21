"""Bounded email-confirmation parsing with masked credentials."""

from fastapi import HTTPException, Request, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)

_MAX_BODY_BYTES = 4 * 1024


class EmailConfirmationCredentials(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
    )

    email: SecretStr = Field(min_length=1, max_length=320)
    code: SecretStr = Field(min_length=6, max_length=10)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: SecretStr) -> SecretStr:
        raw_code = value.get_secret_value()

        if any(character not in "0123456789" for character in raw_code):
            raise ValueError("Invalid confirmation code.")

        return value


def email_confirmation_request_error(
    status_code: int,
    detail: str,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"Cache-Control": "no-store"},
    )


async def read_email_confirmation_credentials(
    request: Request,
) -> EmailConfirmationCredentials:
    """Parse credentials without verifying the code or creating a session.

    The caller must enforce the total request deadline.
    """
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    if content_type != "application/json":
        raise email_confirmation_request_error(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Email confirmation requires a JSON request.",
        )

    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            raise email_confirmation_request_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "Email confirmation request is too large.",
            )

        body.extend(chunk)

    try:
        credentials = EmailConfirmationCredentials.model_validate_json(bytes(body))
        credentials.email.get_secret_value().encode("utf-8")
    except (ValidationError, UnicodeError, RecursionError):
        raise email_confirmation_request_error(
            status.HTTP_400_BAD_REQUEST,
            "Invalid email confirmation request.",
        ) from None

    return credentials
