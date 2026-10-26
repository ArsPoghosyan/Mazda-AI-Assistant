"""Encrypted, short-lived evidence of email-registration Terms agreement.

This cookie is not authentication. A pending receipt must first be bound by a
successful signup-code confirmation, then matched to a verified account login.
No email address, password, provider token or browser credential is stored in it.
"""

import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Literal
from uuid import UUID

from fastapi import Request, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, ValidationError

from app.account_terms_requests import CURRENT_TERMS_VERSION
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings

RECEIPT_LIFETIME_SECONDS = 3600
_MAX_COOKIE_LENGTH = 1536
_COOKIE_VALUE = re.compile(r"[A-Za-z0-9_-]{100,1534}={0,2}", re.ASCII)


class SignupTermsReceipt(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    purpose: Literal["email_signup_terms"] = "email_signup_terms"
    terms_version: str
    email_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted_at: AwareDatetime
    expires_at: AwareDatetime
    confirmed_user_id: UUID | None


def signup_terms_cookie_name(settings: Settings) -> str:
    return "__Host-askm6_signup_terms" if settings.account_cookie_secure else "askm6_signup_terms"


def read_signup_terms_cookie(request: Request, settings: Settings) -> SecretStr | None:
    value = request.cookies.get(signup_terms_cookie_name(settings))
    if value is None or len(value) > _MAX_COOKIE_LENGTH or _COOKIE_VALUE.fullmatch(value) is None:
        return None
    return SecretStr(value)


def _email_hash(email: SecretStr) -> str:
    # Preserve exact input, just as the auth adapters do. Differently entered
    # addresses safely fall back to setup rather than guessing provider aliases.
    return sha256(email.get_secret_value().encode("utf-8")).hexdigest()


def make_signup_terms_receipt(email: SecretStr) -> SignupTermsReceipt:
    now = datetime.now(UTC)
    return SignupTermsReceipt(
        terms_version=CURRENT_TERMS_VERSION,
        email_hash=_email_hash(email),
        accepted_at=now,
        expires_at=now + timedelta(seconds=RECEIPT_LIFETIME_SECONDS),
        confirmed_user_id=None,
    )


def decode_signup_terms_receipt(
    value: SecretStr | None,
    email: SecretStr,
    settings: Settings,
) -> SignupTermsReceipt | None:
    receipt = _decode_receipt(value, settings)
    return receipt if receipt is not None and receipt.email_hash == _email_hash(email) else None


def decode_confirmed_signup_terms_receipt(
    value: SecretStr | None,
    user_id: UUID,
    settings: Settings,
) -> SignupTermsReceipt | None:
    """Match OTP-bound evidence to a server-verified subject, never an email claim."""
    receipt = _decode_receipt(value, settings)
    return receipt if receipt is not None and receipt.confirmed_user_id == user_id else None


def _decode_receipt(value: SecretStr | None, settings: Settings) -> SignupTermsReceipt | None:
    if value is None or settings.account_session_encryption_key is None:
        return None
    raw = value.get_secret_value()
    if len(raw) > _MAX_COOKIE_LENGTH or _COOKIE_VALUE.fullmatch(raw) is None:
        return None
    try:
        plaintext = AccountTokenCipher(settings.account_session_encryption_key).decrypt(
            raw.encode("ascii")
        )
        receipt = SignupTermsReceipt.model_validate_json(plaintext.get_secret_value())
        now = datetime.now(UTC)
        lifetime = (receipt.expires_at - receipt.accepted_at).total_seconds()
        if (
            receipt.terms_version != CURRENT_TERMS_VERSION
            or not 0 < lifetime <= RECEIPT_LIFETIME_SECONDS
            or receipt.accepted_at > now + timedelta(seconds=5)
            or receipt.expires_at <= now
        ):
            return None
        return receipt
    except (ValueError, UnicodeError, ValidationError):
        return None


def set_signup_terms_cookie(
    response: Response, receipt: SignupTermsReceipt, settings: Settings
) -> None:
    key = settings.account_session_encryption_key
    if key is None:
        raise ValueError("Registration agreement encryption is unavailable.")
    value = AccountTokenCipher(key).encrypt(SecretStr(receipt.model_dump_json())).decode("ascii")
    if len(value) > _MAX_COOKIE_LENGTH:
        raise ValueError("Registration agreement is too large.")
    remaining = max(0, int((receipt.expires_at - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        signup_terms_cookie_name(settings),
        value,
        max_age=remaining,
        expires=receipt.expires_at,
        path="/",
        secure=settings.account_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"


def clear_signup_terms_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        signup_terms_cookie_name(settings),
        path="/",
        secure=settings.account_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
