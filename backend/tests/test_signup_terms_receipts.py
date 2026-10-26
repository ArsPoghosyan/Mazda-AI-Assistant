"""Registration agreement receipts are private evidence, never account credentials."""

from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import Request, Response
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_signup_terms import (
    clear_signup_terms_cookie,
    decode_signup_terms_receipt,
    make_signup_terms_receipt,
    read_signup_terms_cookie,
    set_signup_terms_cookie,
    signup_terms_cookie_name,
)
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings

EMAIL = SecretStr(" Owner@Example.test ")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii"))
    )


def encoded(settings: Settings, **changes: object) -> SecretStr:
    receipt = make_signup_terms_receipt(EMAIL).model_copy(update=changes)
    key = settings.account_session_encryption_key
    assert key is not None
    return SecretStr(
        AccountTokenCipher(key).encrypt(SecretStr(receipt.model_dump_json())).decode("ascii")
    )


def test_receipt_contains_no_plaintext_email_or_account_before_confirmation(
    settings: Settings,
) -> None:
    pending = make_signup_terms_receipt(EMAIL)
    response = Response()
    set_signup_terms_cookie(response, pending, settings)
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[signup_terms_cookie_name(settings)]
    assert EMAIL.get_secret_value() not in response.headers["set-cookie"]
    assert len(cookie.value) <= 1536
    request = Request(
        {"type": "http", "headers": [(b"cookie", f"{cookie.key}={cookie.value}".encode())]}
    )
    decoded = decode_signup_terms_receipt(
        read_signup_terms_cookie(request, settings), EMAIL, settings
    )
    assert decoded == pending
    assert decoded.confirmed_user_id is None
    assert cookie["secure"] and cookie["httponly"]
    assert cookie["path"] == "/" and cookie["samesite"].lower() == "lax"
    assert 1 <= int(cookie["max-age"]) <= 3600


def test_confirmation_preserves_original_agreement_time_and_expiry(settings: Settings) -> None:
    pending = make_signup_terms_receipt(EMAIL)
    confirmed = pending.model_copy(update={"confirmed_user_id": uuid4()})
    response = Response()
    set_signup_terms_cookie(response, confirmed, settings)
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    decoded = decode_signup_terms_receipt(
        SecretStr(cookies[signup_terms_cookie_name(settings)].value), EMAIL, settings
    )
    assert decoded == confirmed
    assert decoded.accepted_at == pending.accepted_at
    assert decoded.expires_at == pending.expires_at


@pytest.mark.parametrize(
    "change", ["old-version", "expired", "future", "extended", "wrong-purpose", "missing-fields"]
)
def test_invalid_signed_receipts_are_not_agreement(settings: Settings, change: str) -> None:
    now = datetime.now(UTC)
    changes: dict[str, object] = {}
    if change == "old-version":
        changes["terms_version"] = "previous"
    elif change == "expired":
        changes.update(accepted_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
    elif change == "future":
        changes.update(
            accepted_at=now + timedelta(minutes=5), expires_at=now + timedelta(minutes=10)
        )
    elif change == "extended":
        changes["expires_at"] = now + timedelta(days=1)
    elif change == "wrong-purpose":
        changes["purpose"] = "provider_access"
    else:
        changes["email_hash"] = ""
    assert decode_signup_terms_receipt(encoded(settings, **changes), EMAIL, settings) is None


def test_tampering_wrong_key_and_different_email_are_ignored(settings: Settings) -> None:
    value = encoded(settings)
    assert decode_signup_terms_receipt(value, SecretStr("other@example.test"), settings) is None
    other = IsolatedSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii"))
    )
    assert decode_signup_terms_receipt(value, EMAIL, other) is None
    altered = value.get_secret_value()[:20] + "AA" + value.get_secret_value()[22:]
    assert decode_signup_terms_receipt(SecretStr(altered), EMAIL, settings) is None
    assert decode_signup_terms_receipt(SecretStr("A" * 1537), EMAIL, settings) is None


def test_provider_tokens_cannot_be_used_as_agreement_receipts(settings: Settings) -> None:
    key = settings.account_session_encryption_key
    assert key is not None
    value = SecretStr(
        AccountTokenCipher(key).encrypt(SecretStr("synthetic-provider-access-token")).decode()
    )
    assert decode_signup_terms_receipt(value, EMAIL, settings) is None


@pytest.mark.parametrize("secure", [False, True])
def test_receipt_deletion_uses_the_same_scope(settings: Settings, secure: bool) -> None:
    settings.account_cookie_secure = secure
    response = Response()
    clear_signup_terms_cookie(response, settings)
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[signup_terms_cookie_name(settings)]
    assert cookie.value == "" and cookie["max-age"] == "0"
    assert bool(cookie["secure"]) is secure
    assert cookie["httponly"] and cookie["path"] == "/"


@pytest.mark.parametrize(
    "kind", ["confirmed", "pending", "different-account", "old-version", "expired"]
)
def test_google_receipt_requires_current_otp_bound_subject(settings: Settings, kind: str) -> None:
    from uuid import uuid4

    from app.account_signup_terms import decode_confirmed_signup_terms_receipt

    user_id = uuid4()
    updates: dict[str, object] = {"confirmed_user_id": user_id}
    if kind == "pending":
        updates["confirmed_user_id"] = None
    elif kind == "different-account":
        updates["confirmed_user_id"] = uuid4()
    elif kind == "old-version":
        updates["terms_version"] = "old"
    elif kind == "expired":
        updates.update(
            accepted_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
    receipt = decode_confirmed_signup_terms_receipt(encoded(settings, **updates), user_id, settings)
    assert (receipt is not None) == (kind == "confirmed")
