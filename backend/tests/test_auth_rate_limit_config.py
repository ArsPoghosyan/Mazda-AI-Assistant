"""HMAC secret configuration using synthetic values and no private files."""

from secrets import token_hex

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedRateLimitSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AUTH_RATE_LIMIT_HMAC_SECRET",
        "ACCOUNT_SESSION_ENCRYPTION_KEY",
        "ACCOUNT_PASSWORD_RECOVERY_API_ENABLED",
        "ACCOUNT_PASSWORD_RESET_API_ENABLED",
        "ACCOUNT_SIGN_IN_API_ENABLED",
        "ACCOUNT_SIGN_UP_API_ENABLED",
        "ACCOUNT_SESSION_API_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_missing_secret_is_optional_during_configuration() -> None:
    assert IsolatedRateLimitSettings().auth_rate_limit_hmac_secret is None


@pytest.mark.parametrize("secret", ["ab" * 32, "AB" * 32, "aB01" * 16])
def test_exact_ascii_hex_formats_are_accepted_without_modification(secret: str) -> None:
    settings = IsolatedRateLimitSettings(auth_rate_limit_hmac_secret=SecretStr(secret))
    value = settings.auth_rate_limit_hmac_secret
    assert isinstance(value, SecretStr)
    assert value.get_secret_value() == secret
    assert len(bytes.fromhex(value.get_secret_value())) == 32


def test_explicit_none_is_accepted() -> None:
    settings = IsolatedRateLimitSettings.model_validate({"auth_rate_limit_hmac_secret": None})
    assert settings.auth_rate_limit_hmac_secret is None


@pytest.mark.parametrize(
    "secret",
    [
        "",
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "Ａ" * 64,
        "a" * 31 + " " + "a" * 32,
        "a" * 31 + "\t" + "a" * 32,
        "a" * 31 + "\x00" + "a" * 32,
        " " + "ab" * 32,
        "ab" * 32 + " ",
        "ab" * 32 + "\n",
        "0x" + "ab" * 32,
        Fernet.generate_key().decode("ascii"),
        123,
        ["ab" * 32],
    ],
    ids=[
        "empty-explicit",
        "short",
        "long",
        "nonhex",
        "nonascii",
        "space",
        "tab",
        "nul",
        "leading-space",
        "trailing-space",
        "newline",
        "hex-prefix",
        "fernet-format",
        "integer",
        "list",
    ],
)
def test_invalid_explicit_formats_are_rejected(secret: object) -> None:
    with pytest.raises(ValidationError) as caught:
        IsolatedRateLimitSettings.model_validate({"auth_rate_limit_hmac_secret": secret})
    assert any(
        error["loc"] == ("auth_rate_limit_hmac_secret",)
        for error in caught.value.errors(include_input=False)
    )


def test_environment_loads_valid_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = token_hex(32)
    monkeypatch.setenv("AUTH_RATE_LIMIT_HMAC_SECRET", secret)
    value = IsolatedRateLimitSettings().auth_rate_limit_hmac_secret
    assert isinstance(value, SecretStr)
    assert value.get_secret_value() == secret


@pytest.mark.parametrize("secret", ["short", "z" * 64, "ab" * 32 + "\n"])
def test_invalid_environment_is_rejected_without_fallback(
    monkeypatch: pytest.MonkeyPatch, secret: str
) -> None:
    monkeypatch.setenv("AUTH_RATE_LIMIT_HMAC_SECRET", secret)
    with pytest.raises(ValidationError):
        IsolatedRateLimitSettings()


def test_empty_environment_keeps_optional_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_RATE_LIMIT_HMAC_SECRET", "")
    assert IsolatedRateLimitSettings().auth_rate_limit_hmac_secret is None


def test_explicit_input_overrides_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_RATE_LIMIT_HMAC_SECRET", "invalid-environment")
    secret = token_hex(32)
    value = IsolatedRateLimitSettings(
        auth_rate_limit_hmac_secret=SecretStr(secret)
    ).auth_rate_limit_hmac_secret
    assert isinstance(value, SecretStr)
    assert value.get_secret_value() == secret


def test_secret_stays_masked_in_representations_and_json() -> None:
    secret = token_hex(32)
    settings = IsolatedRateLimitSettings(auth_rate_limit_hmac_secret=SecretStr(secret))
    for representation in (str(settings), repr(settings), settings.model_dump_json()):
        assert secret not in representation
        assert "**********" in representation
    assert isinstance(settings.model_dump()["auth_rate_limit_hmac_secret"], SecretStr)


def test_validation_message_hides_invalid_secret() -> None:
    secret = "invalid-" + token_hex(32)
    with pytest.raises(ValidationError) as caught:
        IsolatedRateLimitSettings.model_validate({"auth_rate_limit_hmac_secret": secret})
    assert secret not in str(caught.value)
    assert "64 hexadecimal characters" in str(caught.value)


def test_hmac_and_session_encryption_secrets_are_independent() -> None:
    hmac_secret = token_hex(32)
    encryption_key = Fernet.generate_key().decode("ascii")
    settings = IsolatedRateLimitSettings(
        auth_rate_limit_hmac_secret=SecretStr(hmac_secret),
        account_session_encryption_key=SecretStr(encryption_key),
    )
    assert settings.auth_rate_limit_hmac_secret is not None
    assert settings.account_session_encryption_key is not None
    assert settings.auth_rate_limit_hmac_secret.get_secret_value() == hmac_secret
    assert settings.account_session_encryption_key.get_secret_value() == encryption_key


def test_setting_hmac_secret_does_not_enable_account_endpoints() -> None:
    settings = IsolatedRateLimitSettings(auth_rate_limit_hmac_secret=SecretStr(token_hex(32)))
    assert settings.account_password_recovery_api_enabled is False
    assert settings.account_password_reset_api_enabled is False
    assert settings.account_sign_in_api_enabled is False
    assert settings.account_sign_up_api_enabled is False
    assert settings.account_session_api_enabled is False
    assert settings.account_session_encryption_key is None


def test_encryption_key_does_not_supply_a_missing_hmac_secret() -> None:
    settings = IsolatedRateLimitSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii"))
    )
    assert settings.auth_rate_limit_hmac_secret is None
