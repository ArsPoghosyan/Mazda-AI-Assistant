"""Account-session encryption configuration; no persisted keys or live services."""

from base64 import urlsafe_b64encode

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedSessionSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_session_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACCOUNT_SESSION_ENCRYPTION_KEY",
        "SUPABASE_AUTH_ISSUER",
        "SUPABASE_AUTH_AUDIENCE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_encryption_key_is_optional() -> None:
    assert IsolatedSessionSettings().account_session_encryption_key is None


def test_valid_key_is_accepted_and_redacted() -> None:
    raw_key = Fernet.generate_key().decode("ascii")
    settings = IsolatedSessionSettings.model_validate({"account_session_encryption_key": raw_key})
    secret = settings.account_session_encryption_key

    assert isinstance(secret, SecretStr)
    assert secret.get_secret_value() == raw_key
    assert raw_key not in str(secret)
    assert raw_key not in repr(settings)
    assert raw_key not in settings.model_dump_json()


def test_key_can_be_loaded_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("ACCOUNT_SESSION_ENCRYPTION_KEY", raw_key)

    secret = IsolatedSessionSettings().account_session_encryption_key

    assert secret is not None
    assert secret.get_secret_value() == raw_key


def test_empty_environment_value_remains_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCOUNT_SESSION_ENCRYPTION_KEY", "")

    assert IsolatedSessionSettings().account_session_encryption_key is None


@pytest.mark.parametrize(
    "raw_key",
    [
        pytest.param("", id="empty-explicit-value"),
        pytest.param("not-a-fernet-key", id="malformed-key"),
        pytest.param("A" * 43, id="too-short"),
        pytest.param("A" * 45, id="too-long"),
        pytest.param("!" * 44, id="invalid-alphabet"),
        pytest.param("\N{SNOWMAN}" * 44, id="non-ascii"),
        pytest.param(
            urlsafe_b64encode(b"x" * 31).decode("ascii"),
            id="decoded-key-too-short",
        ),
        pytest.param(
            urlsafe_b64encode(b"x" * 33).decode("ascii"),
            id="decoded-key-too-long",
        ),
    ],
)
def test_invalid_keys_are_rejected(raw_key: str) -> None:
    with pytest.raises(ValidationError, match="must be a valid Fernet key"):
        IsolatedSessionSettings.model_validate({"account_session_encryption_key": raw_key})


@pytest.mark.parametrize("source", ["model", "environment"])
def test_validation_messages_hide_invalid_key(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    # Correct encoded length, but not a 32-byte encryption key.
    raw_key = urlsafe_b64encode(b"x" * 31).decode("ascii")

    with pytest.raises(ValidationError) as caught:
        if source == "environment":
            monkeypatch.setenv("ACCOUNT_SESSION_ENCRYPTION_KEY", raw_key)
            IsolatedSessionSettings()
        else:
            IsolatedSessionSettings.model_validate({"account_session_encryption_key": raw_key})

    assert "must be a valid Fernet key" in str(caught.value)
    assert raw_key not in str(caught.value)
    assert raw_key not in repr(caught.value)
    assert raw_key not in caught.value.json(include_input=False)
