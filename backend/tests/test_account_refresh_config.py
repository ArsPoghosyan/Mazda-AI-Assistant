"""Refresh configuration tests without private files or live services."""

import pytest
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedRefreshSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_refresh_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUPABASE_AUTH_PUBLISHABLE_KEY", raising=False)


def test_publishable_key_is_optional() -> None:
    assert IsolatedRefreshSettings().supabase_auth_publishable_key is None


def test_valid_key_is_accepted_and_masked() -> None:
    raw_key = "sb_publishable_synthetic_test_value"
    settings = IsolatedRefreshSettings.model_validate({"supabase_auth_publishable_key": raw_key})
    key = settings.supabase_auth_publishable_key

    assert isinstance(key, SecretStr)
    assert key.get_secret_value() == raw_key
    assert raw_key not in str(key)
    assert raw_key not in repr(settings)
    assert raw_key not in settings.model_dump_json()


def test_key_can_be_loaded_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_key = "sb_publishable_synthetic_environment_value"
    monkeypatch.setenv("SUPABASE_AUTH_PUBLISHABLE_KEY", raw_key)

    key = IsolatedRefreshSettings().supabase_auth_publishable_key

    assert key is not None
    assert key.get_secret_value() == raw_key


def test_empty_environment_value_remains_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUPABASE_AUTH_PUBLISHABLE_KEY", "")

    assert IsolatedRefreshSettings().supabase_auth_publishable_key is None


def test_maximum_configured_length_is_accepted() -> None:
    prefix = "sb_publishable_"
    raw_key = prefix + "x" * (512 - len(prefix))

    settings = IsolatedRefreshSettings.model_validate({"supabase_auth_publishable_key": raw_key})

    key = settings.supabase_auth_publishable_key
    assert key is not None
    assert key.get_secret_value() == raw_key


@pytest.mark.parametrize(
    "raw_key",
    [
        "",
        "sb_publishable_",
        "not-a-publishable-key",
        "sb_secret_synthetic",
        "eyJhbGciOiJIUzI1NiJ9.synthetic.signature",
        " sb_publishable_synthetic",
        "sb_publishable_synthetic ",
        "sb_publishable_synthetic\n",
        "sb_publishable_synthetic\r",
        "sb_publishable_synthetic\t",
        "sb_publishable_\N{SNOWMAN}",
        "sb_publishable_" + "x" * 512,
    ],
)
def test_invalid_key_is_rejected(raw_key: str) -> None:
    with pytest.raises(ValidationError, match="requires a publishable key"):
        IsolatedRefreshSettings.model_validate({"supabase_auth_publishable_key": raw_key})


@pytest.mark.parametrize("source", ["model", "environment"])
def test_validation_messages_hide_invalid_key(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    raw_key = "sb_secret_synthetic_private_value"

    with pytest.raises(ValidationError) as caught:
        if source == "environment":
            monkeypatch.setenv("SUPABASE_AUTH_PUBLISHABLE_KEY", raw_key)
            IsolatedRefreshSettings()
        else:
            IsolatedRefreshSettings.model_validate({"supabase_auth_publishable_key": raw_key})

    assert raw_key not in str(caught.value)
    assert raw_key not in repr(caught.value)
    assert raw_key not in str(caught.value.errors(include_input=False))
