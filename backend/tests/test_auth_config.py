"""Account-auth configuration tests; no network or database is required."""

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict

from app.config import Settings


class IsolatedAuthSettings(Settings):
    """Do not read the developer's private dotenv file."""

    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture(autouse=True)
def clear_auth_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUPABASE_AUTH_ISSUER", raising=False)
    monkeypatch.delenv("SUPABASE_AUTH_AUDIENCE", raising=False)


def test_auth_configuration_is_optional() -> None:
    settings = IsolatedAuthSettings()

    assert settings.supabase_auth_issuer is None
    assert settings.supabase_auth_audience == "authenticated"


def test_valid_auth_issuer_is_accepted() -> None:
    issuer = "https://auth.example.test/auth/v1"

    settings = IsolatedAuthSettings.model_validate({"supabase_auth_issuer": issuer})

    assert str(settings.supabase_auth_issuer) == issuer
    assert settings.supabase_auth_audience == "authenticated"


@pytest.mark.parametrize(
    "issuer",
    [
        "http://auth.example.test/auth/v1",
        "https://user@auth.example.test/auth/v1",
        "https://user:password@auth.example.test/auth/v1",
        "https://auth.example.test/auth/v1?debug=true",
        "https://auth.example.test/auth/v1#fragment",
        "https://auth.example.test/auth/v1/",
        "https://auth.example.test/",
        "not-a-url",
    ],
)
def test_invalid_auth_issuer_is_rejected(issuer: str) -> None:
    with pytest.raises(ValidationError):
        IsolatedAuthSettings.model_validate({"supabase_auth_issuer": issuer})


@pytest.mark.parametrize("audience", ["", "x" * 129])
def test_invalid_audience_length_is_rejected(audience: str) -> None:
    with pytest.raises(ValidationError):
        IsolatedAuthSettings.model_validate({"supabase_auth_audience": audience})
