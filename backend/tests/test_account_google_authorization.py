"""Allowlisted authorization query construction without provider requests."""

from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from app.account_google_authorization import (
    GoogleAuthorizationUnavailable,
    build_google_authorization_url,
)
from app.account_oauth_material import InvalidOAuthLoginMaterial, create_oauth_login_material
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings

CALLBACK = "https://askm6.com/api/v1/account/google/callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.fixture
def settings() -> Settings:
    return IsolatedSettings.model_validate(
        {
            "supabase_auth_issuer": "https://auth.example.com/auth/v1",
            "supabase_auth_publishable_key": SecretStr("sb_publishable_synthetic"),
            "account_google_oauth_callback_url": CALLBACK,
            "account_google_oauth_api_enabled": False,
            "account_cookie_secure": True,
        }
    )


def test_authorization_uses_only_fixed_provider_callback_and_s256(settings: Settings) -> None:
    result = build_google_authorization_url(settings, CHALLENGE)
    parsed = urlsplit(result)
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "auth.example.com",
        "/auth/v1/authorize",
    )
    assert parse_qs(parsed.query, strict_parsing=True) == {
        "provider": ["google"],
        "redirect_to": [CALLBACK],
        "code_challenge": [CHALLENGE],
        "code_challenge_method": ["s256"],
    }
    assert parsed.fragment == ""
    assert "state=" not in result
    assert "sb_publishable_synthetic" not in result
    assert settings.account_google_oauth_api_enabled is False


def test_local_callback_is_encoded_once_and_preserves_its_port(settings: Settings) -> None:
    callback = "http://127.0.0.1:5173/api/v1/account/google/callback"
    local = IsolatedSettings.model_validate(
        {
            "supabase_auth_issuer": settings.supabase_auth_issuer,
            "account_google_oauth_callback_url": callback,
            "account_cookie_secure": False,
        }
    )
    result = build_google_authorization_url(local, CHALLENGE)
    assert parse_qs(urlsplit(result).query)["redirect_to"] == [callback]
    assert "%253A" not in result


@pytest.mark.parametrize("missing", ["supabase_auth_issuer", "account_google_oauth_callback_url"])
def test_missing_configuration_fails_without_constructing_a_destination(
    settings: Settings, missing: str
) -> None:
    settings = settings.model_copy(update={missing: None})
    with pytest.raises(GoogleAuthorizationUnavailable, match="^Google sign-in is unavailable\\.$"):
        build_google_authorization_url(settings, CHALLENGE)


@pytest.mark.parametrize(
    "challenge",
    [
        "",
        "a" * 42,
        "a" * 44,
        "a" * 42 + "=",
        "a" * 42 + "+",
        "a" * 42 + "/",
        "a" * 42 + "\n",
        "a" * 42 + "\N{SNOWMAN}",
        "a&provider=github&redirect_to=https://other.example",
    ],
)
def test_invalid_challenge_cannot_inject_authorization_parameters(
    settings: Settings, challenge: str
) -> None:
    with pytest.raises(InvalidOAuthLoginMaterial, match="^Invalid OAuth login material\\.$"):
        build_google_authorization_url(settings, challenge)


def test_generated_material_exposes_only_the_public_challenge(settings: Settings) -> None:
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    material = create_oauth_login_material(cipher)
    verifier = cipher.decrypt(material.pkce_verifier_ciphertext).get_secret_value()
    result = build_google_authorization_url(settings, material.code_challenge)

    assert verifier not in result
    assert material.browser_token.get_secret_value() not in result
    assert material.pkce_verifier_ciphertext.decode("ascii") not in result
    assert parse_qs(urlsplit(result).query)["code_challenge"] == [material.code_challenge]
