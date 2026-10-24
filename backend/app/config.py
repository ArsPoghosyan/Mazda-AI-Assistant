"""Validated backend configuration."""

from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import Field, HttpUrl, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[1] / ".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        hide_input_in_errors=True,
    )
    database_url: SecretStr | None = None
    migration_database_url: SecretStr | None = None
    db_pool_size: int = Field(default=2, ge=1, le=5)
    db_connect_timeout_seconds: int = Field(default=5, ge=1, le=30)
    db_readiness_timeout_seconds: int = Field(default=8, ge=1, le=30)
    auth_rate_limit_cleanup_enabled: bool = False
    auth_rate_limit_cleanup_interval_seconds: int = Field(default=300, ge=60, le=86400)
    auth_rate_limit_cleanup_batch_size: int = Field(default=100, ge=1, le=1000)
    auth_rate_limit_cleanup_timeout_seconds: int = Field(default=5, ge=1, le=30)
    guest_session_inactivity_days: int = Field(default=30, ge=1)
    guest_cookie_secure: bool = True
    csrf_trusted_origins: tuple[str, ...] = ()
    guest_session_api_enabled: bool = False
    guest_creation_ip_max_requests: int = Field(default=10, ge=1, le=1000)
    guest_creation_ip_window_seconds: int = Field(default=600, ge=60, le=86400)
    guest_session_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    supabase_auth_issuer: HttpUrl | None = None
    supabase_auth_publishable_key: SecretStr | None = None
    supabase_auth_audience: str = Field(
        default="authenticated",
        min_length=1,
        max_length=128,
    )
    supabase_auth_iat_clock_skew_seconds: int = Field(default=5, ge=0, le=30)
    account_session_encryption_key: SecretStr | None = None
    account_session_inactivity_days: int = Field(default=7, ge=1)
    account_session_absolute_lifetime_days: int = Field(default=30, ge=1)
    account_cookie_secure: bool = True
    account_session_api_enabled: bool = False
    account_session_auth_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_sign_in_api_enabled: bool = False
    account_sign_in_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_sign_in_ip_max_requests: int = Field(
        default=30,
        ge=1,
        le=1000,
    )
    account_sign_in_ip_window_seconds: int = Field(
        default=600,
        ge=60,
        le=86400,
    )
    account_sign_out_api_enabled: bool = False
    account_sign_out_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_sign_up_api_enabled: bool = False
    account_sign_up_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_sign_up_ip_max_requests: int = Field(default=10, ge=1, le=1000)
    account_sign_up_ip_window_seconds: int = Field(default=600, ge=60, le=86400)
    account_email_confirmation_api_enabled: bool = False
    account_email_confirmation_ip_max_requests: int = Field(default=10, ge=1, le=1000)
    account_email_confirmation_ip_window_seconds: int = Field(default=600, ge=60, le=86400)
    account_email_confirmation_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_password_recovery_api_enabled: bool = False
    account_password_recovery_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_password_recovery_ip_max_requests: int = Field(
        default=10,
        ge=1,
        le=1000,
    )
    account_password_recovery_ip_window_seconds: int = Field(
        default=600,
        ge=60,
        le=86400,
    )
    auth_rate_limit_hmac_secret: SecretStr | None = None
    account_password_reset_api_enabled: bool = False
    account_password_reset_ip_max_requests: int = Field(default=10, ge=1, le=1000)
    account_password_reset_ip_window_seconds: int = Field(default=600, ge=60, le=86400)
    account_password_reset_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_google_oauth_api_enabled: bool = False
    account_google_oauth_ip_max_requests: int = Field(default=10, ge=1, le=1000)
    account_google_oauth_ip_window_seconds: int = Field(default=600, ge=60, le=86400)
    account_google_oauth_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=30,
    )
    account_google_oauth_attempt_lifetime_seconds: int = Field(
        default=600,
        ge=60,
        le=900,
    )
    account_google_oauth_callback_url: HttpUrl | None = None
    turnstile_secret_key: SecretStr | None = None
    turnstile_allowed_hostnames: tuple[str, ...] = ()
    turnstile_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=30,
    )

    @field_validator("account_google_oauth_callback_url", mode="before")
    @classmethod
    def validate_raw_google_callback_url(cls, value: object) -> object:
        """Reject ambiguous spellings before URL parsing can normalize them."""
        if value is None:
            return None
        if not isinstance(value, (str, HttpUrl)):
            raise ValueError("Invalid Google OAuth callback URL.")
        raw = str(value)
        if (
            len(raw) > 2048
            or any(ord(character) < 33 or ord(character) > 126 for character in raw)
            or any(character in raw for character in ("\\", "?", "#"))
        ):
            raise ValueError("Invalid Google OAuth callback URL.")
        try:
            parsed = urlsplit(raw)
        except ValueError:
            raise ValueError("Invalid Google OAuth callback URL.") from None
        if (
            parsed.path != "/api/v1/account/google/callback"
            or parsed.username is not None
            or parsed.password is not None
            or (
                parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            )
        ):
            raise ValueError("Invalid Google OAuth callback URL.")
        return value

    @field_validator("account_google_oauth_callback_url")
    @classmethod
    def validate_google_callback_url(
        cls, value: HttpUrl | None, info: ValidationInfo
    ) -> HttpUrl | None:
        if value is None:
            return None
        if (
            value.username is not None
            or value.password is not None
            or value.query is not None
            or value.fragment is not None
            or value.host is None
            or "*" in value.host
            or value.path != "/api/v1/account/google/callback"
        ):
            raise ValueError("Invalid Google OAuth callback URL.")
        if value.scheme != "https" and not (
            value.scheme == "http"
            and value.host in ("127.0.0.1", "localhost", "[::1]")
            and info.data.get("account_cookie_secure", True) is False
        ):
            raise ValueError("Google OAuth callbacks require HTTPS outside local development.")
        return value

    @field_validator("supabase_auth_publishable_key")
    @classmethod
    def validate_supabase_auth_publishable_key(
        cls,
        value: SecretStr | None,
    ) -> SecretStr | None:
        if value is None:
            return None

        raw_key = value.get_secret_value()
        prefix = "sb_publishable_"

        if (
            not raw_key.startswith(prefix)
            or len(raw_key) <= len(prefix)
            or len(raw_key) > 512
            or any(ord(character) < 33 or ord(character) > 126 for character in raw_key)
        ):
            raise ValueError(
                "Supabase Auth requires a publishable key without whitespace or control characters."
            )

        return value

    @field_validator("account_session_encryption_key")
    @classmethod
    def validate_account_session_encryption_key(
        cls,
        value: SecretStr | None,
    ) -> SecretStr | None:
        if value is None:
            return None

        raw_key = value.get_secret_value()
        error_message = "Account session encryption key must be a valid Fernet key."

        if len(raw_key) != 44 or not raw_key.isascii():
            raise ValueError(error_message)

        try:
            Fernet(raw_key.encode("ascii"))
        except ValueError:
            raise ValueError(error_message) from None

        return value

    @field_validator("auth_rate_limit_hmac_secret")
    @classmethod
    def validate_auth_rate_limit_hmac_secret(
        cls,
        value: SecretStr | None,
    ) -> SecretStr | None:
        if value is None:
            return None

        raw_secret = value.get_secret_value()
        if len(raw_secret) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in raw_secret
        ):
            raise ValueError(
                "Authentication rate-limit secret must contain exactly 64 hexadecimal characters."
            )

        return value

    @field_validator("supabase_auth_issuer")
    @classmethod
    def validate_supabase_auth_issuer(
        cls,
        value: HttpUrl | None,
    ) -> HttpUrl | None:
        if value is None:
            return None

        if (
            value.scheme != "https"
            or value.username is not None
            or value.password is not None
            or value.query is not None
            or value.fragment is not None
            or value.path != "/auth/v1"
        ):
            raise ValueError(
                "Supabase issuer must be an HTTPS URL ending in /auth/v1 "
                "without credentials, query parameters, or a fragment"
            )

        return value


class MigrationSettings(Settings):
    """Load the separate configuration used by Alembic."""

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[1] / ".env.migrations",
    )
