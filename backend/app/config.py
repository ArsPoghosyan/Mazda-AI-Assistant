"""Validated backend configuration."""

from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import Field, HttpUrl, SecretStr, field_validator
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
    guest_session_inactivity_days: int = Field(default=30, ge=1)
    guest_cookie_secure: bool = True
    csrf_trusted_origins: tuple[str, ...] = ()
    guest_session_api_enabled: bool = False
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
    account_email_confirmation_api_enabled: bool = False
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
    turnstile_secret_key: SecretStr | None = None
    turnstile_allowed_hostnames: tuple[str, ...] = ()
    turnstile_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=30,
    )

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
