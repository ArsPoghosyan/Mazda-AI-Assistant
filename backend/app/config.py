"""Validated backend configuration."""

from pathlib import Path

from pydantic import Field, SecretStr
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


class MigrationSettings(Settings):
    """Load the separate configuration used by Alembic."""

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[1] / ".env.migrations",
    )
