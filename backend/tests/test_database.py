"""Database configuration tests; no live database is required."""

import asyncio
from pathlib import Path

import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy.engine import URL

from app.config import Settings
from app.database import create_database_engine


class IsolatedSettings(Settings):
    """Use production settings without reading a local dotenv file."""

    model_config = SettingsConfigDict(env_file=None)


def settings_for(url: str | None) -> Settings:
    return IsolatedSettings(
        database_url=SecretStr(url) if url is not None else None,
    )


def test_missing_database_url_returns_no_engine() -> None:
    assert create_database_engine(settings_for(None)) is None


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "sqlite:///test.db",
        "postgresql+psycopg:///postgres",
        "postgresql+psycopg://test:test@localhost",
        "postgresql+psycopg://test:test@database.example/postgres",
        "postgresql+psycopg://test:test@database.example/postgres?sslmode=require",
        "postgresql+psycopg://test:test@database.example/postgres?sslmode=verify-full",
    ],
)
def test_rejects_invalid_or_insecure_configuration(url: str) -> None:
    with pytest.raises(ValueError):
        create_database_engine(settings_for(url))


def test_rejects_missing_certificate_file(tmp_path: Path) -> None:
    url = URL.create(
        "postgresql+psycopg",
        username="test",
        password="test",
        host="database.example",
        database="postgres",
        query={
            "sslmode": "verify-full",
            "sslrootcert": str(tmp_path / "missing-ca.crt"),
        },
    )

    with pytest.raises(ValueError, match="certificate file was not found"):
        create_database_engine(settings_for(url.render_as_string(hide_password=False)))


def test_local_engine_can_be_created_without_connecting() -> None:
    engine = create_database_engine(
        settings_for("postgresql+psycopg://test:test@127.0.0.1:15432/test")
    )

    assert engine is not None
    asyncio.run(engine.dispose())
