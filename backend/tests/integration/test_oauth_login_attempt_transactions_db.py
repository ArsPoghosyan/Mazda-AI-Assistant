"""Committed OAuth service results and failed transaction completion on PostgreSQL."""

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

import app.account_oauth_transactions as transactions
from app.account_oauth_attempts import ConsumedOAuthLoginAttempt, consume_oauth_login_attempt
from app.account_oauth_material import (
    InvalidOAuthLoginMaterial,
    OAuthLoginMaterial,
    create_oauth_login_material,
)
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import OAuthLoginAttempt

pytestmark = pytest.mark.integration


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class Environment:
    settings: Settings
    generated_hashes: list[bytes]


@pytest.fixture
def environment(
    integration_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Environment]:
    generated_hashes: list[bytes] = []
    settings = IsolatedSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii")),
        account_google_oauth_attempt_lifetime_seconds=600,
        account_google_oauth_api_enabled=False,
    )

    def record_generated_material(cipher: AccountTokenCipher) -> OAuthLoginMaterial:
        material = create_oauth_login_material(cipher)
        generated_hashes.append(material.browser_token_hash)
        return material

    monkeypatch.setattr(
        "app.account_oauth_attempts.create_oauth_login_material", record_generated_material
    )
    try:
        yield Environment(settings, generated_hashes)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(
                delete(OAuthLoginAttempt).where(
                    OAuthLoginAttempt.browser_token_hash.in_(generated_hashes)
                )
            )


def app_engine(integration_engine: Engine) -> AsyncEngine:
    # The shared fixture validates the local URL, connected identity and migration.
    engine = create_async_engine(
        integration_engine.url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
        echo=False,
        hide_parameters=True,
    )

    def restrict_transaction(connection: Connection) -> None:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        connection.execute(text("SET LOCAL statement_timeout = '5s'"))
        assert connection.scalar(text("SELECT current_user")) == "askm6_app"

    event.listen(engine.sync_engine, "begin", restrict_transaction)
    return engine


def test_service_results_describe_committed_creation_replacement_and_consumption(
    integration_engine: Engine, environment: Environment
) -> None:
    async def check() -> None:
        engine = app_engine(integration_engine)
        try:
            first = await transactions.create_oauth_login_attempt_transaction(
                engine, environment.settings
            )
            async with engine.connect() as observer:
                assert (
                    await observer.scalar(
                        select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == first.attempt_id)
                    )
                    == first.attempt_id
                )

            replacement = await transactions.replace_oauth_login_attempt_transaction(
                engine, environment.settings, first.browser_token.get_secret_value()
            )
            async with engine.connect() as observer:
                assert (
                    await observer.scalar(
                        select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == first.attempt_id)
                    )
                    is None
                )
                assert (
                    await observer.scalar(
                        select(OAuthLoginAttempt.id).where(
                            OAuthLoginAttempt.id == replacement.attempt_id
                        )
                    )
                    == replacement.attempt_id
                )

            consumed = await transactions.consume_oauth_login_attempt_transaction(
                engine, replacement.browser_token.get_secret_value()
            )
            assert consumed.attempt_id == replacement.attempt_id
            async with engine.connect() as observer:
                assert (
                    await observer.scalar(
                        select(OAuthLoginAttempt.id).where(
                            OAuthLoginAttempt.id == replacement.attempt_id
                        )
                    )
                    is None
                )
            with pytest.raises(InvalidOAuthLoginMaterial):
                await transactions.consume_oauth_login_attempt_transaction(
                    engine, replacement.browser_token.get_secret_value()
                )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("operation", ["create", "replace", "consume"])
def test_precommit_database_failure_restores_original_database_state(
    integration_engine: Engine, environment: Environment, operation: str
) -> None:
    async def check() -> None:
        engine = app_engine(integration_engine)
        try:
            first = await transactions.create_oauth_login_attempt_transaction(
                engine, environment.settings
            )
            statement = select(OAuthLoginAttempt).where(
                OAuthLoginAttempt.browser_token_hash.in_(environment.generated_hashes)
            )
            async with engine.connect() as observer:
                original = (await observer.execute(statement)).all()

            failure = SQLAlchemyError("Synthetic failure before database COMMIT.")

            def reject_commit(connection: Connection) -> None:
                raise failure

            event.listen(engine.sync_engine, "commit", reject_commit, once=True)
            with pytest.raises(SQLAlchemyError) as caught:
                if operation == "create":
                    await transactions.create_oauth_login_attempt_transaction(
                        engine, environment.settings
                    )
                elif operation == "replace":
                    await transactions.replace_oauth_login_attempt_transaction(
                        engine, environment.settings, first.browser_token.get_secret_value()
                    )
                else:
                    await transactions.consume_oauth_login_attempt_transaction(
                        engine, first.browser_token.get_secret_value()
                    )
            assert caught.value is failure
            async with engine.connect() as observer:
                # Include all newly generated hashes, even if no result was returned.
                stored = (
                    await observer.execute(
                        select(OAuthLoginAttempt).where(
                            OAuthLoginAttempt.browser_token_hash.in_(environment.generated_hashes)
                        )
                    )
                ).all()
                assert stored == original
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_cancelled_service_consumption_rolls_back_before_commit(
    integration_engine: Engine, environment: Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def check() -> None:
        engine = app_engine(integration_engine)
        try:
            first = await transactions.create_oauth_login_attempt_transaction(
                engine, environment.settings
            )
            prepared = asyncio.Event()

            async def hold_consumption(
                connection: AsyncConnection, token: str | None
            ) -> ConsumedOAuthLoginAttempt:
                consumed = await consume_oauth_login_attempt(connection, token)
                prepared.set()
                await asyncio.Event().wait()
                return consumed

            monkeypatch.setattr(transactions, "consume_oauth_login_attempt", hold_consumption)
            async with asyncio.timeout(5):
                async with asyncio.TaskGroup() as group:
                    task = group.create_task(
                        transactions.consume_oauth_login_attempt_transaction(
                            engine, first.browser_token.get_secret_value()
                        )
                    )
                    await prepared.wait()
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
            assert task.cancelled()
            async with engine.connect() as observer:
                assert (
                    await observer.scalar(
                        select(OAuthLoginAttempt.id).where(OAuthLoginAttempt.id == first.attempt_id)
                    )
                    == first.attempt_id
                )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
