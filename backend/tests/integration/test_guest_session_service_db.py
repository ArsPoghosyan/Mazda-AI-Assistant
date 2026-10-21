"""Verified guest creation against guarded local PostgreSQL."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import timedelta
from secrets import token_urlsafe
from unittest.mock import Mock

import httpx2
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.config import Settings
from app.guest_session_service import EstablishedGuestSession, establish_guest_session
from app.guest_tokens import hash_guest_token
from app.models import GuestSession

pytestmark = pytest.mark.integration

HOSTNAME = "guest.example.test"
CHALLENGE = "synthetic-guest-challenge"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class JsonStream(httpx2.AsyncByteStream):
    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@pytest.mark.parametrize(
    "fail_commit",
    [False, True],
    ids=["committed", "rolled-back"],
)
def test_verified_creation_obeys_commit_boundary(
    integration_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    fail_commit: bool,
) -> None:
    raw_token = token_urlsafe(32)
    token_hash = hash_guest_token(raw_token)
    generator = Mock(return_value=raw_token)
    monkeypatch.setattr("app.guest_sessions.generate_guest_token", generator)

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": None,
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "guest_session_inactivity_days": 30,
            "turnstile_secret_key": "synthetic-turnstile-secret",
            "turnstile_allowed_hostnames": (HOSTNAME,),
            "turnstile_timeout_seconds": 5,
        }
    )

    events: list[str] = []
    requests: list[httpx2.Request] = []
    statement = select(GuestSession).where(GuestSession.token_hash == token_hash)

    provider_response = httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=JsonStream(
            {
                "success": True,
                "hostname": HOSTNAME,
                "action": "guest_start",
                "error-codes": [],
            }
        ),
    )

    def provider(request: httpx2.Request) -> httpx2.Response:
        assert events == []
        assert request.method == "POST"
        assert str(request.url) == ("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        assert json.loads(request.content) == {
            "secret": "synthetic-turnstile-secret",
            "response": CHALLENGE,
        }
        requests.append(request)
        events.append("verify")
        return provider_response

    async def run() -> EstablishedGuestSession | None:
        engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            connect_args={
                "connect_timeout": 5,
                "hostaddr": "127.0.0.1",
            },
            echo=False,
            hide_parameters=True,
        )

        @event.listens_for(engine.sync_engine, "begin")
        def restrict_transaction(connection: Connection) -> None:
            events.append("begin")
            connection.exec_driver_sql("SET LOCAL TIME ZONE 'UTC'")
            connection.exec_driver_sql("SET LOCAL ROLE askm6_app")
            restricted = connection.scalar(
                text(
                    "SELECT current_user = 'askm6_app' "
                    "AND NOT rolsuper AND NOT rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            )
            assert restricted is True

        @event.listens_for(engine.sync_engine, "commit")
        def inspect_before_commit(connection: Connection) -> None:
            events.append("commit")
            stored = connection.execute(statement).one()
            assert stored.token_hash == token_hash

            if fail_commit:
                connection.exec_driver_sql("SELECT 1 / 0")
                raise AssertionError("Expected PostgreSQL division by zero.")

        try:
            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(provider),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                if fail_commit:
                    with pytest.raises(SQLAlchemyError):
                        await establish_guest_session(
                            engine,
                            browser_token=None,
                            challenge_token=SecretStr(CHALLENGE),
                            settings=settings,
                            client=client,
                        )
                    return None

                result = await establish_guest_session(
                    engine,
                    browser_token=None,
                    challenge_token=SecretStr(CHALLENGE),
                    settings=settings,
                    client=client,
                )
                events.append("returned")
                return result
        finally:
            await engine.dispose()

    try:
        result = asyncio.run(run(), loop_factory=asyncio.SelectorEventLoop)

        assert len(requests) == 1
        assert provider_response.is_closed
        generator.assert_called_once_with()

        with integration_engine.connect() as observer:
            stored = observer.execute(statement).one_or_none()

        if fail_commit:
            assert events == ["verify", "begin", "commit"]
            assert result is None
            assert stored is None
        else:
            assert events == ["verify", "begin", "commit", "returned"]
            assert result is not None
            assert stored is not None
            assert result.token.get_secret_value() == raw_token
            assert result.expires_at == stored.expires_at
            assert stored.token_hash == token_hash
            assert stored.token_hash != raw_token.encode("ascii")
            assert stored.created_at == stored.last_seen_at
            assert stored.expires_at - stored.created_at == timedelta(days=30)
            assert raw_token not in repr(result)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(GuestSession).where(GuestSession.token_hash == token_hash))
