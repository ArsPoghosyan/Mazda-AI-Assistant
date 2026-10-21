"""Guest HTTP cookie lifecycle against the guarded local PostgreSQL database."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import httpx2
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, func, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.config import Settings
from app.guest_tokens import generate_guest_token, hash_guest_token
from app.main import create_app
from app.models import GuestSession

pytestmark = pytest.mark.integration


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class JsonStream(httpx2.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'{"success":true,"hostname":"askm6.com","action":"guest_start"}'


@pytest.mark.parametrize(
    "initial_cookie",
    ["missing", "malformed", "unknown", "expired"],
)
def test_http_creation_and_reuse_persist_the_same_session(
    integration_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    initial_cookie: str,
) -> None:
    origin = "https://askm6.com"
    token = generate_guest_token()
    verifier = hash_guest_token(token)
    unknown_token = generate_guest_token()
    unknown_verifier = hash_guest_token(unknown_token)

    settings = IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        guest_session_api_enabled=True,
        guest_cookie_secure=True,
        guest_session_inactivity_days=30,
        csrf_trusted_origins=(origin,),
        supabase_auth_issuer=None,
        supabase_auth_publishable_key=None,
        account_session_encryption_key=None,
        turnstile_secret_key=SecretStr("synthetic-test-secret"),
        turnstile_allowed_hostnames=("askm6.com",),
    )

    statement = select(
        GuestSession.id,
        GuestSession.token_hash,
        GuestSession.created_at,
        GuestSession.last_seen_at,
        GuestSession.expires_at,
    ).where(GuestSession.token_hash == verifier)

    expired_statement = select(
        GuestSession.id,
        GuestSession.token_hash,
        GuestSession.created_at,
        GuestSession.last_seen_at,
        GuestSession.expires_at,
    ).where(GuestSession.token_hash == unknown_verifier)

    with integration_engine.connect() as connection:
        assert connection.execute(statement).one_or_none() is None
        assert (
            connection.scalar(
                select(GuestSession.id).where(GuestSession.token_hash == unknown_verifier)
            )
            is None
        )

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
    def use_application_role(connection: Connection) -> None:
        connection.exec_driver_sql("SET LOCAL ROLE askm6_app")

        restricted = connection.scalar(
            text(
                "SELECT current_user = 'askm6_app' "
                "AND NOT rolsuper AND NOT rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        )
        assert restricted is True

    monkeypatch.setattr(
        "app.main.create_database_engine",
        Mock(return_value=engine),
    )

    # Keep the randomly generated test token known so cleanup remains possible
    # even if the response fails after the database commit.
    monkeypatch.setattr(
        "app.guest_sessions.generate_guest_token",
        lambda: token,
    )

    provider_requests: list[httpx2.Request] = []

    def verify_challenge(request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        assert str(request.url) == ("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        assert json.loads(request.content) == {
            "secret": "synthetic-test-secret",
            "response": "synthetic-guest-challenge",
        }
        provider_requests.append(request)
        return httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=JsonStream(),
        )

    http_client = httpx2.AsyncClient(
        transport=httpx2.MockTransport(verify_challenge),
        trust_env=False,
    )
    client_factory = Mock(return_value=http_client)
    monkeypatch.setattr(
        "app.main.httpx2",
        SimpleNamespace(AsyncClient=client_factory, Limits=httpx2.Limits),
    )

    expired_before: tuple[object, ...] | None = None

    try:
        if initial_cookie == "expired":
            assert token != unknown_token
            old_activity = func.statement_timestamp() - timedelta(days=31)

            with integration_engine.begin() as connection:
                connection.execute(
                    insert(GuestSession).values(
                        token_hash=unknown_verifier,
                        created_at=old_activity,
                        last_seen_at=old_activity,
                        expires_at=func.statement_timestamp() - timedelta(days=1),
                    )
                )
                expired_before = tuple(connection.execute(expired_statement).one())

        with TestClient(
            create_app(settings),
            base_url=origin,
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            if initial_cookie != "missing":
                incoming_token = "invalid-token" if initial_cookie == "malformed" else unknown_token
                client.cookies.set(
                    "__Host-askm6_guest",
                    incoming_token,
                    domain="askm6.com",
                    path="/",
                )

            first = client.post(
                "/api/v1/guest/session",
                headers={"Origin": origin},
                json={"turnstile_token": "synthetic-guest-challenge"},
            )

            assert first.status_code == 200
            assert first.json()["status"] == "ok"
            assert token not in first.text
            assert first.cookies.get("__Host-askm6_guest") == token
            assert first.headers["Cache-Control"] == "no-store"

            # A separate connection can see the row only after commit.
            with integration_engine.connect() as connection:
                before = connection.execute(statement).one()

            assert before.token_hash == verifier
            assert before.token_hash != token.encode("ascii")
            assert datetime.fromisoformat(first.json()["expires_at"]) == before.expires_at

            # TestClient automatically sends the cookie received above.
            second = client.post(
                "/api/v1/guest/session",
                headers={"Origin": origin},
            )

            assert second.status_code == 200
            assert second.cookies.get("__Host-askm6_guest") == token
            assert token not in second.text
            assert second.headers["Cache-Control"] == "no-store"
            # Only creation consumes a challenge; an active cookie refresh does not.
            assert len(provider_requests) == 1

            with integration_engine.connect() as connection:
                after = connection.execute(statement).one()

            assert after.id == before.id
            assert after.created_at == before.created_at
            assert after.token_hash == before.token_hash
            assert after.last_seen_at >= before.last_seen_at
            assert after.expires_at - after.last_seen_at == timedelta(days=30)
            assert datetime.fromisoformat(second.json()["expires_at"]) == after.expires_at

            if initial_cookie == "expired":
                assert expired_before is not None
                assert before.id != expired_before[0]
                assert first.cookies.get("__Host-askm6_guest") != unknown_token

                with integration_engine.connect() as connection:
                    expired_after = tuple(connection.execute(expired_statement).one())

                assert expired_after == expired_before

        assert http_client.is_closed
        client_factory.assert_called_once()

    finally:
        verifiers_to_delete = [verifier]
        if initial_cookie == "expired":
            verifiers_to_delete.append(unknown_verifier)

        with integration_engine.begin() as connection:
            connection.execute(
                delete(GuestSession).where(GuestSession.token_hash.in_(verifiers_to_delete))
            )
