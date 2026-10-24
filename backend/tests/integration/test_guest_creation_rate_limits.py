"""New guest limits and active-cookie reuse on guarded PostgreSQL; no live HTTP."""

import asyncio
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_hex, token_urlsafe
from unittest.mock import AsyncMock, Mock

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, insert, select, text, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.auth_rate_limit_keys import (
    get_email_confirmation_ip_key,
    get_guest_creation_ip_key,
    get_password_recovery_ip_key,
    get_password_reset_ip_key,
    get_sign_in_ip_key,
    get_sign_up_ip_key,
)
from app.config import Settings
from app.guest_tokens import hash_guest_token
from app.main import create_app
from app.models import AuthRateLimit, GuestSession
from app.turnstile import TurnstileRejected, TurnstileUnavailable

pytestmark = pytest.mark.integration
ORIGIN = "https://askm6.com"
PATH = "/api/v1/guest/session"
PEER = "192.0.2.12"
BODY = {"turnstile_token": "synthetic-proof"}
KEY_FUNCTIONS = {
    "password_recovery": get_password_recovery_ip_key,
    "sign_in": get_sign_in_ip_key,
    "sign_up": get_sign_up_ip_key,
    "email_confirmation": get_email_confirmation_ip_key,
    "password_reset": get_password_reset_ip_key,
    "guest_creation": get_guest_creation_ip_key,
}


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class GuestAPI:
    client: TestClient
    application: FastAPI
    settings: Settings
    database: Engine
    engine: AsyncEngine
    verify: AsyncMock
    keys: dict[tuple[str, str], bytes] = field(repr=False)
    tokens: list[str] = field(default_factory=list, repr=False)

    def key(self, peer: str = PEER, purpose: str = "guest_creation") -> bytes:
        return self.keys[(peer, purpose)]


@pytest.fixture
def api(integration_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[GuestAPI]:
    settings = IsolatedSettings(
        database_url=None,
        migration_database_url=None,
        supabase_auth_issuer=None,
        supabase_auth_publishable_key=None,
        account_session_encryption_key=None,
        guest_session_api_enabled=True,
        guest_creation_ip_max_requests=2,
        guest_creation_ip_window_seconds=600,
        auth_rate_limit_hmac_secret=SecretStr(token_hex(32)),
        csrf_trusted_origins=(ORIGIN,),
        guest_cookie_secure=True,
        turnstile_secret_key=SecretStr("synthetic-test-secret"),
        turnstile_allowed_hostnames=("askm6.com",),
    )
    peers = (PEER, "::ffff:192.0.2.12", "192.0.2.13", "invalid-peer")
    keys = {
        (peer, purpose): function(Request({"type": "http", "client": (peer, 12345)}), settings)
        for peer in peers
        if peer != "invalid-peer"
        for purpose, function in KEY_FUNCTIONS.items()
    }
    engine = create_async_engine(
        integration_engine.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={
            "connect_timeout": 5,
            "hostaddr": "127.0.0.1",
            "options": "-c role=askm6_app -c timezone=UTC -c statement_timeout=5000",
        },
    )

    @event.listens_for(engine.sync_engine, "begin")
    def restricted(connection: Connection) -> None:
        assert tuple(connection.execute(text("SELECT current_database(), current_user")).one()) == (
            "askm6_test",
            "askm6_app",
        )
        assert (
            connection.scalar(
                text(
                    "SELECT NOT rolsuper AND NOT rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            )
            is True
        )

    monkeypatch.setattr("app.main.create_database_engine", Mock(return_value=engine))
    verify = AsyncMock()
    monkeypatch.setattr("app.guest_session_service.verify_turnstile_token", verify)
    application = create_app(settings)
    tokens: list[str] = []

    def token() -> str:
        raw = token_urlsafe(32)
        tokens.append(raw)
        return raw

    monkeypatch.setattr("app.guest_sessions.generate_guest_token", token)
    try:
        with TestClient(
            application,
            base_url=ORIGIN,
            client=(PEER, 12345),
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            application.state.turnstile_client = Mock(spec=httpx2.AsyncClient)
            material = GuestAPI(
                client, application, settings, integration_engine, engine, verify, keys, tokens
            )
            with integration_engine.connect() as observer:
                assert tuple(observer.execute(text("SELECT current_database()")).one()) == (
                    "askm6_test",
                )

            async def verified(*args: object, **kwargs: object) -> None:
                # Verification must observe committed accounting from another connection.
                assert any(len(times) > 0 for times, _ in state(material).values())

            verify.side_effect = verified
            yield material
    finally:
        with integration_engine.begin() as connection:
            if tokens:
                connection.execute(
                    delete(GuestSession).where(
                        GuestSession.token_hash.in_([hash_guest_token(raw) for raw in tokens])
                    )
                )
            connection.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.purpose.in_(KEY_FUNCTIONS),
                    AuthRateLimit.key_hash.in_(set(keys.values())),
                )
            )


def fresh(
    api: GuestAPI, *, peer: str = PEER, proof: bool = True, headers: dict[str, str] | None = None
) -> httpx2.Response:
    client = TestClient(
        api.application,
        base_url=ORIGIN,
        client=(peer, 12345),
        backend_options={"loop_factory": asyncio.SelectorEventLoop},
    )
    # Share the fixture's application loop, while keeping an independent cookie
    # jar. An AsyncEngine must not be initialized on several concurrent loops.
    client.portal = api.client.portal
    try:
        return client.post(
            PATH, headers={"Origin": ORIGIN, **(headers or {})}, json=BODY if proof else None
        )
    finally:
        client.close()


def state(api: GuestAPI) -> dict[tuple[str, bytes], tuple[list[datetime], datetime]]:
    with api.database.connect() as connection:
        return {
            (row.purpose, row.key_hash): (row.request_times, row.expires_at)
            for row in connection.execute(
                select(AuthRateLimit).where(AuthRateLimit.key_hash.in_(set(api.keys.values())))
            )
        }


def assert_denied(response: httpx2.Response) -> None:
    assert response.status_code == 429
    assert response.json() == {"detail": "Guest session creation is temporarily rate limited."}
    assert 1 <= int(response.headers["Retry-After"]) <= 600
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "X-Guest-Verification" not in response.headers


def test_creation_is_committed_and_active_cookie_works_at_cap(api: GuestAPI) -> None:
    first = api.client.post(PATH, headers={"Origin": ORIGIN}, json=BODY)
    assert first.status_code == 200
    assert set(first.json()) == {"status", "expires_at"}
    assert fresh(api).status_code == 200
    before = state(api)
    assert_denied(fresh(api))
    assert state(api) == before
    response = api.client.post(PATH, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert response.cookies.get("__Host-askm6_guest") == first.cookies.get("__Host-askm6_guest")
    assert state(api) == before
    assert api.verify.await_count == 2


def test_missing_proof_and_rejected_proof_are_counted_without_new_session(api: GuestAPI) -> None:
    assert fresh(api, proof=False).status_code == 403
    api.verify.side_effect = TurnstileRejected("private-details")
    assert fresh(api).status_code == 403
    assert_denied(fresh(api))
    assert len(state(api)[("guest_creation", api.key())][0]) == 2
    assert not api.tokens
    api.verify.assert_awaited_once()


@pytest.mark.parametrize("failure", [TurnstileUnavailable("private"), TimeoutError("private")])
def test_verification_failure_retains_the_committed_attempt(
    api: GuestAPI, failure: Exception
) -> None:
    api.verify.side_effect = failure
    response = fresh(api)
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    assert len(state(api)[("guest_creation", api.key())][0]) == 1
    assert not api.tokens


def test_concurrent_creation_never_exceeds_the_cap(api: GuestAPI) -> None:
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: fresh(api), range(6)))
    assert sorted(response.status_code for response in responses) == [200, 200, 429, 429, 429, 429]
    assert api.verify.await_count == 2
    assert len(api.tokens) == 2
    assert len(state(api)[("guest_creation", api.key())][0]) == 2
    for response in responses:
        if response.status_code == 429:
            assert_denied(response)


def test_mapped_address_headers_and_cookie_clearing_cannot_reset_budget(api: GuestAPI) -> None:
    assert fresh(api).status_code == 200
    assert fresh(api, peer="::ffff:192.0.2.12").status_code == 200
    assert_denied(
        fresh(api, headers={"X-Forwarded-For": "203.0.113.12", "CF-Connecting-IP": "198.51.100.10"})
    )
    assert fresh(api, peer="192.0.2.13").status_code == 200
    assert len(state(api)[("guest_creation", api.key())][0]) == 2


def test_expired_attempts_allow_creation_and_retry_matches_window(api: GuestAPI) -> None:
    now = datetime.now(UTC)
    times = [now - timedelta(seconds=590), now - timedelta(seconds=580)]
    with api.database.begin() as connection:
        connection.execute(
            insert(AuthRateLimit).values(
                purpose="guest_creation",
                key_hash=api.key(),
                request_times=times,
                expires_at=times[-1] + timedelta(seconds=600),
            )
        )
    response = fresh(api)
    assert_denied(response)
    assert 1 <= int(response.headers["Retry-After"]) <= 10
    with api.database.begin() as connection:
        connection.execute(
            update(AuthRateLimit)
            .where(AuthRateLimit.purpose == "guest_creation", AuthRateLimit.key_hash == api.key())
            .values(
                request_times=[now - timedelta(seconds=601)], expires_at=now - timedelta(seconds=1)
            )
        )
    assert fresh(api).status_code == 200
    assert len(state(api)[("guest_creation", api.key())][0]) == 1


@pytest.mark.parametrize(
    "guard",
    ["origin", "disabled", "database", "client", "secret", "hostnames", "hmac", "peer", "body"],
)
def test_guards_prevent_accounting_and_verification(api: GuestAPI, guard: str) -> None:
    if guard == "disabled":
        api.settings.guest_session_api_enabled = False
    elif guard == "database":
        api.application.state.database_engine = None
    elif guard == "client":
        api.application.state.turnstile_client = None
    elif guard == "secret":
        api.settings.turnstile_secret_key = None
    elif guard == "hostnames":
        api.settings.turnstile_allowed_hostnames = ()
    elif guard == "hmac":
        api.settings.auth_rate_limit_hmac_secret = None
    if guard == "body":
        response = api.client.post(
            PATH, headers={"Origin": ORIGIN, "Content-Type": "application/json"}, content=b"invalid"
        )
    else:
        response = fresh(
            api,
            peer="invalid-peer" if guard == "peer" else PEER,
            headers={"Origin": "https://evil.test"} if guard == "origin" else None,
        )
    assert response.status_code == (403 if guard == "origin" else 400 if guard == "body" else 503)
    assert not state(api)
    assert "set-cookie" not in response.headers
    api.verify.assert_not_awaited()
    assert not api.tokens


@pytest.mark.parametrize("phase", ["accounting", "creation"])
def test_failed_commit_does_not_issue_cookie_or_retry(api: GuestAPI, phase: str) -> None:
    commits = 0

    def fail(connection: Connection) -> None:
        nonlocal commits
        commits += 1
        if commits == (1 if phase == "accounting" else 2):
            connection.exec_driver_sql("SELECT 1 / 0")

    event.listen(api.engine.sync_engine, "commit", fail)
    try:
        response = fresh(api)
    finally:
        event.remove(api.engine.sync_engine, "commit", fail)
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    assert commits == (1 if phase == "accounting" else 2)
    if phase == "accounting":
        assert not state(api)
        api.verify.assert_not_awaited()
    else:
        assert len(state(api)[("guest_creation", api.key())][0]) == 1
        api.verify.assert_awaited_once()
    with api.database.connect() as connection:
        assert (
            connection.scalar(
                select(GuestSession.id).where(
                    GuestSession.token_hash.in_([hash_guest_token(raw) for raw in api.tokens])
                )
            )
            is None
        )


def test_lock_wait_deadline_does_not_verify_or_create(api: GuestAPI) -> None:
    now = datetime.now(UTC)
    with api.database.begin() as connection:
        connection.execute(
            insert(AuthRateLimit).values(
                purpose="guest_creation",
                key_hash=api.key(),
                request_times=[now],
                expires_at=now + timedelta(seconds=600),
            )
        )
    before = state(api)
    api.settings.guest_session_timeout_seconds = 1
    with api.database.begin() as holder:
        holder.execute(
            select(AuthRateLimit)
            .where(
                AuthRateLimit.purpose == "guest_creation",
                AuthRateLimit.key_hash == api.key(),
            )
            .with_for_update()
        ).one()
        response = fresh(api)
        assert response.status_code == 503
        assert "set-cookie" not in response.headers
        assert state(api) == before
        api.verify.assert_not_awaited()
        assert not api.tokens
    api.settings.guest_session_timeout_seconds = 15
    assert fresh(api).status_code == 200


def test_account_budgets_are_unchanged(api: GuestAPI) -> None:
    now = datetime.now(UTC)
    with api.database.begin() as connection:
        for purpose in KEY_FUNCTIONS:
            if purpose != "guest_creation":
                connection.execute(
                    insert(AuthRateLimit).values(
                        purpose=purpose,
                        key_hash=api.key(purpose=purpose),
                        request_times=[now],
                        expires_at=now + timedelta(seconds=600),
                    )
                )
    before = state(api)
    assert fresh(api).status_code == 200
    after = state(api)
    assert {
        identity: value for identity, value in after.items() if identity[0] != "guest_creation"
    } == before
