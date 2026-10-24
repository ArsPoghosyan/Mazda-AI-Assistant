"""Google start accounting and attempt commits on guarded local PostgreSQL."""

import asyncio
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from unittest.mock import Mock

import httpx2
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, insert, select, text, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_google_routes import router
from app.account_key_cache import AccountKeyCache
from app.account_oauth_material import OAuthLoginMaterial, create_oauth_login_material
from app.account_token_encryption import AccountTokenCipher
from app.auth_rate_limit_keys import (
    get_email_confirmation_ip_key,
    get_google_start_ip_key,
    get_guest_creation_ip_key,
    get_password_recovery_ip_key,
    get_password_reset_ip_key,
    get_sign_in_ip_key,
    get_sign_up_ip_key,
)
from app.config import Settings
from app.models import AuthRateLimit, OAuthLoginAttempt

pytestmark = pytest.mark.integration
PATH = "/api/v1/account/google/start"
ORIGIN = "https://app.example.test"
PEER = "192.0.2.12"
KEY_FUNCTIONS = {
    "password_recovery": get_password_recovery_ip_key,
    "sign_in": get_sign_in_ip_key,
    "sign_up": get_sign_up_ip_key,
    "email_confirmation": get_email_confirmation_ip_key,
    "password_reset": get_password_reset_ip_key,
    "guest_creation": get_guest_creation_ip_key,
    "google_start": get_google_start_ip_key,
}


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class GoogleAPI:
    client: TestClient
    application: FastAPI
    settings: Settings
    database: Engine
    engine: AsyncEngine
    keys: dict[tuple[str, str], bytes] = field(repr=False)
    hashes: list[bytes] = field(default_factory=list, repr=False)

    def key(self, peer: str = PEER, purpose: str = "google_start") -> bytes:
        return self.keys[(peer, purpose)]


@pytest.fixture
def api(integration_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[GoogleAPI]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "account_google_oauth_api_enabled": True,
            "account_google_oauth_callback_url": "https://api.example.test/api/v1/account/google/callback",
            "account_google_oauth_ip_max_requests": 2,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    keys = {
        (peer, purpose): function(Request({"type": "http", "client": (peer, 12345)}), settings)
        for peer in (PEER, "::ffff:192.0.2.12", "192.0.2.13")
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
                    "FROM pg_roles WHERE rolname=current_user"
                )
            )
            is True
        )

    application = FastAPI()
    application.include_router(router)
    application.state.settings = settings
    application.state.database_engine = engine
    provider = Mock(spec=httpx2.AsyncClient)
    application.state.account_auth_client = provider
    application.state.account_key_cache = Mock(spec=AccountKeyCache)
    with TestClient(
        application,
        base_url=ORIGIN,
        client=(PEER, 12345),
        backend_options={"loop_factory": asyncio.SelectorEventLoop},
    ) as client:
        material = GoogleAPI(client, application, settings, integration_engine, engine, keys)

        def generate(cipher: AccountTokenCipher) -> OAuthLoginMaterial:
            # The real attempt generator runs only after accounting committed
            # and became visible on this independent observer connection.
            assert any(
                identity[0] == "google_start" and len(times) > 0
                for identity, (times, _) in state(material).items()
            )
            created = create_oauth_login_material(cipher)
            material.hashes.append(created.browser_token_hash)
            return created

        monkeypatch.setattr("app.account_oauth_attempts.create_oauth_login_material", generate)
        try:
            yield material
            provider.post.assert_not_called()
        finally:
            assert client.portal is not None
            client.portal.call(engine.dispose)
            with integration_engine.begin() as connection:
                if material.hashes:
                    connection.execute(
                        delete(OAuthLoginAttempt).where(
                            OAuthLoginAttempt.browser_token_hash.in_(material.hashes)
                        )
                    )
                connection.execute(
                    delete(AuthRateLimit).where(
                        AuthRateLimit.purpose.in_(KEY_FUNCTIONS),
                        AuthRateLimit.key_hash.in_(set(keys.values())),
                    )
                )


def start(
    api: GoogleAPI, *, peer: str = PEER, headers: dict[str, str] | None = None
) -> httpx2.Response:
    client = TestClient(api.application, base_url=ORIGIN, client=(peer, 12345))
    client.portal = api.client.portal
    try:
        return client.post(PATH, headers={"Origin": ORIGIN, **(headers or {})})
    finally:
        client.close()


def state(api: GoogleAPI) -> dict[tuple[str, bytes], tuple[list[datetime], datetime]]:
    with api.database.connect() as connection:
        return {
            (row.purpose, row.key_hash): (row.request_times, row.expires_at)
            for row in connection.execute(
                select(AuthRateLimit).where(AuthRateLimit.key_hash.in_(set(api.keys.values())))
            )
        }


def pending(api: GoogleAPI) -> list[object]:
    with api.database.connect() as connection:
        return list(
            connection.execute(
                select(OAuthLoginAttempt).where(
                    OAuthLoginAttempt.browser_token_hash.in_(api.hashes)
                )
            ).all()
        )


def denied(response: httpx2.Response) -> None:
    assert response.status_code == 429
    assert response.json() == {"detail": "Google sign-in is temporarily rate limited."}
    assert 1 <= int(response.headers["Retry-After"]) <= 600
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "set-cookie" not in response.headers and "location" not in response.headers


def test_replacement_counts_and_denial_preserves_pending_attempt_and_cookie(api: GoogleAPI) -> None:
    first = api.client.post(PATH, headers={"Origin": ORIGIN})
    assert first.status_code == 200 and len(pending(api)) == 1
    assert set(first.json()) == {"authorization_url", "expires_at"}
    old = pending(api)
    second = api.client.post(PATH, headers={"Origin": ORIGIN})
    assert second.status_code == 200 and len(pending(api)) == 1
    assert pending(api) != old
    before, binding, limits = pending(api), dict(api.client.cookies), state(api)
    denied(api.client.post(PATH, headers={"Origin": ORIGIN}))
    assert pending(api) == before and dict(api.client.cookies) == binding
    assert state(api) == limits


def test_concurrent_starts_create_exactly_the_configured_cap(api: GoogleAPI) -> None:
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: start(api), range(6)))
    assert sum(response.status_code == 200 for response in responses) == 2
    for response in responses:
        if response.status_code != 200:
            denied(response)
    assert len(api.hashes) == len(pending(api)) == 2
    assert len(state(api)[("google_start", api.key())][0]) == 2


def test_peer_identity_ignores_cookie_clearing_and_forwarded_ip(api: GoogleAPI) -> None:
    assert start(api).status_code == 200
    assert start(api, peer="::ffff:192.0.2.12").status_code == 200
    denied(
        start(api, headers={"X-Forwarded-For": "198.51.100.9", "CF-Connecting-IP": "198.51.100.9"})
    )
    assert start(api, peer="192.0.2.13").status_code == 200
    assert len(state(api)[("google_start", api.key())][0]) == 2
    assert len(state(api)[("google_start", api.key("192.0.2.13"))][0]) == 1


def test_expired_window_allows_new_start_and_denial_does_not_extend_it(api: GoogleAPI) -> None:
    api.settings.account_google_oauth_ip_max_requests = 1
    assert start(api).status_code == 200
    before = state(api)
    denied(start(api))
    assert state(api) == before
    with api.database.begin() as connection:
        now = connection.scalar(select(text("clock_timestamp()")))
        assert isinstance(now, datetime)
        connection.execute(
            update(AuthRateLimit)
            .where(
                AuthRateLimit.purpose == "google_start",
                AuthRateLimit.key_hash == api.key(),
            )
            .values(
                request_times=[now - timedelta(seconds=601)], expires_at=now - timedelta(seconds=1)
            )
        )
    assert start(api).status_code == 200
    assert len(state(api)[("google_start", api.key())][0]) == 1


@pytest.mark.parametrize(
    "guard",
    [
        "origin",
        "disabled",
        "database_engine",
        "account_auth_client",
        "account_key_cache",
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "account_google_oauth_callback_url",
        "auth_rate_limit_hmac_secret",
        "invalid_hmac",
        "peer",
        "body",
        "query",
        "account_cookie",
    ],
)
def test_invalid_or_unavailable_requests_do_not_count_or_create(api: GoogleAPI, guard: str) -> None:
    if guard == "disabled":
        api.settings.account_google_oauth_api_enabled = False
    elif guard in {"database_engine", "account_auth_client", "account_key_cache"}:
        setattr(api.application.state, guard, None)
    elif guard in {
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "account_google_oauth_callback_url",
        "auth_rate_limit_hmac_secret",
    }:
        setattr(api.settings, guard, None)
    elif guard == "invalid_hmac":
        api.settings.auth_rate_limit_hmac_secret = SecretStr("malformed")
    headers = {"Origin": ORIGIN}
    if guard == "origin":
        headers["Origin"] = "https://evil.test"
    if guard == "account_cookie":
        headers["Cookie"] = "__Host-askm6_account=invalid"
    if guard in {"body", "query"}:
        response = api.client.post(
            PATH + ("?provider=github" if guard == "query" else ""),
            content=b"{}" if guard == "body" else b"",
            headers=headers,
        )
    else:
        response = start(api, peer="invalid-peer" if guard == "peer" else PEER, headers=headers)
    assert response.status_code == (
        403
        if guard == "origin"
        else 409
        if guard == "account_cookie"
        else 400
        if guard in {"body", "query"}
        else 503
    )
    assert "set-cookie" not in response.headers
    assert not state(api) and not pending(api) and not api.hashes


def test_invalid_pending_cookie_counts_but_cannot_clear_binding_when_capped(api: GoogleAPI) -> None:
    api.settings.account_google_oauth_ip_max_requests = 1
    bad = {"Cookie": "__Host-askm6_oauth=invalid"}
    response = start(api, headers=bad)
    assert response.status_code == 400 and "Max-Age=0" in response.headers["set-cookie"]
    assert len(state(api)[("google_start", api.key())][0]) == 1
    denied(start(api, headers=bad))
    assert not api.hashes


@pytest.mark.parametrize("phase", ["accounting", "creation", "replacement"])
def test_failed_commit_never_issues_new_cookie_or_retries(api: GoogleAPI, phase: str) -> None:
    if phase == "replacement":
        assert api.client.post(PATH, headers={"Origin": ORIGIN}).status_code == 200
    before = pending(api)
    commits = 0

    def fail(connection: Connection) -> None:
        nonlocal commits
        commits += 1
        if commits == (1 if phase == "accounting" else 2):
            connection.exec_driver_sql("SELECT 1 / 0")

    event.listen(api.engine.sync_engine, "commit", fail)
    try:
        response = api.client.post(PATH, headers={"Origin": ORIGIN})
    finally:
        event.remove(api.engine.sync_engine, "commit", fail)
    assert response.status_code == 503 and "set-cookie" not in response.headers
    assert commits == (1 if phase == "accounting" else 2)
    assert pending(api) == before
    if phase == "accounting":
        assert not state(api) and not api.hashes
    else:
        assert len(state(api)[("google_start", api.key())][0]) == (
            2 if phase == "replacement" else 1
        )


def test_lock_wait_respects_overall_deadline_before_material_generation(api: GoogleAPI) -> None:
    now = datetime.now(UTC)
    with api.database.begin() as connection:
        connection.execute(
            insert(AuthRateLimit).values(
                purpose="google_start",
                key_hash=api.key(),
                request_times=[now],
                expires_at=now + timedelta(seconds=600),
            )
        )
    before = state(api)
    api.settings.account_google_oauth_timeout_seconds = 1
    with api.database.begin() as holder:
        holder.execute(
            select(AuthRateLimit)
            .where(
                AuthRateLimit.purpose == "google_start",
                AuthRateLimit.key_hash == api.key(),
            )
            .with_for_update()
        ).one()
        response = start(api)
        assert response.status_code == 503 and "set-cookie" not in response.headers
        assert state(api) == before and not api.hashes
    api.settings.account_google_oauth_timeout_seconds = 15
    assert start(api).status_code == 200


def test_other_authentication_budgets_are_unchanged(api: GoogleAPI) -> None:
    now = datetime.now(UTC)
    with api.database.begin() as connection:
        for purpose in KEY_FUNCTIONS:
            if purpose != "google_start":
                connection.execute(
                    insert(AuthRateLimit).values(
                        purpose=purpose,
                        key_hash=api.key(purpose=purpose),
                        request_times=[now],
                        expires_at=now + timedelta(seconds=600),
                    )
                )
    before = state(api)
    assert start(api).status_code == 200
    assert {key: value for key, value in state(api).items() if key[0] != "google_start"} == before
