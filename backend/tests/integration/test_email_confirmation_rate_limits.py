"""Email-confirmation accounting with guarded PostgreSQL and mocked provider HTTP."""

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_hex

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app import auth_rate_limits as limiter
from app.account_email_confirmation_routes import router
from app.auth_rate_limit_keys import (
    get_email_confirmation_ip_key,
    get_password_recovery_ip_key,
    get_sign_in_ip_key,
    get_sign_up_ip_key,
)
from app.config import Settings
from app.models import AuthRateLimit

pytestmark = pytest.mark.integration
PATH = "/api/v1/account/confirm-email"
ORIGIN = "https://app.example.test"
PEER = "192.0.2.12"
OTHER_PEER = "198.51.100.20"
EMAIL = "owner@example.test"
CODE = "001234"
USER_ID = "563128d6-22fd-464f-a3bd-31018fdf1b3c"
UNAVAILABLE = "Email confirmation is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class JSONStream(httpx2.AsyncByteStream):
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@dataclass
class ConfirmationCase:
    application: FastAPI
    engine: AsyncEngine
    inspector: Engine
    settings: Settings
    keys: dict[tuple[str, str], bytes] = field(repr=False)
    client: TestClient | None = None
    provider_status: int = 200
    provider_payload: object = field(
        default_factory=lambda: {
            "user": {"id": USER_ID, "email_confirmed_at": "2026-10-22T10:00:00Z"},
            "access_token": "synthetic-access-token",
            "refresh_token": "synthetic-refresh-token",
        }
    )
    requests: list[httpx2.Request] = field(default_factory=list, repr=False)


@pytest.fixture
def confirmation_case(integration_engine: Engine) -> Iterator[ConfirmationCase]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": None,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "account_email_confirmation_api_enabled": True,
            "account_email_confirmation_ip_max_requests": 2,
            "account_email_confirmation_timeout_seconds": 5,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    keys = {
        (purpose, peer): function(
            Request({"type": "http", "headers": [], "client": (peer, 12345)}), settings
        )
        for purpose, function in (
            ("email_confirmation", get_email_confirmation_ip_key),
            ("sign_in", get_sign_in_ip_key),
            ("sign_up", get_sign_up_ip_key),
            ("password_recovery", get_password_recovery_ip_key),
        )
        for peer in (PEER, OTHER_PEER)
    }
    engine = create_async_engine(
        integration_engine.url,
        pool_size=4,
        max_overflow=0,
        pool_timeout=2,
        hide_parameters=True,
        connect_args={
            "connect_timeout": 5,
            "hostaddr": "127.0.0.1",
            "options": "-c role=askm6_app -c timezone=UTC -c statement_timeout=5000",
        },
    )
    case: ConfirmationCase

    async def provider(request: httpx2.Request) -> httpx2.Response:
        assert (
            request.method == "POST"
            and str(request.url) == "https://auth.example.test/auth/v1/verify"
        )
        assert "cookie" not in request.headers and "authorization" not in request.headers
        assert request.headers["apikey"] == "sb_publishable_synthetic_test_key"
        payload = json.loads(request.content)
        assert payload["email"] in (EMAIL, "another@example.test")
        assert payload == {"email": payload["email"], "token": CODE, "type": "signup"}
        async with engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(AuthRateLimit.request_times).where(
                        AuthRateLimit.purpose == "email_confirmation",
                        AuthRateLimit.key_hash.in_(keys.values()),
                    )
                )
            ).all()
            # Accounting must already be committed and visible on another connection.
            assert sum(len(row.request_times) for row in rows) >= 1
        case.requests.append(request)
        return httpx2.Response(
            case.provider_status,
            headers={"Content-Type": "application/json"},
            stream=JSONStream(case.provider_payload),
        )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        try:
            async with engine.connect() as connection:
                assert tuple(
                    (
                        await connection.execute(text("SELECT current_database(), current_user"))
                    ).one()
                ) == ("askm6_test", "askm6_app")
                assert (
                    await connection.scalar(
                        text(
                            "SELECT NOT rolsuper AND NOT rolbypassrls "
                            "FROM pg_roles WHERE rolname=current_user"
                        )
                    )
                    is True
                )
            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(provider), trust_env=False
            ) as client:
                application.state.settings = settings
                application.state.database_engine = engine
                application.state.account_auth_client = client
                application.state.account_key_cache = None
                yield
        finally:
            await engine.dispose()

    application = FastAPI(lifespan=lifespan)
    application.include_router(router)
    case = ConfirmationCase(application, engine, integration_engine, settings, keys)
    try:
        with TestClient(
            application,
            client=(PEER, 12345),
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            case.client = client
            yield case
    finally:
        with integration_engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE askm6_app"))
            connection.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.purpose.in_(
                        ["password_recovery", "sign_in", "sign_up", "email_confirmation"]
                    ),
                    AuthRateLimit.key_hash.in_(keys.values()),
                )
            )


def post(case: ConfirmationCase, **headers: str) -> httpx2.Response:
    assert case.client is not None
    return case.client.post(
        PATH,
        json={"email": EMAIL, "code": CODE},
        headers={"Origin": ORIGIN, **headers},
    )


def state(
    case: ConfirmationCase, purpose: str = "email_confirmation"
) -> tuple[list[datetime], datetime] | None:
    with case.inspector.connect() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        row = connection.execute(
            select(AuthRateLimit).where(
                AuthRateLimit.purpose == purpose, AuthRateLimit.key_hash == case.keys[purpose, PEER]
            )
        ).one_or_none()
        return None if row is None else (list(row.request_times), row.expires_at)


def seed(
    case: ConfirmationCase, times: list[datetime], purpose: str = "email_confirmation"
) -> None:
    with case.inspector.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(
            insert(AuthRateLimit).values(
                purpose=purpose,
                key_hash=case.keys[purpose, PEER],
                request_times=times,
                expires_at=max(times) + timedelta(seconds=600),
            )
        )


def assert_private(response: httpx2.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert all(
        value not in response.text
        for value in (EMAIL, CODE, USER_ID, "synthetic-access-token", "synthetic-refresh-token")
    )


def test_confirmation_acknowledges_without_logging_in(confirmation_case: ConfirmationCase) -> None:
    response = post(confirmation_case)
    assert response.status_code == 200
    assert response.json() == {
        "status": "confirmed",
        "message": "Email confirmed. You can now sign in.",
    }
    assert_private(response)
    stored = state(confirmation_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(confirmation_case.requests) == 1


def test_local_cap_prevents_body_parsing_and_cannot_be_bypassed_by_email_or_header(
    confirmation_case: ConfirmationCase,
) -> None:
    assert post(confirmation_case).status_code == 200
    assert confirmation_case.client is not None
    assert (
        confirmation_case.client.post(
            PATH,
            json={"email": "another@example.test", "code": CODE},
            headers={"Origin": ORIGIN},
        ).status_code
        == 200
    )
    before = state(confirmation_case)
    response = confirmation_case.client.post(
        PATH,
        content=b"not-json",
        headers={
            "Origin": ORIGIN,
            "Content-Type": "application/json",
            "X-Forwarded-For": OTHER_PEER,
        },
    )
    assert response.status_code == 429
    assert 1 <= int(response.headers["Retry-After"]) <= 600
    assert "X-Account-Verification" not in response.headers
    assert_private(response)
    assert state(confirmation_case) == before and len(confirmation_case.requests) == 2


@pytest.mark.parametrize("body", [b"{}", b"not-json"])
def test_invalid_body_remains_counted(confirmation_case: ConfirmationCase, body: bytes) -> None:
    assert confirmation_case.client is not None
    response = confirmation_case.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert_private(response)
    stored = state(confirmation_case)
    assert stored is not None and len(stored[0]) == 1
    assert not confirmation_case.requests


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (403, {"code": "otp_expired"}, 400),
        (500, {}, 503),
        (429, {"code": "over_request_rate_limit"}, 503),
    ],
)
def test_provider_failures_do_not_refund_attempts(
    confirmation_case: ConfirmationCase, status: int, payload: object, expected: int
) -> None:
    confirmation_case.provider_status, confirmation_case.provider_payload = status, payload
    response = post(confirmation_case)
    assert response.status_code == expected
    assert "Retry-After" not in response.headers
    assert_private(response)
    stored = state(confirmation_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(confirmation_case.requests) == 1


@pytest.mark.parametrize(
    "guard", ["origin", "disabled", "engine", "client", "hmac", "issuer", "publishable-key"]
)
def test_guards_do_not_count_or_contact_provider(
    confirmation_case: ConfirmationCase, guard: str
) -> None:
    if guard == "disabled":
        confirmation_case.settings.account_email_confirmation_api_enabled = False
    elif guard in ("engine", "client"):
        setattr(
            confirmation_case.application.state,
            "database_engine" if guard == "engine" else "account_auth_client",
            None,
        )
    elif guard != "origin":
        name = {
            "hmac": "auth_rate_limit_hmac_secret",
            "issuer": "supabase_auth_issuer",
            "publishable-key": "supabase_auth_publishable_key",
        }[guard]
        setattr(confirmation_case.settings, name, None)
    response = post(
        confirmation_case, Origin="https://untrusted.example.test" if guard == "origin" else ORIGIN
    )
    assert response.status_code == (403 if guard == "origin" else 503)
    assert_private(response)
    assert state(confirmation_case) is None and not confirmation_case.requests


@pytest.mark.parametrize("existing", [False, True])
def test_failed_accounting_commit_rolls_back_without_provider(
    confirmation_case: ConfirmationCase, existing: bool
) -> None:
    if existing:
        seed(confirmation_case, [datetime.now(UTC) - timedelta(seconds=30)])
    before = state(confirmation_case)

    def fail_commit(connection: Connection) -> None:
        connection.exec_driver_sql("SELECT 1 / 0")

    event.listen(confirmation_case.engine.sync_engine, "commit", fail_commit)
    try:
        response = post(confirmation_case)
    finally:
        event.remove(confirmation_case.engine.sync_engine, "commit", fail_commit)
    assert response.status_code == 503 and response.json() == {"detail": UNAVAILABLE}
    assert_private(response)
    assert state(confirmation_case) == before and not confirmation_case.requests


def test_real_lock_wait_is_bounded_and_recovers(confirmation_case: ConfirmationCase) -> None:
    seed(confirmation_case, [datetime.now(UTC)])
    before = state(confirmation_case)
    confirmation_case.settings.account_email_confirmation_timeout_seconds = 1
    with confirmation_case.inspector.connect() as locker:
        transaction = locker.begin()
        try:
            locker.execute(text("SET LOCAL ROLE askm6_app"))
            locker.execute(
                select(AuthRateLimit)
                .where(
                    AuthRateLimit.purpose == "email_confirmation",
                    AuthRateLimit.key_hash == confirmation_case.keys["email_confirmation", PEER],
                )
                .with_for_update()
            )
            response = post(confirmation_case)
        finally:
            transaction.rollback()
    assert response.status_code == 503
    assert_private(response)
    assert state(confirmation_case) == before and not confirmation_case.requests
    confirmation_case.settings.account_email_confirmation_timeout_seconds = 5
    assert post(confirmation_case).status_code == 200


def test_concurrent_confirmations_cannot_exceed_cap(confirmation_case: ConfirmationCase) -> None:
    assert confirmation_case.client is not None and confirmation_case.client.portal is not None

    async def burst() -> list[httpx2.Response]:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=confirmation_case.application, client=(PEER, 12345)),
            base_url="http://testserver",
        ) as browser:
            async with asyncio.timeout(10):
                return list(
                    await asyncio.gather(
                        *(
                            browser.post(
                                PATH,
                                json={
                                    "email": EMAIL,
                                    "code": CODE,
                                },
                                headers={"Origin": ORIGIN},
                            )
                            for _ in range(8)
                        )
                    )
                )

    responses = confirmation_case.client.portal.call(burst)
    assert sorted(response.status_code for response in responses) == [200, 200] + [429] * 6
    assert all(
        "Retry-After" in response.headers for response in responses if response.status_code == 429
    )
    stored = state(confirmation_case)
    assert stored is not None and len(stored[0]) == 2
    assert len(confirmation_case.requests) == 2


def test_exact_retry_and_expiry(
    confirmation_case: ConfirmationCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    current = now

    async def clock(_connection: AsyncConnection) -> datetime:
        return current

    monkeypatch.setattr(limiter, "_database_now", clock)
    seed(confirmation_case, [now - timedelta(seconds=590.2), now - timedelta(seconds=5)])
    before = state(confirmation_case)
    response = post(confirmation_case)
    assert response.status_code == 429 and response.headers["Retry-After"] == "10"
    assert state(confirmation_case) == before and not confirmation_case.requests
    current = now + timedelta(seconds=10)
    assert post(confirmation_case).status_code == 200
    assert state(confirmation_case) == (
        [now - timedelta(seconds=5), current],
        current + timedelta(seconds=600),
    )


def test_other_auth_budgets_do_not_block_or_change(confirmation_case: ConfirmationCase) -> None:
    now = datetime.now(UTC)
    for purpose in ("password_recovery", "sign_in", "sign_up"):
        seed(confirmation_case, [now] * 30, purpose)
    before = {
        purpose: state(confirmation_case, purpose)
        for purpose in ("password_recovery", "sign_in", "sign_up")
    }
    assert post(confirmation_case).status_code == 200
    assert post(confirmation_case).status_code == 200
    assert post(confirmation_case).status_code == 429
    assert {purpose: state(confirmation_case, purpose) for purpose in before} == before


def test_mapped_peer_cannot_split_budget_and_distinct_peer_is_independent(
    confirmation_case: ConfirmationCase,
) -> None:
    confirmation_case.settings.account_email_confirmation_ip_max_requests = 1
    assert post(confirmation_case).status_code == 200
    assert confirmation_case.client is not None and confirmation_case.client.portal is not None

    async def from_peer(peer: str) -> httpx2.Response:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=confirmation_case.application, client=(peer, 12345)),
            base_url="http://testserver",
        ) as browser:
            return await browser.post(
                PATH,
                json={"email": EMAIL, "code": CODE},
                headers={"Origin": ORIGIN},
            )

    assert confirmation_case.client.portal.call(from_peer, f"::ffff:{PEER}").status_code == 429
    assert confirmation_case.client.portal.call(from_peer, OTHER_PEER).status_code == 200
    assert len(confirmation_case.requests) == 2
