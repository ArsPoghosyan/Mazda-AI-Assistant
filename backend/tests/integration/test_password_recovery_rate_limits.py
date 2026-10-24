"""Real recovery HTTP/accounting transactions with mocked provider delivery."""

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
from app.account_password_recovery_routes import router
from app.auth_rate_limit_keys import get_password_recovery_ip_key
from app.config import Settings
from app.models import AuthRateLimit

pytestmark = pytest.mark.integration
PATH = "/api/v1/account/password-recovery"
ORIGIN = "https://app.example.test"
PEER = "192.0.2.12"
OTHER_PEER = "198.51.100.20"
EMAIL = "owner@example.test"
CAPTCHA = "synthetic-proof"
UNAVAILABLE = "Password recovery is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class JSONStream(httpx2.AsyncByteStream):
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@dataclass
class RecoveryCase:
    application: FastAPI
    engine: AsyncEngine
    inspector: Engine
    settings: Settings
    key: bytes = field(repr=False)
    other_key: bytes = field(repr=False)
    client: TestClient | None = None
    provider_status: int = 200
    provider_payload: object = field(default_factory=dict)
    requests: list[httpx2.Request] = field(default_factory=list, repr=False)
    visible_counts: list[int] = field(default_factory=list)


@pytest.fixture
def recovery_case(integration_engine: Engine) -> Iterator[RecoveryCase]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "auth_rate_limit_hmac_secret": token_hex(32),
            "account_password_recovery_api_enabled": True,
            "account_password_recovery_ip_max_requests": 2,
            "account_password_recovery_timeout_seconds": 5,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    keys = []
    for peer in (PEER, OTHER_PEER):
        keys.append(
            get_password_recovery_ip_key(
                Request(
                    {
                        "type": "http",
                        "headers": [],
                        "client": (peer, 12345),
                    }
                ),
                settings,
            )
        )
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
    # The shared fixture validates the exact local target and migration head
    # before this test can construct or use its application engine.
    case: RecoveryCase

    async def provider(request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://auth.example.test/auth/v1/recover"
        assert "cookie" not in request.headers and "authorization" not in request.headers
        # A different database connection must see committed accounting before
        # the real adapter can send the mocked provider request.
        async with engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(AuthRateLimit.request_times).where(
                        AuthRateLimit.purpose == "password_recovery",
                        AuthRateLimit.key_hash.in_(keys),
                    )
                )
            ).all()
            visible = sum(len(row.request_times) for row in rows)
            assert visible >= 1
            case.visible_counts.append(visible)
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
                            "FROM pg_roles WHERE rolname = current_user"
                        )
                    )
                    is True
                )
            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(provider),
                trust_env=False,
            ) as provider_client:
                application.state.settings = settings
                application.state.database_engine = engine
                application.state.account_auth_client = provider_client
                yield
        finally:
            await engine.dispose()

    application = FastAPI(lifespan=lifespan)
    application.include_router(router)
    case = RecoveryCase(application, engine, integration_engine, settings, keys[0], keys[1])
    try:
        with TestClient(
            application,
            client=(PEER, 12345),
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            case.client = client
            yield case
    finally:
        # Tests deliberately commit. Never delete any other test/user's rows.
        with integration_engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE askm6_app"))
            connection.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.purpose == "password_recovery",
                    AuthRateLimit.key_hash.in_(keys),
                )
            )


def post(case: RecoveryCase, email: str = EMAIL, **headers: str) -> httpx2.Response:
    assert case.client is not None
    return case.client.post(
        PATH, json={"email": email, "captcha_token": CAPTCHA}, headers={"Origin": ORIGIN, **headers}
    )


def state(case: RecoveryCase) -> tuple[list[datetime], datetime] | None:
    with case.inspector.connect() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        row = connection.execute(
            select(AuthRateLimit).where(
                AuthRateLimit.purpose == "password_recovery",
                AuthRateLimit.key_hash == case.key,
            )
        ).one_or_none()
        return None if row is None else (list(row.request_times), row.expires_at)


def seed(case: RecoveryCase, times: list[datetime]) -> None:
    with case.inspector.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(
            insert(AuthRateLimit).values(
                purpose="password_recovery",
                key_hash=case.key,
                request_times=times,
                expires_at=max(times) + timedelta(seconds=600),
            )
        )


def assert_private(response: httpx2.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert EMAIL not in response.text and CAPTCHA not in response.text


def test_count_is_committed_before_real_adapter_sends_request(recovery_case: RecoveryCase) -> None:
    response = post(recovery_case)
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert_private(response)
    assert recovery_case.visible_counts == [1]
    stored = state(recovery_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(recovery_case.requests) == 1


def test_real_limit_blocks_new_email_and_spoofed_header_without_mutation(
    recovery_case: RecoveryCase,
) -> None:
    assert post(recovery_case).status_code == 202
    assert post(recovery_case, "another@example.test").status_code == 202
    before = state(recovery_case)
    response = post(recovery_case, "third@example.test", **{"X-Forwarded-For": OTHER_PEER})
    assert response.status_code == 429
    assert 1 <= int(response.headers["Retry-After"]) <= 600
    assert "X-Account-Verification" not in response.headers
    assert_private(response)
    assert state(recovery_case) == before
    assert len(recovery_case.requests) == 2


def test_http_retry_rounding_and_individual_expiry(
    recovery_case: RecoveryCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    current = now

    async def clock(_connection: AsyncConnection) -> datetime:
        return current

    monkeypatch.setattr(limiter, "_database_now", clock)
    seed(recovery_case, [now - timedelta(seconds=590.2), now - timedelta(seconds=5)])
    before = state(recovery_case)
    denied = post(recovery_case)
    assert denied.status_code == 429 and denied.headers["Retry-After"] == "10"
    assert state(recovery_case) == before
    assert not recovery_case.requests
    current = now + timedelta(seconds=10)
    assert post(recovery_case).status_code == 202
    assert state(recovery_case) == (
        [now - timedelta(seconds=5), current],
        current + timedelta(seconds=600),
    )


@pytest.mark.parametrize("body", [b"not-json", b"{}"])
def test_invalid_body_still_consumes_one_committed_attempt(
    recovery_case: RecoveryCase,
    body: bytes,
) -> None:
    assert recovery_case.client is not None
    response = recovery_case.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert_private(response)
    stored = state(recovery_case)
    assert stored is not None and len(stored[0]) == 1
    assert not recovery_case.requests


@pytest.mark.parametrize(
    ("provider_status", "payload", "expected"),
    [
        (400, {"code": "captcha_failed"}, 403),
        (429, {"code": "over_request_rate_limit"}, 429),
        (500, {}, 503),
        (404, {"code": "user_not_found"}, 202),
    ],
)
def test_provider_outcomes_preserve_accounting(
    recovery_case: RecoveryCase,
    provider_status: int,
    payload: object,
    expected: int,
) -> None:
    recovery_case.provider_status = provider_status
    recovery_case.provider_payload = payload
    response = post(recovery_case)
    assert response.status_code == expected
    assert_private(response)
    assert "Retry-After" not in response.headers
    stored = state(recovery_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(recovery_case.requests) == 1


def test_invalid_origin_never_counts(recovery_case: RecoveryCase) -> None:
    response = post(recovery_case, Origin="https://untrusted.example.test")
    assert response.status_code == 403
    assert_private(response)
    assert state(recovery_case) is None
    assert not recovery_case.requests


@pytest.mark.parametrize("existing", [False, True])
def test_real_sql_error_at_commit_returns_503_and_rolls_back(
    recovery_case: RecoveryCase,
    existing: bool,
) -> None:
    if existing:
        seed(recovery_case, [datetime.now(UTC) - timedelta(seconds=30)])
    before = state(recovery_case)

    def fail_commit(connection: Connection) -> None:
        connection.exec_driver_sql("SELECT 1 / 0")

    event.listen(recovery_case.engine.sync_engine, "commit", fail_commit)
    try:
        response = post(recovery_case)
    finally:
        event.remove(recovery_case.engine.sync_engine, "commit", fail_commit)
    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE}
    assert_private(response)
    assert state(recovery_case) == before
    assert not recovery_case.requests


def test_http_deadline_cancels_a_real_lock_wait(recovery_case: RecoveryCase) -> None:
    seed(recovery_case, [datetime.now(UTC)])
    before = state(recovery_case)
    recovery_case.settings.account_password_recovery_timeout_seconds = 1
    with recovery_case.inspector.connect() as locker:
        transaction = locker.begin()
        try:
            locker.execute(text("SET LOCAL ROLE askm6_app"))
            locker.execute(
                select(AuthRateLimit)
                .where(AuthRateLimit.key_hash == recovery_case.key)
                .with_for_update()
            )
            response = post(recovery_case)
        finally:
            transaction.rollback()
    assert response.status_code == 503
    assert_private(response)
    assert state(recovery_case) == before
    assert not recovery_case.requests
    recovery_case.settings.account_password_recovery_timeout_seconds = 5
    assert post(recovery_case).status_code == 202


def test_concurrent_http_requests_cannot_bypass_the_limit(recovery_case: RecoveryCase) -> None:
    assert recovery_case.client is not None and recovery_case.client.portal is not None

    async def burst() -> list[httpx2.Response]:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=recovery_case.application, client=(PEER, 12345)),
            base_url="http://testserver",
        ) as browser:
            async with asyncio.timeout(10):
                return list(
                    await asyncio.gather(
                        *(
                            browser.post(
                                PATH,
                                json={"email": EMAIL, "captcha_token": CAPTCHA},
                                headers={"Origin": ORIGIN},
                            )
                            for _ in range(8)
                        )
                    )
                )

    responses = recovery_case.client.portal.call(burst)
    assert sorted(response.status_code for response in responses) == [202, 202] + [429] * 6
    assert all(
        "Retry-After" in response.headers for response in responses if response.status_code == 429
    )
    assert len(recovery_case.requests) == 2
    stored = state(recovery_case)
    assert stored is not None and len(stored[0]) == 2


def test_mapped_ipv4_shares_limit_but_distinct_peer_has_its_own(
    recovery_case: RecoveryCase,
) -> None:
    recovery_case.settings.account_password_recovery_ip_max_requests = 1
    assert post(recovery_case).status_code == 202
    assert recovery_case.client is not None and recovery_case.client.portal is not None

    async def from_peer(peer: str) -> httpx2.Response:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=recovery_case.application, client=(peer, 12345)),
            base_url="http://testserver",
        ) as browser:
            return await browser.post(
                PATH, json={"email": EMAIL, "captcha_token": CAPTCHA}, headers={"Origin": ORIGIN}
            )

    assert recovery_case.client.portal.call(from_peer, f"::ffff:{PEER}").status_code == 429
    assert recovery_case.client.portal.call(from_peer, OTHER_PEER).status_code == 202
    assert len(recovery_case.requests) == 2
