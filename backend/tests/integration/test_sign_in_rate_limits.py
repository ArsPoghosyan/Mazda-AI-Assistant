"""Sign-in HTTP accounting on guarded PostgreSQL with mocked provider responses."""

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_hex

import httpx2
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app import auth_rate_limits as limiter
from app.account_key_cache import AccountKeyCache
from app.account_password_recovery_routes import router as recovery_router
from app.account_sign_in_routes import router
from app.auth_rate_limit_keys import get_password_recovery_ip_key, get_sign_in_ip_key
from app.config import Settings
from app.models import AuthRateLimit

pytestmark = pytest.mark.integration
PATH = "/api/v1/account/sign-in"
ORIGIN = "https://app.example.test"
PEER = "192.0.2.12"
OTHER_PEER = "198.51.100.20"
EMAIL = "owner@example.test"
PASSWORD = "  synthetic-password-é  "
CAPTCHA = "synthetic-sign-in-proof"
UNAVAILABLE = "Account sign-in is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class JSONStream(httpx2.AsyncByteStream):
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@dataclass
class SignInCase:
    application: FastAPI
    engine: AsyncEngine
    inspector: Engine
    settings: Settings
    key: bytes = field(repr=False)
    recovery_key: bytes = field(repr=False)
    client: TestClient | None = None
    provider_status: int = 400
    provider_payload: object = field(default_factory=lambda: {"code": "invalid_credentials"})
    requests: list[httpx2.Request] = field(default_factory=list, repr=False)
    visible_counts: list[int] = field(default_factory=list)


@pytest.fixture
def sign_in_case(integration_engine: Engine) -> Iterator[SignInCase]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": Fernet.generate_key().decode("ascii"),
            "auth_rate_limit_hmac_secret": token_hex(32),
            "account_sign_in_api_enabled": True,
            "account_sign_in_ip_max_requests": 2,
            "account_sign_in_timeout_seconds": 5,
            "account_password_recovery_api_enabled": True,
            "account_password_recovery_ip_max_requests": 1,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    keys = []
    for function in (get_sign_in_ip_key, get_password_recovery_ip_key):
        for peer in (PEER, OTHER_PEER):
            keys.append(
                function(
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
    case: SignInCase

    async def fetch_keys() -> dict[str, object]:
        raise AssertionError("Rejected sign-in must not fetch signing keys.")

    async def provider(request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        assert "cookie" not in request.headers and "authorization" not in request.headers
        assert request.headers["apikey"] == "sb_publishable_synthetic_test_key"
        payload: object
        if str(request.url) == "https://auth.example.test/auth/v1/recover":
            purpose = "password_recovery"
            response_status, payload = 200, {}
        else:
            assert str(request.url) == "https://auth.example.test/auth/v1/token?grant_type=password"
            purpose = "sign_in"
            response_status, payload = case.provider_status, case.provider_payload
            body = json.loads(request.content)
            assert body["password"] == PASSWORD
            assert body["gotrue_meta_security"] == {"captcha_token": CAPTCHA}
        # A separate connection must see committed accounting before delivery.
        async with engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(AuthRateLimit.request_times).where(
                        AuthRateLimit.purpose == purpose,
                        AuthRateLimit.key_hash.in_(keys),
                    )
                )
            ).all()
            visible = sum(len(row.request_times) for row in rows)
            assert visible >= 1
            case.visible_counts.append(visible)
        case.requests.append(request)
        return httpx2.Response(
            response_status,
            headers={"Content-Type": "application/json"},
            stream=JSONStream(payload),
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
            ) as provider_client:
                application.state.settings = settings
                application.state.database_engine = engine
                application.state.account_auth_client = provider_client
                application.state.account_key_cache = AccountKeyCache(fetch_keys)
                yield
        finally:
            await engine.dispose()

    application = FastAPI(lifespan=lifespan)
    application.include_router(router)
    application.include_router(recovery_router)
    case = SignInCase(application, engine, integration_engine, settings, keys[0], keys[2])
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
                    AuthRateLimit.purpose.in_(["password_recovery", "sign_in"]),
                    AuthRateLimit.key_hash.in_(keys),
                )
            )


def post(case: SignInCase, email: str = EMAIL, **headers: str) -> httpx2.Response:
    assert case.client is not None
    return case.client.post(
        PATH,
        json={"email": email, "password": PASSWORD, "captcha_token": CAPTCHA},
        headers={"Origin": ORIGIN, **headers},
    )


def state(case: SignInCase, *, purpose: str = "sign_in") -> tuple[list[datetime], datetime] | None:
    with case.inspector.connect() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        row = connection.execute(
            select(AuthRateLimit).where(
                AuthRateLimit.purpose == purpose,
                AuthRateLimit.key_hash == (case.key if purpose == "sign_in" else case.recovery_key),
            )
        ).one_or_none()
        return None if row is None else (list(row.request_times), row.expires_at)


def seed(case: SignInCase, times: list[datetime]) -> None:
    with case.inspector.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(
            insert(AuthRateLimit).values(
                purpose="sign_in",
                key_hash=case.key,
                request_times=times,
                expires_at=max(times) + timedelta(seconds=600),
            )
        )


def assert_private(response: httpx2.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert (
        EMAIL not in response.text
        and PASSWORD not in response.text
        and CAPTCHA not in response.text
    )


def test_accounting_is_committed_before_rejected_credentials_reach_provider(
    sign_in_case: SignInCase,
) -> None:
    response = post(sign_in_case)
    assert response.status_code == 401
    assert_private(response)
    assert sign_in_case.visible_counts == [1]
    stored = state(sign_in_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(sign_in_case.requests) == 1


def test_cap_blocks_new_email_spoofed_header_and_invalid_body_without_mutation(
    sign_in_case: SignInCase,
) -> None:
    assert post(sign_in_case).status_code == 401
    assert post(sign_in_case, "another@example.test").status_code == 401
    before = state(sign_in_case)
    assert sign_in_case.client is not None
    response = sign_in_case.client.post(
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
    assert state(sign_in_case) == before
    assert len(sign_in_case.requests) == 2


def test_http_retry_rounding_and_individual_expiry(
    sign_in_case: SignInCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    current = now

    async def clock(_connection: AsyncConnection) -> datetime:
        return current

    monkeypatch.setattr(limiter, "_database_now", clock)
    seed(sign_in_case, [now - timedelta(seconds=590.2), now - timedelta(seconds=5)])
    before = state(sign_in_case)
    denied = post(sign_in_case)
    assert denied.status_code == 429 and denied.headers["Retry-After"] == "10"
    assert state(sign_in_case) == before and not sign_in_case.requests
    current = now + timedelta(seconds=10)
    assert post(sign_in_case).status_code == 401
    assert state(sign_in_case) == (
        [now - timedelta(seconds=5), current],
        current + timedelta(seconds=600),
    )


@pytest.mark.parametrize("body", [b"not-json", b"{}"])
def test_invalid_body_consumes_one_committed_attempt(sign_in_case: SignInCase, body: bytes) -> None:
    assert sign_in_case.client is not None
    response = sign_in_case.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert_private(response)
    stored = state(sign_in_case)
    assert stored is not None and len(stored[0]) == 1
    assert not sign_in_case.requests


@pytest.mark.parametrize(
    ("provider_status", "payload", "expected"),
    [
        (400, {"code": "captcha_failed"}, 403),
        (500, {}, 503),
        (429, {"code": "over_request_rate_limit"}, 503),
    ],
)
def test_provider_failures_retain_accounting_without_invented_retry_header(
    sign_in_case: SignInCase,
    provider_status: int,
    payload: object,
    expected: int,
) -> None:
    sign_in_case.provider_status = provider_status
    sign_in_case.provider_payload = payload
    response = post(sign_in_case)
    assert response.status_code == expected
    assert_private(response)
    assert "Retry-After" not in response.headers
    stored = state(sign_in_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(sign_in_case.requests) == 1


def test_invalid_origin_never_counts(sign_in_case: SignInCase) -> None:
    response = post(sign_in_case, Origin="https://untrusted.example.test")
    assert response.status_code == 403
    assert_private(response)
    assert state(sign_in_case) is None and not sign_in_case.requests


@pytest.mark.parametrize(
    "missing",
    [
        "supabase_auth_issuer",
        "supabase_auth_publishable_key",
        "account_session_encryption_key",
        "auth_rate_limit_hmac_secret",
    ],
)
def test_missing_configuration_never_counts(sign_in_case: SignInCase, missing: str) -> None:
    setattr(sign_in_case.settings, missing, None)
    response = post(sign_in_case)
    assert response.status_code == 503
    assert_private(response)
    assert state(sign_in_case) is None and not sign_in_case.requests


@pytest.mark.parametrize("existing", [False, True])
def test_accounting_commit_error_returns_503_and_rolls_back(
    sign_in_case: SignInCase,
    existing: bool,
) -> None:
    if existing:
        seed(sign_in_case, [datetime.now(UTC) - timedelta(seconds=30)])
    before = state(sign_in_case)

    def fail_commit(connection: Connection) -> None:
        connection.exec_driver_sql("SELECT 1 / 0")

    event.listen(sign_in_case.engine.sync_engine, "commit", fail_commit)
    try:
        response = post(sign_in_case)
    finally:
        event.remove(sign_in_case.engine.sync_engine, "commit", fail_commit)
    assert response.status_code == 503 and response.json() == {"detail": UNAVAILABLE}
    assert_private(response)
    assert state(sign_in_case) == before and not sign_in_case.requests


def test_http_deadline_cancels_real_accounting_lock_wait(sign_in_case: SignInCase) -> None:
    seed(sign_in_case, [datetime.now(UTC)])
    before = state(sign_in_case)
    sign_in_case.settings.account_sign_in_timeout_seconds = 1
    with sign_in_case.inspector.connect() as locker:
        transaction = locker.begin()
        try:
            locker.execute(text("SET LOCAL ROLE askm6_app"))
            locker.execute(
                select(AuthRateLimit)
                .where(
                    AuthRateLimit.purpose == "sign_in",
                    AuthRateLimit.key_hash == sign_in_case.key,
                )
                .with_for_update()
            )
            response = post(sign_in_case)
        finally:
            transaction.rollback()
    assert response.status_code == 503
    assert_private(response)
    assert state(sign_in_case) == before and not sign_in_case.requests
    sign_in_case.settings.account_sign_in_timeout_seconds = 5
    assert post(sign_in_case).status_code == 401


def test_concurrent_http_requests_cannot_exceed_cap(sign_in_case: SignInCase) -> None:
    assert sign_in_case.client is not None and sign_in_case.client.portal is not None

    async def burst() -> list[httpx2.Response]:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=sign_in_case.application, client=(PEER, 12345)),
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
                                    "password": PASSWORD,
                                    "captcha_token": CAPTCHA,
                                },
                                headers={"Origin": ORIGIN},
                            )
                            for _ in range(8)
                        )
                    )
                )

    responses = sign_in_case.client.portal.call(burst)
    assert sorted(response.status_code for response in responses) == [401, 401] + [429] * 6
    assert all(
        "Retry-After" in response.headers for response in responses if response.status_code == 429
    )
    stored = state(sign_in_case)
    assert stored is not None and len(stored[0]) == 2
    assert len(sign_in_case.requests) == 2


def test_mapped_ipv4_shares_budget_and_distinct_peer_has_its_own(sign_in_case: SignInCase) -> None:
    sign_in_case.settings.account_sign_in_ip_max_requests = 1
    assert post(sign_in_case).status_code == 401
    assert sign_in_case.client is not None and sign_in_case.client.portal is not None

    async def from_peer(peer: str) -> httpx2.Response:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=sign_in_case.application, client=(peer, 12345)),
            base_url="http://testserver",
        ) as browser:
            return await browser.post(
                PATH,
                json={"email": EMAIL, "password": PASSWORD, "captcha_token": CAPTCHA},
                headers={"Origin": ORIGIN},
            )

    assert sign_in_case.client.portal.call(from_peer, f"::ffff:{PEER}").status_code == 429
    assert sign_in_case.client.portal.call(from_peer, OTHER_PEER).status_code == 401
    assert len(sign_in_case.requests) == 2


def test_sign_in_and_recovery_http_budgets_are_independent(sign_in_case: SignInCase) -> None:
    assert sign_in_case.client is not None

    def recover() -> httpx2.Response:
        assert sign_in_case.client is not None
        return sign_in_case.client.post(
            "/api/v1/account/password-recovery",
            json={"email": EMAIL, "captcha_token": CAPTCHA},
            headers={"Origin": ORIGIN},
        )

    assert recover().status_code == 202
    recovery_before = state(sign_in_case, purpose="password_recovery")
    assert recover().status_code == 429
    assert post(sign_in_case).status_code == 401
    assert post(sign_in_case).status_code == 401
    assert post(sign_in_case).status_code == 429
    assert state(sign_in_case, purpose="password_recovery") == recovery_before
    assert len(sign_in_case.requests) == 3


def test_disabled_sign_in_never_counts(sign_in_case: SignInCase) -> None:
    sign_in_case.settings.account_sign_in_api_enabled = False
    response = post(sign_in_case)
    assert response.status_code == 503
    assert_private(response)
    assert state(sign_in_case) is None and not sign_in_case.requests


def test_proxy_visitors_have_separate_budgets_and_spoofing_cannot_reset_them(
    sign_in_case: SignInCase,
) -> None:
    sign_in_case.settings.auth_proxy_trust_enabled = True
    sign_in_case.settings.auth_proxy_shared_secret = SecretStr("ab" * 32)
    sign_in_case.settings.account_sign_in_ip_max_requests = 1
    headers = {"X-AskM6-Proxy-Secret": "ab" * 32, "X-AskM6-Client-IP": PEER}
    assert post(sign_in_case, **headers).status_code == 401
    before = state(sign_in_case)
    assert post(sign_in_case, **{**headers, "X-Forwarded-For": OTHER_PEER}).status_code == 429
    assert (
        post(sign_in_case, **{**headers, "X-AskM6-Client-IP": f"::ffff:{PEER}"}).status_code == 429
    )
    assert post(sign_in_case, **{**headers, "X-AskM6-Client-IP": OTHER_PEER}).status_code == 401
    assert post(sign_in_case, **{"CF-Connecting-IP": OTHER_PEER}).status_code == 503
    assert state(sign_in_case) == before
    assert len(sign_in_case.requests) == 2
    assert all("x-askm6-proxy-secret" not in request.headers for request in sign_in_case.requests)
