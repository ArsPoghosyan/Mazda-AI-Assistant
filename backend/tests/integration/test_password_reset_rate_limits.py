"""Real HTTP/PG password-reset accounting with a mocked reset service.

The existing password-reset service integration suite separately exercises real
JWT verification, mocked provider HTTP and committed application revocation.
"""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from unittest.mock import Mock

import httpx2
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app import auth_rate_limits as limiter
from app.account_key_cache import AccountKeyCache
from app.account_password_reset_routes import router
from app.account_password_reset_service import AccountPasswordResetUnavailable
from app.account_password_update import AccountPasswordUpdateRateLimited
from app.account_recovery_verification import (
    AccountRecoveryVerificationRateLimited,
    AccountRecoveryVerificationRejected,
)
from app.auth_rate_limit_keys import (
    get_email_confirmation_ip_key,
    get_password_recovery_ip_key,
    get_password_reset_ip_key,
    get_sign_in_ip_key,
    get_sign_up_ip_key,
)
from app.config import Settings
from app.models import AuthRateLimit

pytestmark = pytest.mark.integration
PATH = "/api/v1/account/password-reset"
ORIGIN = "https://app.example.test"
PEER = "192.0.2.12"
OTHER_PEER = "198.51.100.20"
EMAIL = "owner@example.test"
CODE = "001234"
PASSWORD = "  synthetic-new-password-é  "
UNAVAILABLE = "Password reset is temporarily unavailable."


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass
class ResetCase:
    application: FastAPI
    engine: AsyncEngine
    inspector: Engine
    settings: Settings
    keys: dict[tuple[str, str], bytes] = field(repr=False)
    client: TestClient | None = None
    service_error: Exception | None = field(default=None, repr=False)
    calls: list[tuple[SecretStr, SecretStr, SecretStr]] = field(default_factory=list, repr=False)


@pytest.fixture
def reset_case(integration_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[ResetCase]:
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": None,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "account_password_reset_api_enabled": True,
            "account_password_reset_ip_max_requests": 2,
            "account_password_reset_timeout_seconds": 5,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )
    keys = {
        (purpose, peer): function(
            Request({"type": "http", "headers": [], "client": (peer, 12345)}), settings
        )
        for purpose, function in (
            ("password_reset", get_password_reset_ip_key),
            ("password_recovery", get_password_recovery_ip_key),
            ("sign_in", get_sign_in_ip_key),
            ("sign_up", get_sign_up_ip_key),
            ("email_confirmation", get_email_confirmation_ip_key),
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
    provider_client = Mock(spec=httpx2.AsyncClient)
    key_cache = Mock(spec=AccountKeyCache)
    case: ResetCase

    async def service(
        selected_engine: AsyncEngine,
        email: SecretStr,
        code: SecretStr,
        password: SecretStr,
        *,
        settings: Settings,
        client: httpx2.AsyncClient,
        key_cache: AccountKeyCache | None,
    ) -> None:
        assert selected_engine is engine and settings is case.settings
        assert client is provider_client and key_cache is case.application.state.account_key_cache
        assert email.get_secret_value() in (EMAIL, "another@example.test")
        assert code.get_secret_value() == CODE and password.get_secret_value() == PASSWORD
        async with engine.connect() as connection:
            rows = (
                await connection.execute(
                    select(AuthRateLimit.request_times).where(
                        AuthRateLimit.purpose == "password_reset",
                        AuthRateLimit.key_hash.in_(keys.values()),
                    )
                )
            ).all()
            # Accounting must be committed and visible on another connection.
            assert sum(len(row.request_times) for row in rows) >= 1
        case.calls.append((email, code, password))
        if case.service_error is not None:
            raise case.service_error

    monkeypatch.setattr("app.account_password_reset_routes.reset_account_password", service)

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
            application.state.settings = settings
            application.state.database_engine = engine
            application.state.account_auth_client = provider_client
            application.state.account_key_cache = key_cache
            yield
        finally:
            await engine.dispose()

    application = FastAPI(lifespan=lifespan)
    application.include_router(router)
    case = ResetCase(application, engine, integration_engine, settings, keys)
    try:
        with TestClient(
            application,
            client=(PEER, 12345),
            backend_options={
                "loop_factory": asyncio.SelectorEventLoop,
            },
        ) as client:
            case.client = client
            yield case
    finally:
        provider_client.assert_not_called()
        assert not provider_client.method_calls
        with integration_engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE askm6_app"))
            connection.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.purpose.in_(
                        [
                            "password_recovery",
                            "sign_in",
                            "sign_up",
                            "email_confirmation",
                            "password_reset",
                        ]
                    ),
                    AuthRateLimit.key_hash.in_(keys.values()),
                )
            )


def post(case: ResetCase, **headers: str) -> httpx2.Response:
    assert case.client is not None
    return case.client.post(
        PATH,
        json={"email": EMAIL, "code": CODE, "new_password": PASSWORD},
        headers={"Origin": ORIGIN, **headers},
    )


def state(
    case: ResetCase, purpose: str = "password_reset"
) -> tuple[list[datetime], datetime] | None:
    with case.inspector.connect() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        row = connection.execute(
            select(AuthRateLimit).where(
                AuthRateLimit.purpose == purpose, AuthRateLimit.key_hash == case.keys[purpose, PEER]
            )
        ).one_or_none()
        return None if row is None else (list(row.request_times), row.expires_at)


def seed(case: ResetCase, times: list[datetime], purpose: str = "password_reset") -> None:
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
        value not in response.text for value in (EMAIL, CODE, PASSWORD, "private-provider-detail")
    )


def test_reset_acknowledges_without_logging_in(reset_case: ResetCase) -> None:
    response = post(reset_case)
    assert response.status_code == 200
    assert response.json() == {
        "status": "completed",
        "message": "Password reset completed. Sign in with your new password.",
    }
    assert_private(response)
    stored = state(reset_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(reset_case.calls) == 1


def test_local_cap_prevents_body_parsing_and_cannot_be_bypassed_by_email_or_header(
    reset_case: ResetCase,
) -> None:
    assert post(reset_case).status_code == 200
    assert reset_case.client is not None
    assert (
        reset_case.client.post(
            PATH,
            json={"email": "another@example.test", "code": CODE, "new_password": PASSWORD},
            headers={"Origin": ORIGIN},
        ).status_code
        == 200
    )
    before = state(reset_case)
    response = reset_case.client.post(
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
    assert state(reset_case) == before and len(reset_case.calls) == 2


@pytest.mark.parametrize("body", [b"{}", b"not-json"])
def test_invalid_body_remains_counted(reset_case: ResetCase, body: bytes) -> None:
    assert reset_case.client is not None
    response = reset_case.client.post(
        PATH, content=body, headers={"Origin": ORIGIN, "Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert_private(response)
    stored = state(reset_case)
    assert stored is not None and len(stored[0]) == 1
    assert not reset_case.calls


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (AccountRecoveryVerificationRejected, 400),
        (AccountPasswordResetUnavailable, 503),
        (AccountRecoveryVerificationRateLimited, 429),
        (AccountPasswordUpdateRateLimited, 429),
    ],
)
def test_service_failures_do_not_refund_attempts(
    reset_case: ResetCase, failure: type[Exception], expected: int
) -> None:
    reset_case.service_error = failure("private-provider-detail")
    response = post(reset_case)
    assert response.status_code == expected
    assert "Retry-After" not in response.headers
    assert_private(response)
    stored = state(reset_case)
    assert stored is not None and len(stored[0]) == 1
    assert len(reset_case.calls) == 1


@pytest.mark.parametrize(
    "guard",
    ["origin", "disabled", "engine", "client", "key-cache", "hmac", "issuer", "publishable-key"],
)
def test_guards_do_not_count_or_contact_provider(reset_case: ResetCase, guard: str) -> None:
    if guard == "disabled":
        reset_case.settings.account_password_reset_api_enabled = False
    elif guard in ("engine", "client"):
        setattr(
            reset_case.application.state,
            "database_engine" if guard == "engine" else "account_auth_client",
            None,
        )
    elif guard == "key-cache":
        reset_case.application.state.account_key_cache = None
    elif guard != "origin":
        name = {
            "hmac": "auth_rate_limit_hmac_secret",
            "issuer": "supabase_auth_issuer",
            "publishable-key": "supabase_auth_publishable_key",
        }[guard]
        setattr(reset_case.settings, name, None)
    response = post(
        reset_case, Origin="https://untrusted.example.test" if guard == "origin" else ORIGIN
    )
    assert response.status_code == (403 if guard == "origin" else 503)
    assert_private(response)
    assert state(reset_case) is None and not reset_case.calls


@pytest.mark.parametrize("existing", [False, True])
def test_failed_accounting_commit_rolls_back_without_provider(
    reset_case: ResetCase, existing: bool
) -> None:
    if existing:
        seed(reset_case, [datetime.now(UTC) - timedelta(seconds=30)])
    before = state(reset_case)

    def fail_commit(connection: Connection) -> None:
        connection.exec_driver_sql("SELECT 1 / 0")

    event.listen(reset_case.engine.sync_engine, "commit", fail_commit)
    try:
        response = post(reset_case)
    finally:
        event.remove(reset_case.engine.sync_engine, "commit", fail_commit)
    assert response.status_code == 503 and response.json() == {"detail": UNAVAILABLE}
    assert_private(response)
    assert state(reset_case) == before and not reset_case.calls


def test_real_lock_wait_is_bounded_and_recovers(reset_case: ResetCase) -> None:
    seed(reset_case, [datetime.now(UTC)])
    before = state(reset_case)
    reset_case.settings.account_password_reset_timeout_seconds = 1
    with reset_case.inspector.connect() as locker:
        transaction = locker.begin()
        try:
            locker.execute(text("SET LOCAL ROLE askm6_app"))
            locker.execute(
                select(AuthRateLimit)
                .where(
                    AuthRateLimit.purpose == "password_reset",
                    AuthRateLimit.key_hash == reset_case.keys["password_reset", PEER],
                )
                .with_for_update()
            )
            response = post(reset_case)
        finally:
            transaction.rollback()
    assert response.status_code == 503
    assert_private(response)
    assert state(reset_case) == before and not reset_case.calls
    reset_case.settings.account_password_reset_timeout_seconds = 5
    assert post(reset_case).status_code == 200


def test_concurrent_resets_cannot_exceed_cap(reset_case: ResetCase) -> None:
    assert reset_case.client is not None and reset_case.client.portal is not None

    async def burst() -> list[httpx2.Response]:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=reset_case.application, client=(PEER, 12345)),
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
                                    "new_password": PASSWORD,
                                },
                                headers={"Origin": ORIGIN},
                            )
                            for _ in range(8)
                        )
                    )
                )

    responses = reset_case.client.portal.call(burst)
    assert sorted(response.status_code for response in responses) == [200, 200] + [429] * 6
    assert all(
        "Retry-After" in response.headers for response in responses if response.status_code == 429
    )
    stored = state(reset_case)
    assert stored is not None and len(stored[0]) == 2
    assert len(reset_case.calls) == 2


def test_exact_retry_and_expiry(reset_case: ResetCase, monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC)
    current = now

    async def clock(_connection: AsyncConnection) -> datetime:
        return current

    monkeypatch.setattr(limiter, "_database_now", clock)
    seed(reset_case, [now - timedelta(seconds=590.2), now - timedelta(seconds=5)])
    before = state(reset_case)
    response = post(reset_case)
    assert response.status_code == 429 and response.headers["Retry-After"] == "10"
    assert state(reset_case) == before and not reset_case.calls
    current = now + timedelta(seconds=10)
    assert post(reset_case).status_code == 200
    assert state(reset_case) == (
        [now - timedelta(seconds=5), current],
        current + timedelta(seconds=600),
    )


def test_other_auth_budgets_do_not_block_or_change(reset_case: ResetCase) -> None:
    now = datetime.now(UTC)
    for purpose in ("password_recovery", "sign_in", "sign_up", "email_confirmation"):
        seed(reset_case, [now] * 30, purpose)
    before = {
        purpose: state(reset_case, purpose)
        for purpose in ("password_recovery", "sign_in", "sign_up", "email_confirmation")
    }
    assert post(reset_case).status_code == 200
    assert post(reset_case).status_code == 200
    assert post(reset_case).status_code == 429
    assert {purpose: state(reset_case, purpose) for purpose in before} == before


def test_mapped_peer_cannot_split_budget_and_distinct_peer_is_independent(
    reset_case: ResetCase,
) -> None:
    reset_case.settings.account_password_reset_ip_max_requests = 1
    assert post(reset_case).status_code == 200
    assert reset_case.client is not None and reset_case.client.portal is not None

    async def from_peer(peer: str) -> httpx2.Response:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=reset_case.application, client=(peer, 12345)),
            base_url="http://testserver",
        ) as browser:
            return await browser.post(
                PATH,
                json={"email": EMAIL, "code": CODE, "new_password": PASSWORD},
                headers={"Origin": ORIGIN},
            )

    assert reset_case.client.portal.call(from_peer, f"::ffff:{PEER}").status_code == 429
    assert reset_case.client.portal.call(from_peer, OTHER_PEER).status_code == 200
    assert len(reset_case.calls) == 2
