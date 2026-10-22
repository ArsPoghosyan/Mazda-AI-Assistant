"""Service and HTTP password resets with real JWT verification and guarded PostgreSQL."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID, uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, func, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

import app.account_session_service as session_service
from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import fetch_account_key_set
from app.account_password_reset_service import (
    AccountPasswordResetUnavailable,
    reset_account_password,
)
from app.account_password_update import (
    AccountPasswordUpdateRateLimited,
    AccountPasswordUpdateRejected,
    AccountPasswordUpdateUnavailable,
)
from app.account_recovery_session_cleanup import AccountRecoverySessionCleanupUnavailable
from app.account_recovery_verification import (
    AccountRecoveryVerificationRejected,
    AccountRecoveryVerificationUnavailable,
)
from app.account_refresh import AccountRefreshRejected
from app.account_refresh_verification import VerifiedAccountRefresh
from app.account_session_auth import AuthenticatedAccountSession, LockedAccountSession
from app.account_session_refresh import store_verified_account_refresh
from app.account_session_transactions import authenticate_account_session_transaction
from app.account_sessions import CreatedAccountSession
from app.account_sign_in_service import sign_in_account
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import InvalidAccountToken
from app.config import Settings
from app.main import create_app
from app.models import AccountSession, GuestSession, UserProfile

pytestmark = pytest.mark.integration

ISSUER = "https://auth.example.test/auth/v1"
PUBLISHABLE_KEY = "sb_publishable_synthetic_test_key"
EMAIL = SecretStr("owner@example.test")
CODE = SecretStr("001234")
NEW_PASSWORD = SecretStr("  synthetic-new-password-é  ")


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@pytest.mark.parametrize("boundary", ["service", "http"])
@pytest.mark.parametrize(
    ("scenario", "expected_error"),
    [
        pytest.param("success", None, id="committed"),
        pytest.param("already-absent", None, id="recovery-session-already-absent"),
        pytest.param("sign-in-overlap", None, id="reset-revokes-pending-sign-in"),
        pytest.param("approved-sign-in", None, id="reset-refuses-late-approved-sign-in"),
        pytest.param("refresh-overlap", None, id="reset-revokes-pending-refresh"),
        pytest.param("approved-refresh", None, id="reset-deletes-approved-refresh"),
        pytest.param(
            "recovery-rejected", AccountRecoveryVerificationRejected, id="recovery-rejected"
        ),
        pytest.param(
            "identity-mismatch", AccountRecoveryVerificationUnavailable, id="identity-mismatch"
        ),
        pytest.param("update-rejected", AccountPasswordUpdateRejected, id="password-rejected"),
        pytest.param(
            "update-rate-limited", AccountPasswordUpdateRateLimited, id="password-rate-limited"
        ),
        pytest.param(
            "update-unavailable", AccountPasswordUpdateUnavailable, id="update-acknowledgement-lost"
        ),
        pytest.param(
            "cleanup-unavailable",
            AccountRecoverySessionCleanupUnavailable,
            id="cleanup-acknowledgement-lost",
        ),
        pytest.param(
            "update-and-cleanup-unavailable",
            AccountPasswordResetUnavailable,
            id="update-and-cleanup-unavailable",
        ),
        pytest.param("commit-failed", SQLAlchemyError, id="database-commit-failed"),
    ],
)
def test_reset_preserves_ownership_and_provider_database_boundaries(
    integration_engine: Engine,
    scenario: str,
    expected_error: type[Exception] | None,
    boundary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid4()
    other_user_id = uuid4()
    guest_id = uuid4()
    recovery_session_id = uuid4()
    old_provider_session_id = uuid4()
    old_browser_token = token_urlsafe(32)
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    cipher = AccountTokenCipher(encryption_key)
    now = int(datetime.now(UTC).timestamp())
    access_expiry = datetime.fromtimestamp(now + 600, tz=UTC)

    def make_access(subject: UUID, provider_session_id: UUID) -> str:
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": "authenticated",
                "iat": now - 1,
                "exp": now + 600,
                "sub": str(subject),
                "session_id": str(provider_session_id),
                "role": "authenticated",
                "is_anonymous": False,
                "aal": "aal1",
            },
            signing_key,
            algorithm="ES256",
            headers={"kid": "reset-integration-key"},
        )

    recovery_token = make_access(user_id, recovery_session_id)
    old_access = make_access(user_id, old_provider_session_id)
    refresh_access = make_access(user_id, old_provider_session_id)
    public_jwk = ECAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    public_jwk.update(
        {"kid": "reset-integration-key", "alg": "ES256", "use": "sig", "key_ops": ["verify"]}
    )
    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
            "supabase_auth_publishable_key": PUBLISHABLE_KEY,
            "account_session_encryption_key": encryption_key,
            "account_password_reset_api_enabled": True,
            "csrf_trusted_origins": ("https://app.example.test",),
        }
    )
    owners = [user_id, other_user_id]
    sessions_statement = (
        select(AccountSession).where(AccountSession.user_id.in_(owners)).order_by(AccountSession.id)
    )
    owner_statement = select(AccountSession.id).where(AccountSession.user_id == user_id)
    profiles_statement = (
        select(UserProfile).where(UserProfile.id.in_(owners)).order_by(UserProfile.id)
    )
    guest_statement = select(GuestSession).where(GuestSession.id == guest_id)
    events: list[str] = []
    responses: list[httpx2.Response] = []
    password_changed = False
    recovery_session_absent = False

    def respond(status: int, payload: object = None) -> httpx2.Response:
        response = httpx2.Response(
            status,
            headers={} if status == 204 else {"Content-Type": "application/json"},
            stream=ResponseStream(b"" if status == 204 else json.dumps(payload).encode()),
        )
        responses.append(response)
        return response

    def provider(request: httpx2.Request) -> httpx2.Response:
        nonlocal password_changed, recovery_session_absent
        url = str(request.url)

        if request.method == "GET" and url == ISSUER + "/user":
            assert password_changed
            assert request.headers["authorization"] == f"Bearer {old_access}"
            events.append("old-session-check")
            return respond(403, {"code": "session_not_found"})

        # Reset provider calls must all precede the application transaction.
        assert "begin" not in events
        if request.method == "GET" and url == ISSUER + "/.well-known/jwks.json":
            events.append("keys")
            return respond(200, {"keys": [public_jwk]})

        assert request.headers["apikey"] == PUBLISHABLE_KEY
        if request.method == "POST" and url == ISSUER + "/verify":
            assert events == []
            assert request.headers.get("authorization") is None
            assert json.loads(request.content) == {
                "email": EMAIL.get_secret_value(),
                "token": CODE.get_secret_value(),
                "type": "recovery",
            }
            events.append("verify")
            if scenario == "recovery-rejected":
                return respond(403, {"code": "otp_expired"})
            return respond(
                200,
                {
                    "access_token": recovery_token,
                    "token_type": "bearer",
                    "user": {
                        "id": str(other_user_id if scenario == "identity-mismatch" else user_id),
                        "is_anonymous": False,
                    },
                },
            )

        assert request.headers["authorization"] == f"Bearer {recovery_token}"
        if request.method == "PUT" and url == ISSUER + "/user":
            assert events == ["verify", "keys"]
            assert json.loads(request.content) == {"password": NEW_PASSWORD.get_secret_value()}
            events.append("update")
            if scenario == "update-rejected":
                return respond(422, {"code": "weak_password"})
            if scenario == "update-rate-limited":
                return respond(429, {"code": "over_request_rate_limit"})
            # Model a password change even when its acknowledgement is lost.
            password_changed = True
            if scenario in {"update-unavailable", "update-and-cleanup-unavailable"}:
                return respond(503, {"msg": "private-provider-detail"})
            return respond(200, {"id": str(user_id), "is_anonymous": False})

        assert request.method == "POST"
        assert url == ISSUER + "/logout?scope=local"
        assert request.content == b""
        assert events == ["verify", "keys", "update"]
        events.append("cleanup")
        recovery_session_absent = True
        if scenario in {"cleanup-unavailable", "update-and-cleanup-unavailable"}:
            return respond(503, {"msg": "private-provider-detail"})
        if scenario == "already-absent":
            return respond(403, {"code": "session_not_found"})
        return respond(204)

    try:
        with integration_engine.begin() as connection:
            connection.execute(insert(UserProfile).values([{"id": owner} for owner in owners]))
            for owner, expiry in (
                (user_id, "active"),
                (user_id, "idle"),
                (user_id, "absolute"),
                (other_user_id, "active"),
            ):
                is_old_active = owner == user_id and expiry == "active"
                provider_session_id = old_provider_session_id if is_old_active else uuid4()
                browser_token = old_browser_token if is_old_active else token_urlsafe(32)
                access = old_access if is_old_active else make_access(owner, provider_session_id)
                database_now = func.statement_timestamp()
                connection.execute(
                    insert(AccountSession).values(
                        id=uuid4(),
                        user_id=owner,
                        provider_session_id=provider_session_id,
                        token_hash=sha256(browser_token.encode("ascii")).digest(),
                        access_token_ciphertext=cipher.encrypt(SecretStr(access)),
                        refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-old-refresh")),
                        access_token_expires_at=(
                            database_now - timedelta(seconds=1)
                            if scenario in {"refresh-overlap", "approved-refresh"} and is_old_active
                            else access_expiry
                        ),
                        created_at=database_now - timedelta(days=40),
                        last_seen_at=database_now - timedelta(days=10),
                        idle_expires_at=database_now
                        + (
                            timedelta(days=6)
                            if expiry == "active"
                            else timedelta(days=-1 if expiry == "idle" else -2)
                        ),
                        absolute_expires_at=database_now
                        + timedelta(days=-1 if expiry == "absolute" else 20),
                    )
                )
            database_now = func.statement_timestamp()
            connection.execute(
                insert(GuestSession).values(
                    id=guest_id,
                    token_hash=sha256(token_urlsafe(32).encode("ascii")).digest(),
                    created_at=database_now,
                    last_seen_at=database_now,
                    expires_at=database_now + timedelta(days=30),
                )
            )
            before_sessions = connection.execute(sessions_statement).all()
            before_profiles = connection.execute(profiles_statement).all()
            before_guest = connection.execute(guest_statement).one()

        async def run() -> None:
            refresh_ready = asyncio.Event()
            resume_refresh = asyncio.Event()
            pending_refresh: asyncio.Task[AuthenticatedAccountSession | None] | None = None
            refresh_events: list[str] = []
            refresh_written_rows = before_sessions
            checking_deleted_session = False
            sign_in_ready = asyncio.Event()
            resume_sign_in = asyncio.Event()
            pending_sign_in: asyncio.Task[CreatedAccountSession] | None = None
            sign_in_requests = 0
            sign_in_checks = 0
            sign_in_events: list[str] = []

            class PausingSignInCache(AccountKeyCache):
                """Pause persistence verification after real provider approval."""

                lookups = 0

                async def get_public_key(self, key_id: str) -> ec.EllipticCurvePublicKey:
                    key = await super().get_public_key(key_id)
                    self.lookups += 1
                    if self.lookups == 2:
                        assert sign_in_checks == 1
                        assert not password_changed
                        sign_in_ready.set()
                        await resume_sign_in.wait()
                    return key

            async def concurrent_provider(request: httpx2.Request) -> httpx2.Response:
                nonlocal sign_in_requests, sign_in_checks

                if (
                    scenario in {"sign-in-overlap", "approved-sign-in"}
                    and request.method == "POST"
                    and str(request.url) == ISSUER + "/token?grant_type=password"
                ):
                    sign_in_requests += 1
                    assert request.headers["apikey"] == PUBLISHABLE_KEY
                    assert json.loads(request.content) == {
                        "email": EMAIL.get_secret_value(),
                        "password": "synthetic-old-password",
                    }
                    return respond(
                        200,
                        {
                            "access_token": old_access,
                            "refresh_token": "synthetic-sign-in-refresh",
                            "token_type": "bearer",
                        },
                    )

                if (
                    scenario in {"sign-in-overlap", "approved-sign-in"}
                    and request.method == "GET"
                    and str(request.url) == ISSUER + "/user"
                ):
                    sign_in_checks += 1
                    assert request.headers["authorization"] == f"Bearer {old_access}"
                    assert request.headers["apikey"] == PUBLISHABLE_KEY
                    if scenario == "approved-sign-in":
                        if not password_changed:
                            assert sign_in_checks == 1
                            return respond(200, {"id": str(user_id), "is_anonymous": False})
                        assert sign_in_checks == 2
                    else:
                        assert not password_changed
                        sign_in_ready.set()
                        await resume_sign_in.wait()

                if scenario in {"refresh-overlap", "approved-refresh"}:
                    if (
                        request.method == "POST"
                        and str(request.url) == ISSUER + "/token?grant_type=refresh_token"
                    ):
                        assert request.headers["apikey"] == PUBLISHABLE_KEY
                        assert json.loads(request.content) == {
                            "refresh_token": "synthetic-old-refresh",
                        }
                        refresh_events.append("exchange")
                        return respond(
                            200,
                            {
                                "access_token": refresh_access,
                                "refresh_token": "synthetic-rotated-refresh",
                                "token_type": "bearer",
                            },
                        )

                    if request.method == "GET" and str(request.url) == ISSUER + "/user":
                        assert request.headers["authorization"] == f"Bearer {refresh_access}"
                        assert request.headers["apikey"] == PUBLISHABLE_KEY
                        assert not password_changed
                        refresh_events.append("check")
                        if scenario == "approved-refresh":
                            return respond(200, {"id": str(user_id), "is_anonymous": False})
                        refresh_ready.set()
                        await resume_refresh.wait()
                        assert password_changed
                        return respond(403, {"code": "session_not_found"})

                result = provider(request)
                if (
                    scenario in {"refresh-overlap", "approved-refresh"}
                    and request.method == "POST"
                    and str(request.url) == ISSUER + "/logout?scope=local"
                ):
                    # The refresh holds the row lock needed by reset's DELETE.
                    # Reject it after provider-side reset, before waiting on that lock.
                    assert password_changed and recovery_session_absent
                    resume_refresh.set()

                return result

            engine = create_async_engine(
                integration_engine.url,
                poolclass=NullPool,
                connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
                echo=False,
                hide_parameters=True,
            )

            @event.listens_for(engine.sync_engine, "begin")
            def restrict_transaction(connection: Connection) -> None:
                if asyncio.current_task() is pending_refresh:
                    refresh_events.append("begin")
                elif scenario == "approved-sign-in" and asyncio.current_task() is pending_sign_in:
                    sign_in_events.append("begin")
                else:
                    events.append("begin")
                connection.exec_driver_sql("SET LOCAL TIME ZONE 'UTC'")
                connection.exec_driver_sql("SET LOCAL ROLE askm6_app")
                assert (
                    connection.scalar(
                        text(
                            "SELECT current_user = 'askm6_app' "
                            "AND NOT rolsuper AND NOT rolbypassrls "
                            "FROM pg_roles WHERE rolname = current_user"
                        )
                    )
                    is True
                )

            @event.listens_for(engine.sync_engine, "commit")
            def inspect_commit(connection: Connection) -> None:
                nonlocal refresh_written_rows
                if checking_deleted_session:
                    assert connection.execute(owner_statement).all() == []
                    return
                if asyncio.current_task() is pending_refresh:
                    if scenario != "approved-refresh":
                        raise AssertionError("A rejected refresh must not commit.")
                    assert password_changed and recovery_session_absent
                    refresh_events.append("commit")
                    refresh_written_rows = connection.execute(sessions_statement).all()
                    own_rows = [row for row in refresh_written_rows if row.user_id == user_id]
                    refreshed_row = next(
                        row
                        for row in own_rows
                        if row.provider_session_id == old_provider_session_id
                    )
                    assert cipher.decrypt(refreshed_row.access_token_ciphertext) == SecretStr(
                        refresh_access
                    )
                    assert cipher.decrypt(refreshed_row.refresh_token_ciphertext) == SecretStr(
                        "synthetic-rotated-refresh"
                    )
                    assert refreshed_row.access_token_expires_at == access_expiry
                    old_row = next(row for row in before_sessions if row.id == refreshed_row.id)
                    assert refreshed_row.last_seen_at > old_row.last_seen_at
                    with integration_engine.connect() as observer:
                        assert observer.execute(sessions_statement).all() == before_sessions
                    return

                if scenario == "approved-sign-in" and asyncio.current_task() is pending_sign_in:
                    sign_in_events.append("commit")
                    assert password_changed and recovery_session_absent
                    late_row = connection.execute(owner_statement).one()
                    assert late_row.id is not None
                    with integration_engine.connect() as observer:
                        assert observer.execute(owner_statement).all() == []
                    return

                events.append("commit")
                assert password_changed and recovery_session_absent
                assert connection.execute(owner_statement).all() == []
                # Another transaction still sees the pre-reset rows until commit.
                with integration_engine.connect() as observer:
                    assert observer.execute(sessions_statement).all() == (
                        refresh_written_rows if scenario == "approved-refresh" else before_sessions
                    )
                if scenario == "commit-failed":
                    connection.exec_driver_sql("SELECT 1 / 0")
                    raise AssertionError("Expected PostgreSQL division by zero")

            @event.listens_for(engine.sync_engine, "rollback")
            def record_refresh_rollback(connection: Connection) -> None:
                if asyncio.current_task() is pending_refresh:
                    refresh_events.append("rollback")

            try:
                async with httpx2.AsyncClient(
                    transport=httpx2.MockTransport(concurrent_provider),
                    trust_env=False,
                    follow_redirects=False,
                ) as client:

                    async def download_keys() -> dict[str, object]:
                        return await fetch_account_key_set(settings, client=client)

                    cache = AccountKeyCache(download_keys)
                    if scenario in {"refresh-overlap", "approved-refresh"}:
                        if scenario == "approved-refresh":
                            original_store = store_verified_account_refresh

                            async def paused_store(
                                connection: AsyncConnection,
                                session: LockedAccountSession,
                                refreshed: VerifiedAccountRefresh,
                                *,
                                settings: Settings,
                            ) -> AuthenticatedAccountSession | None:
                                assert asyncio.current_task() is pending_refresh
                                assert refresh_events == ["begin", "exchange", "check"]
                                assert not password_changed
                                refresh_ready.set()
                                await resume_refresh.wait()
                                assert password_changed and recovery_session_absent
                                return await original_store(
                                    connection, session, refreshed, settings=settings
                                )

                            monkeypatch.setattr(
                                session_service, "store_verified_account_refresh", paused_store
                            )

                        async def refresh_keys() -> dict[str, object]:
                            return {"keys": [public_jwk]}

                        pending_refresh = asyncio.create_task(
                            authenticate_account_session_transaction(
                                engine,
                                SecretStr(old_browser_token),
                                settings=settings,
                                client=client,
                                key_cache=AccountKeyCache(refresh_keys),
                            )
                        )
                        await asyncio.wait_for(refresh_ready.wait(), timeout=5)
                        assert not pending_refresh.done()
                        assert refresh_events == ["begin", "exchange", "check"]

                    if scenario in {"sign-in-overlap", "approved-sign-in"}:

                        async def sign_in_keys() -> dict[str, object]:
                            return {"keys": [public_jwk]}

                        sign_in_cache = (
                            PausingSignInCache(sign_in_keys)
                            if scenario == "approved-sign-in"
                            else AccountKeyCache(sign_in_keys)
                        )
                        pending_sign_in = asyncio.create_task(
                            sign_in_account(
                                engine,
                                EMAIL,
                                SecretStr("synthetic-old-password"),
                                settings=settings,
                                client=client,
                                key_cache=sign_in_cache,
                            )
                        )
                        await asyncio.wait_for(sign_in_ready.wait(), timeout=5)
                        assert not pending_sign_in.done()
                        if scenario == "approved-sign-in":
                            assert sign_in_events == ["begin"]

                    if boundary == "http":
                        application = create_app(settings)
                        application.state.settings = settings
                        application.state.database_engine = engine
                        application.state.account_auth_client = client
                        application.state.account_key_cache = cache

                        async with httpx2.AsyncClient(
                            transport=httpx2.ASGITransport(app=application),
                            base_url="https://app.example.test",
                            trust_env=False,
                        ) as browser:
                            response = await browser.post(
                                "/api/v1/account/password-reset",
                                json={
                                    "email": EMAIL.get_secret_value(),
                                    "code": CODE.get_secret_value(),
                                    "new_password": NEW_PASSWORD.get_secret_value(),
                                },
                                headers={"Origin": "https://app.example.test"},
                            )

                        if expected_error is None:
                            assert response.status_code == 200
                            assert response.json() == {
                                "status": "completed",
                                "message": (
                                    "Password reset completed. Sign in with your new password."
                                ),
                            }
                            events.append("returned")
                        else:
                            expected_status = {
                                "recovery-rejected": 400,
                                "update-rejected": 400,
                                "update-rate-limited": 429,
                            }.get(scenario, 503)
                            expected_detail = {
                                400: "Password reset was rejected.",
                                429: "Password reset is temporarily rate limited.",
                                503: "Password reset is temporarily unavailable.",
                            }[expected_status]

                            assert response.status_code == expected_status
                            assert response.json() == {"detail": expected_detail}

                        assert response.headers["Cache-Control"] == "no-store"
                        assert "set-cookie" not in response.headers
                        assert "Retry-After" not in response.headers

                        for private_value in (
                            EMAIL.get_secret_value(),
                            CODE.get_secret_value(),
                            NEW_PASSWORD.get_secret_value(),
                            recovery_token,
                            "private-provider-detail",
                        ):
                            assert private_value not in response.text

                    elif expected_error is None:
                        await reset_account_password(
                            engine,
                            EMAIL,
                            CODE,
                            NEW_PASSWORD,
                            settings=settings,
                            client=client,
                            key_cache=cache,
                        )
                        events.append("returned")
                    else:
                        with pytest.raises(expected_error) as caught:
                            await reset_account_password(
                                engine,
                                EMAIL,
                                CODE,
                                NEW_PASSWORD,
                                settings=settings,
                                client=client,
                                key_cache=cache,
                            )
                        for private_value in (
                            EMAIL.get_secret_value(),
                            CODE.get_secret_value(),
                            NEW_PASSWORD.get_secret_value(),
                            recovery_token,
                            "private-provider-detail",
                        ):
                            assert private_value not in str(caught.value)

                    if scenario == "recovery-rejected":
                        assert events == ["verify"]
                    elif scenario == "identity-mismatch":
                        assert events == ["verify", "keys"]
                    else:
                        expected_events = ["verify", "keys", "update", "cleanup"]
                        if expected_error is None:
                            expected_events += ["begin", "commit", "returned"]
                        elif scenario == "commit-failed":
                            expected_events += ["begin", "commit"]
                        assert events == expected_events

                    with integration_engine.connect() as observer:
                        after_sessions = observer.execute(sessions_statement).all()
                        assert observer.execute(profiles_statement).all() == before_profiles
                        assert observer.execute(guest_statement).one() == before_guest
                        if expected_error is None:
                            assert observer.execute(owner_statement).all() == []
                            assert after_sessions == [
                                row for row in before_sessions if row.user_id == other_user_id
                            ]
                        else:
                            assert after_sessions == before_sessions

                    if scenario == "sign-in-overlap":
                        assert pending_sign_in is not None
                        assert password_changed and recovery_session_absent

                        resume_sign_in.set()
                        with pytest.raises(InvalidAccountToken):
                            await asyncio.wait_for(pending_sign_in, timeout=2)

                        assert sign_in_requests == 1
                        assert events[-1] == "old-session-check"
                        assert events.count("begin") == 1
                        assert events.count("commit") == 1

                        with integration_engine.connect() as observer:
                            assert observer.execute(owner_statement).all() == []
                            assert observer.execute(profiles_statement).all() == before_profiles
                            assert observer.execute(guest_statement).one() == before_guest
                            assert observer.execute(sessions_statement).all() == after_sessions

                    if scenario == "approved-sign-in":
                        assert pending_sign_in is not None
                        assert sign_in_checks == 1
                        assert password_changed and recovery_session_absent
                        resume_sign_in.set()
                        created = await asyncio.wait_for(pending_sign_in, timeout=5)
                        assert sign_in_events == ["begin", "commit"]
                        assert sign_in_requests == 1

                        with integration_engine.connect() as observer:
                            late_rows = observer.execute(sessions_statement).all()
                            own_rows = [row for row in late_rows if row.user_id == user_id]
                            assert len(own_rows) == 1
                            late_row = own_rows[0]
                            assert late_row.id == created.session_id
                            assert late_row.provider_session_id == old_provider_session_id
                            assert (
                                late_row.token_hash
                                == sha256(created.token.get_secret_value().encode("ascii")).digest()
                            )
                            assert cipher.decrypt(late_row.access_token_ciphertext) == SecretStr(
                                old_access
                            )
                            assert [row for row in late_rows if row.user_id == other_user_id] == (
                                after_sessions
                            )

                        session_settings = settings.model_copy(
                            update={
                                "account_session_api_enabled": True,
                                "account_cookie_secure": True,
                            }
                        )
                        session_application = create_app(session_settings)
                        session_application.state.settings = session_settings
                        session_application.state.database_engine = engine
                        session_application.state.account_auth_client = client
                        session_application.state.account_key_cache = cache
                        async with httpx2.AsyncClient(
                            transport=httpx2.ASGITransport(app=session_application),
                            base_url="https://app.example.test",
                            trust_env=False,
                        ) as browser:
                            session_response = await browser.post(
                                "/api/v1/account/session",
                                headers={
                                    "Origin": "https://app.example.test",
                                    "Cookie": (
                                        "__Host-askm6_account=" + created.token.get_secret_value()
                                    ),
                                },
                            )

                        assert session_response.status_code == 401
                        assert session_response.json() == {
                            "detail": "Invalid or expired account session."
                        }
                        assert session_response.headers["Cache-Control"] == "no-store"
                        assert "Max-Age=0" in session_response.headers["Set-Cookie"]
                        assert created.token.get_secret_value() not in session_response.text
                        assert old_access not in session_response.text
                        assert sign_in_checks == 2
                        assert events[-1] == "old-session-check"
                        assert sign_in_events == ["begin", "commit"]
                        with integration_engine.connect() as observer:
                            assert observer.execute(sessions_statement).all() == late_rows
                            assert observer.execute(profiles_statement).all() == before_profiles
                            assert observer.execute(guest_statement).one() == before_guest

                    if scenario == "refresh-overlap":
                        assert pending_refresh is not None
                        with pytest.raises(AccountRefreshRejected):
                            await asyncio.wait_for(pending_refresh, timeout=5)

                        assert refresh_events == ["begin", "exchange", "check", "rollback"]
                        with integration_engine.connect() as observer:
                            assert observer.execute(owner_statement).all() == []
                            assert observer.execute(sessions_statement).all() == after_sessions
                            assert observer.execute(profiles_statement).all() == before_profiles
                            assert observer.execute(guest_statement).one() == before_guest

                    if scenario == "approved-refresh":
                        assert pending_refresh is not None
                        authenticated = await asyncio.wait_for(pending_refresh, timeout=5)
                        assert authenticated is not None
                        assert authenticated.account.user_id == user_id
                        assert refresh_events == ["begin", "exchange", "check", "commit"]

                        checking_deleted_session = True
                        session_settings = settings.model_copy(
                            update={
                                "account_session_api_enabled": True,
                                "account_cookie_secure": True,
                            }
                        )
                        session_application = create_app(session_settings)
                        session_application.state.settings = session_settings
                        session_application.state.database_engine = engine
                        session_application.state.account_auth_client = client
                        session_application.state.account_key_cache = cache
                        async with httpx2.AsyncClient(
                            transport=httpx2.ASGITransport(app=session_application),
                            base_url="https://app.example.test",
                            trust_env=False,
                        ) as browser:
                            session_response = await browser.post(
                                "/api/v1/account/session",
                                headers={
                                    "Origin": "https://app.example.test",
                                    "Cookie": "__Host-askm6_account=" + old_browser_token,
                                },
                            )

                        assert session_response.status_code == 401
                        assert session_response.json() == {
                            "detail": "Invalid or expired account session."
                        }
                        assert session_response.headers["Cache-Control"] == "no-store"
                        assert "Max-Age=0" in session_response.headers["Set-Cookie"]
                        assert old_browser_token not in session_response.text
                        assert refresh_access not in session_response.text
                        assert refresh_events == ["begin", "exchange", "check", "commit"]
                        with integration_engine.connect() as observer:
                            assert observer.execute(owner_statement).all() == []
                            assert observer.execute(sessions_statement).all() == after_sessions
                            assert observer.execute(profiles_statement).all() == before_profiles
                            assert observer.execute(guest_statement).one() == before_guest

                    if password_changed and expected_error is not None:
                        # Surviving local rows must not authorize provider-revoked credentials.
                        with pytest.raises(AccountRefreshRejected):
                            await authenticate_account_session_transaction(
                                engine,
                                SecretStr(old_browser_token),
                                settings=settings,
                                client=client,
                                key_cache=cache,
                            )
                        assert events[-1] == "old-session-check"
                        with integration_engine.connect() as observer:
                            assert observer.execute(sessions_statement).all() == before_sessions

                    assert all(response.is_closed for response in responses)
            finally:
                if pending_sign_in is not None:
                    pending_sign_in.cancel()
                    await asyncio.gather(pending_sign_in, return_exceptions=True)
                if pending_refresh is not None:
                    pending_refresh.cancel()
                    await asyncio.gather(pending_refresh, return_exceptions=True)
                await engine.dispose()

        asyncio.run(run(), loop_factory=asyncio.SelectorEventLoop)
    finally:
        # The guarded fixture restricts this to local askm6_test; remove only test-owned rows.
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.user_id.in_(owners)))
            connection.execute(delete(GuestSession).where(GuestSession.id == guest_id))
            connection.execute(delete(UserProfile).where(UserProfile.id.in_(owners)))
