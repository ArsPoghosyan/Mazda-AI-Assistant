"""Password-reset orchestration with real JWT verification and guarded PostgreSQL."""

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
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

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
from app.account_session_transactions import authenticate_account_session_transaction
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
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


@pytest.mark.parametrize(
    ("scenario", "expected_error"),
    [
        pytest.param("success", None, id="committed"),
        pytest.param("already-absent", None, id="recovery-session-already-absent"),
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
                        access_token_expires_at=access_expiry,
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
            engine = create_async_engine(
                integration_engine.url,
                poolclass=NullPool,
                connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
                echo=False,
                hide_parameters=True,
            )

            @event.listens_for(engine.sync_engine, "begin")
            def restrict_transaction(connection: Connection) -> None:
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
                events.append("commit")
                assert password_changed and recovery_session_absent
                assert connection.execute(owner_statement).all() == []
                # Another transaction still sees the pre-reset rows until commit.
                with integration_engine.connect() as observer:
                    assert observer.execute(sessions_statement).all() == before_sessions
                if scenario == "commit-failed":
                    connection.exec_driver_sql("SELECT 1 / 0")
                    raise AssertionError("Expected PostgreSQL division by zero")

            try:
                async with httpx2.AsyncClient(
                    transport=httpx2.MockTransport(provider),
                    trust_env=False,
                    follow_redirects=False,
                ) as client:

                    async def download_keys() -> dict[str, object]:
                        return await fetch_account_key_set(settings, client=client)

                    cache = AccountKeyCache(download_keys)
                    if expected_error is None:
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
                await engine.dispose()

        asyncio.run(run(), loop_factory=asyncio.SelectorEventLoop)
    finally:
        # The guarded fixture restricts this to local askm6_test; remove only test-owned rows.
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.user_id.in_(owners)))
            connection.execute(delete(GuestSession).where(GuestSession.id == guest_id))
            connection.execute(delete(UserProfile).where(UserProfile.id.in_(owners)))
