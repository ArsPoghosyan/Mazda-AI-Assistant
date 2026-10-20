"""Account-session HTTP authentication against guarded local PostgreSQL."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from hashlib import sha256
from http.cookies import SimpleCookie
from secrets import token_urlsafe
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, func, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.main import create_app
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

ISSUER = "https://auth.example.test/auth/v1"
ORIGIN = "https://app.example.test"
COOKIE_NAME = "__Host-askm6_account"
OLD_REFRESH = "synthetic-old-refresh"
NEW_REFRESH = "synthetic-new-refresh"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class JsonStream(httpx2.AsyncByteStream):
    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


def json_response(payload: dict[str, object]) -> httpx2.Response:
    return httpx2.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=JsonStream(payload),
    )


@pytest.mark.parametrize(
    "rollback_after_auth",
    [False, True],
    ids=["commit", "rollback"],
)
@pytest.mark.parametrize(
    "access_expired",
    [False, True],
    ids=["current-access", "refreshed-access"],
)
def test_http_authentication_obeys_transaction_boundary(
    integration_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    access_expired: bool,
    rollback_after_auth: bool,
) -> None:
    user_id = uuid4()
    provider_session_id = uuid4()
    session_id = uuid4()
    browser_token = token_urlsafe(32)
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    cipher = AccountTokenCipher(encryption_key)
    now = int(datetime.now(UTC).timestamp())

    def make_access(expiry: int) -> str:
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": "authenticated",
                "iat": now - 120,
                "exp": expiry,
                "sub": str(user_id),
                "session_id": str(provider_session_id),
                "role": "authenticated",
                "is_anonymous": False,
                "aal": "aal1",
            },
            signing_key,
            algorithm="ES256",
            headers={"kid": "http-integration-key"},
        )

    initial_expiry = now - 60 if access_expired else now + 300
    initial_access = make_access(initial_expiry)
    replacement_access = make_access(now + 600)

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": "http-integration-key",
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
            "supabase_auth_publishable_key": "sb_publishable_synthetic_test_key",
            "account_session_encryption_key": encryption_key,
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
            "account_cookie_secure": True,
            "account_session_api_enabled": True,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )

    key_requests: list[httpx2.Request] = []
    refresh_requests: list[httpx2.Request] = []

    def provider(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET" and str(request.url) == ISSUER + "/.well-known/jwks.json":
            key_requests.append(request)
            return json_response({"keys": [public_jwk]})

        assert request.method == "POST"
        assert str(request.url) == ISSUER + "/token?grant_type=refresh_token"
        assert access_expired

        refresh_requests.append(request)
        assert len(refresh_requests) == 1
        assert json.loads(request.content) == {"refresh_token": OLD_REFRESH}

        return json_response(
            {
                "access_token": replacement_access,
                "refresh_token": NEW_REFRESH,
                "token_type": "bearer",
            }
        )

    def make_http_client(**options: object) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.MockTransport(provider),
            timeout=5.0,
            follow_redirects=False,
            trust_env=False,
        )

    commit_attempts = 0

    def make_engine(configuration: Settings) -> AsyncEngine:
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
        def check_commit_boundary(connection: Connection) -> None:
            nonlocal commit_attempts
            commit_attempts += 1

            if not rollback_after_auth:
                return

            during = connection.execute(statement).one()
            assert during.last_seen_at > before.last_seen_at

            if access_expired:
                assert during.access_token_ciphertext != before.access_token_ciphertext
                assert during.refresh_token_ciphertext != before.refresh_token_ciphertext

            # Authentication wrote successfully, but commit cannot complete.
            connection.exec_driver_sql("SELECT 1 / 0")
            raise AssertionError("Expected PostgreSQL division by zero")

        return engine

    monkeypatch.setattr(
        "app.main.create_database_engine",
        make_engine,
    )
    monkeypatch.setattr(
        "app.main.httpx2",
        SimpleNamespace(
            AsyncClient=Mock(side_effect=make_http_client),
            Limits=httpx2.Limits,
        ),
    )

    statement = select(AccountSession).where(AccountSession.id == session_id)

    try:
        with integration_engine.begin() as connection:
            connection.execute(insert(UserProfile).values(id=user_id))
            connection.execute(
                insert(AccountSession).values(
                    id=session_id,
                    user_id=user_id,
                    provider_session_id=provider_session_id,
                    token_hash=sha256(browser_token.encode("ascii")).digest(),
                    access_token_ciphertext=cipher.encrypt(SecretStr(initial_access)),
                    refresh_token_ciphertext=cipher.encrypt(SecretStr(OLD_REFRESH)),
                    access_token_expires_at=datetime.fromtimestamp(
                        initial_expiry,
                        tz=UTC,
                    ),
                    created_at=func.statement_timestamp() - timedelta(days=10),
                    last_seen_at=func.statement_timestamp() - timedelta(days=1),
                    idle_expires_at=func.statement_timestamp() + timedelta(days=6),
                    absolute_expires_at=(func.statement_timestamp() + timedelta(days=20)),
                )
            )
            before = connection.execute(statement).one()

        with TestClient(
            create_app(settings),
            base_url="https://api.example.test",
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            response = client.post(
                "/api/v1/account/session",
                headers={
                    "Origin": ORIGIN,
                    "Cookie": f"{COOKIE_NAME}={browser_token}",
                },
            )

            assert response.headers["Cache-Control"] == "no-store"

            with integration_engine.connect() as observer:
                after = observer.execute(statement).one()

            assert commit_attempts == 1
            assert len(key_requests) == 1
            assert len(refresh_requests) == int(access_expired)

            if rollback_after_auth:
                assert response.status_code == 503
                assert response.json() == {
                    "detail": "Account sessions are temporarily unavailable."
                }
                assert "set-cookie" not in response.headers
                assert dict(after._mapping) == dict(before._mapping)
                return

            assert response.status_code == 200

            body = response.json()
            assert set(body) == {
                "user_id",
                "expires_at",
                "absolute_expires_at",
            }
            assert body["user_id"] == str(user_id)
            assert datetime.fromisoformat(body["expires_at"]) == after.idle_expires_at
            assert datetime.fromisoformat(body["absolute_expires_at"]) == after.absolute_expires_at

            cookies: SimpleCookie = SimpleCookie()
            cookies.load(response.headers["set-cookie"])
            cookie = cookies[COOKIE_NAME]
            assert cookie.value == browser_token
            assert parsedate_to_datetime(cookie["expires"]) == (
                after.idle_expires_at.replace(microsecond=0)
            )
            assert bool(cookie["secure"])
            assert bool(cookie["httponly"])
            assert cookie["samesite"] == "lax"
            assert cookie["path"] == "/"
            assert cookie["domain"] == ""

            expected_access = replacement_access if access_expired else initial_access
            expected_refresh = NEW_REFRESH if access_expired else OLD_REFRESH
            assert (
                cipher.decrypt(after.access_token_ciphertext).get_secret_value() == expected_access
            )
            assert (
                cipher.decrypt(after.refresh_token_ciphertext).get_secret_value()
                == expected_refresh
            )

            assert after.access_token_expires_at == datetime.fromtimestamp(
                now + 600 if access_expired else initial_expiry,
                tz=UTC,
            )
            assert after.last_seen_at > before.last_seen_at
            assert after.idle_expires_at == min(
                after.last_seen_at + timedelta(days=7),
                before.absolute_expires_at,
            )
            assert after.user_id == before.user_id
            assert after.provider_session_id == before.provider_session_id
            assert after.token_hash == before.token_hash
            assert after.created_at == before.created_at
            assert after.absolute_expires_at == before.absolute_expires_at

            for secret in (
                browser_token,
                initial_access,
                replacement_access,
                OLD_REFRESH,
                NEW_REFRESH,
            ):
                assert secret not in response.text
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.id == session_id))
            connection.execute(delete(UserProfile).where(UserProfile.id == user_id))
