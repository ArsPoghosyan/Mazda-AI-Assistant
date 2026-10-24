"""HTTP sign-in with real verification and guarded local PostgreSQL."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from hashlib import sha256
from http.cookies import SimpleCookie
from secrets import token_hex
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Request
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_token_encryption import AccountTokenCipher
from app.auth_rate_limit_keys import get_sign_in_ip_key
from app.config import Settings
from app.main import create_app
from app.models import AccountSession, AuthRateLimit, UserProfile

pytestmark = pytest.mark.integration

ISSUER = "https://auth.example.test/auth/v1"
ORIGIN = "https://app.example.test"
COOKIE_NAME = "__Host-askm6_account"
EMAIL = "owner@example.test"
PASSWORD = "  synthetic-password-é  "
CAPTCHA_TOKEN = "synthetic-account-captcha-proof"
OLD_BROWSER_TOKEN = "B" * 43


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
    "fail_commit",
    [False, True],
    ids=["committed", "rolled-back"],
)
def test_http_sign_in_obeys_commit_boundary(
    integration_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    fail_commit: bool,
) -> None:
    user_id = uuid4()
    provider_session_id = uuid4()
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    cipher = AccountTokenCipher(encryption_key)

    now = int(datetime.now(UTC).timestamp())
    expiry = now + 300

    access_token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "authenticated",
            "iat": now - 1,
            "exp": expiry,
            "sub": str(user_id),
            "session_id": str(provider_session_id),
            "role": "authenticated",
            "is_anonymous": False,
            "aal": "aal1",
        },
        signing_key,
        algorithm="ES256",
        headers={"kid": "sign-in-http-key"},
    )
    refresh_token = "synthetic-http-sign-in-refresh"

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": "sign-in-http-key",
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
            "account_sign_in_api_enabled": True,
            "account_sign_in_timeout_seconds": 15,
            "auth_rate_limit_hmac_secret": token_hex(32),
            "csrf_trusted_origins": (ORIGIN,),
        }
    )

    rate_key = get_sign_in_ip_key(
        Request({"type": "http", "headers": [], "client": ("192.0.2.12", 12345)}), settings
    )
    rate_statement = select(AuthRateLimit).where(
        AuthRateLimit.purpose == "sign_in", AuthRateLimit.key_hash == rate_key
    )
    events: list[str] = []
    key_requests: list[httpx2.Request] = []
    sign_in_requests: list[httpx2.Request] = []

    session_statement = select(AccountSession).where(
        AccountSession.provider_session_id == provider_session_id
    )
    profile_statement = select(UserProfile.id).where(UserProfile.id == user_id)

    def provider(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET" and str(request.url) == ISSUER + "/user":
            assert events == ["limit-begin", "limit-commit", "provider"]
            assert request.headers["authorization"] == f"Bearer {access_token}"
            assert request.headers["apikey"] == "sb_publishable_synthetic_test_key"
            assert request.content == b""
            events.append("verify")
            return json_response({"id": str(user_id), "is_anonymous": False})

        if request.method == "GET":
            assert str(request.url) == ISSUER + "/.well-known/jwks.json"
            key_requests.append(request)
            return json_response({"keys": [public_jwk]})

        assert request.method == "POST"
        assert str(request.url) == ISSUER + "/token?grant_type=password"
        assert events == ["limit-begin", "limit-commit"]
        with integration_engine.connect() as observer:
            assert len(observer.execute(rate_statement).one().request_times) == 1
            assert observer.execute(session_statement).one_or_none() is None
        assert request.headers.get("authorization") is None
        assert json.loads(request.content) == {
            "email": EMAIL,
            "password": PASSWORD,
            "gotrue_meta_security": {
                "captcha_token": CAPTCHA_TOKEN,
            },
        }

        sign_in_requests.append(request)
        events.append("provider")

        return json_response(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
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
            events.append("begin" if "provider" in events else "limit-begin")
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
        def inspect_before_commit(connection: Connection) -> None:
            if "provider" not in events:
                assert len(connection.execute(rate_statement).one().request_times) == 1
                events.append("limit-commit")
                return
            events.append("commit")

            # Both writes must have occurred before inducing the failure.
            assert connection.execute(session_statement).one().user_id == user_id
            assert connection.scalar(profile_statement) == user_id

            if fail_commit:
                connection.exec_driver_sql("SELECT 1 / 0")
                raise AssertionError("Expected PostgreSQL division by zero")

        return engine

    monkeypatch.setattr("app.main.create_database_engine", make_engine)
    monkeypatch.setattr(
        "app.main.httpx2",
        SimpleNamespace(
            AsyncClient=Mock(side_effect=make_http_client),
            Limits=httpx2.Limits,
        ),
    )

    try:
        with TestClient(
            create_app(settings),
            base_url="https://api.example.test",
            client=("192.0.2.12", 12345),
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            response = client.post(
                "/api/v1/account/sign-in",
                json={
                    "email": EMAIL,
                    "password": PASSWORD,
                    "captcha_token": CAPTCHA_TOKEN,
                },
                headers={
                    "Origin": ORIGIN,
                    "Cookie": f"{COOKIE_NAME}={OLD_BROWSER_TOKEN}",
                },
            )

            assert response.headers["Cache-Control"] == "no-store"
            assert events == [
                "limit-begin",
                "limit-commit",
                "provider",
                "verify",
                "begin",
                "commit",
            ]
            assert len(sign_in_requests) == 1
            assert len(key_requests) == 1

            with integration_engine.connect() as observer:
                stored = observer.execute(session_statement).one_or_none()
                profile = observer.scalar(profile_statement)
                assert len(observer.execute(rate_statement).one().request_times) == 1

            for secret in (
                EMAIL,
                PASSWORD,
                access_token,
                refresh_token,
                OLD_BROWSER_TOKEN,
            ):
                assert secret not in response.text

            if fail_commit:
                assert response.status_code == 503
                assert response.json() == {"detail": "Account sign-in is temporarily unavailable."}
                assert "set-cookie" not in response.headers
                assert stored is None
                assert profile is None
                return

            assert response.status_code == 200
            assert stored is not None
            assert profile == user_id

            body = response.json()
            assert set(body) == {
                "user_id",
                "expires_at",
                "absolute_expires_at",
            }
            assert body["user_id"] == str(user_id)
            assert datetime.fromisoformat(body["expires_at"]) == stored.idle_expires_at
            assert datetime.fromisoformat(body["absolute_expires_at"]) == (
                stored.absolute_expires_at
            )

            cookies: SimpleCookie = SimpleCookie()
            cookies.load(response.headers["set-cookie"])
            cookie = cookies[COOKIE_NAME]

            browser_token = cookie.value
            assert len(browser_token) == 43
            assert browser_token != OLD_BROWSER_TOKEN
            assert browser_token not in response.text
            assert stored.token_hash == sha256(browser_token.encode("ascii")).digest()

            assert bool(cookie["secure"])
            assert bool(cookie["httponly"])
            assert cookie["samesite"] == "lax"
            assert cookie["path"] == "/"
            assert cookie["domain"] == ""
            assert parsedate_to_datetime(cookie["expires"]) == (
                stored.idle_expires_at.replace(microsecond=0)
            )

            assert stored.user_id == user_id
            assert stored.provider_session_id == provider_session_id
            assert cipher.decrypt(stored.access_token_ciphertext) == SecretStr(access_token)
            assert cipher.decrypt(stored.refresh_token_ciphertext) == SecretStr(refresh_token)
            assert stored.access_token_expires_at == datetime.fromtimestamp(expiry, tz=UTC)
            assert stored.created_at == stored.last_seen_at
            assert stored.idle_expires_at == stored.created_at + timedelta(days=7)
            assert stored.absolute_expires_at == stored.created_at + timedelta(days=30)
    finally:
        with integration_engine.begin() as connection:
            connection.execute(
                delete(AccountSession).where(
                    AccountSession.provider_session_id == provider_session_id
                )
            )
            connection.execute(delete(UserProfile).where(UserProfile.id == user_id))
            connection.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.purpose == "sign_in", AuthRateLimit.key_hash == rate_key
                )
            )
