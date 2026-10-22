"""Sign-in orchestration against guarded local PostgreSQL."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import fetch_account_key_set
from app.account_sessions import CreatedAccountSession
from app.account_sign_in_service import sign_in_account
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

ISSUER = "https://auth.example.test/auth/v1"
EMAIL = SecretStr("owner@example.test")
PASSWORD = SecretStr("  synthetic-password-é  ")


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
def test_sign_in_obeys_database_commit_boundary(
    integration_engine: Engine,
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
        headers={"kid": "sign-in-integration-key"},
    )
    refresh_token = "synthetic-sign-in-refresh"

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": "sign-in-integration-key",
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
        }
    )

    events: list[str] = []
    key_requests: list[httpx2.Request] = []

    session_statement = select(AccountSession).where(
        AccountSession.provider_session_id == provider_session_id
    )
    profile_statement = select(UserProfile.id).where(UserProfile.id == user_id)

    def provider(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET" and str(request.url) == ISSUER + "/user":
            assert events == ["provider"]
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
        assert events == []
        assert json.loads(request.content) == {
            "email": EMAIL.get_secret_value(),
            "password": PASSWORD.get_secret_value(),
        }
        events.append("provider")

        return json_response(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            }
        )

    async def run() -> CreatedAccountSession | None:
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
            events.append("begin")
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
            events.append("commit")
            assert connection.execute(session_statement).one().user_id == user_id
            assert connection.scalar(profile_statement) == user_id

            if fail_commit:
                connection.exec_driver_sql("SELECT 1 / 0")
                raise AssertionError("Expected PostgreSQL division by zero")

        try:
            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(provider),
                follow_redirects=False,
                trust_env=False,
            ) as client:

                async def download_keys() -> dict[str, object]:
                    return await fetch_account_key_set(settings, client=client)

                key_cache = AccountKeyCache(download_keys)

                if fail_commit:
                    with pytest.raises(SQLAlchemyError):
                        await sign_in_account(
                            engine,
                            EMAIL,
                            PASSWORD,
                            settings=settings,
                            client=client,
                            key_cache=key_cache,
                        )
                    return None

                created = await sign_in_account(
                    engine,
                    EMAIL,
                    PASSWORD,
                    settings=settings,
                    client=client,
                    key_cache=key_cache,
                )
                events.append("returned")
                return created
        finally:
            await engine.dispose()

    try:
        created = asyncio.run(run(), loop_factory=asyncio.SelectorEventLoop)

        assert len(key_requests) == 1

        with integration_engine.connect() as observer:
            stored = observer.execute(session_statement).one_or_none()
            profile = observer.scalar(profile_statement)

        if fail_commit:
            assert events == ["provider", "verify", "begin", "commit"]
            assert created is None
            assert stored is None
            assert profile is None
            return

        assert events == ["provider", "verify", "begin", "commit", "returned"]
        assert created is not None
        assert stored is not None
        assert profile == user_id

        assert created.session_id == stored.id
        assert created.user_id == stored.user_id == user_id
        assert stored.provider_session_id == provider_session_id

        browser_token = created.token.get_secret_value()
        assert len(browser_token) == 43
        assert stored.token_hash == sha256(browser_token.encode("ascii")).digest()
        assert browser_token not in repr(created)

        assert cipher.decrypt(stored.access_token_ciphertext) == SecretStr(access_token)
        assert cipher.decrypt(stored.refresh_token_ciphertext) == SecretStr(refresh_token)
        assert stored.access_token_ciphertext != access_token.encode("ascii")
        assert stored.refresh_token_ciphertext != refresh_token.encode("ascii")
        assert stored.access_token_expires_at == datetime.fromtimestamp(expiry, tz=UTC)

        assert stored.created_at == stored.last_seen_at
        assert created.idle_expires_at == stored.idle_expires_at
        assert created.absolute_expires_at == stored.absolute_expires_at
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
