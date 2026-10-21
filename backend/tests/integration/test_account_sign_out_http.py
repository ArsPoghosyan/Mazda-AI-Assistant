"""HTTP sign-out commit, rollback, and isolation on local PostgreSQL."""

import asyncio
from datetime import timedelta
from hashlib import sha256
from http.cookies import SimpleCookie
from secrets import token_urlsafe
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx2
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
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

ORIGIN = "https://app.example.test"
COOKIE_NAME = "__Host-askm6_account"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@pytest.mark.parametrize(
    "fail_commit",
    [False, True],
    ids=["committed", "rolled-back"],
)
def test_http_sign_out_obeys_commit_boundary_and_preserves_other_sessions(
    integration_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    fail_commit: bool,
) -> None:
    owner_ids = [uuid4(), uuid4()]
    session_ids = [uuid4(), uuid4(), uuid4()]
    tokens = [token_urlsafe(32) for _ in session_ids]
    target_id = session_ids[0]
    target_token = tokens[0]

    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": "https://auth.example.test/auth/v1",
            "supabase_auth_publishable_key": None,
            "account_session_encryption_key": None,
            "account_cookie_secure": True,
            "account_session_api_enabled": True,
            "account_sign_out_api_enabled": True,
            "account_sign_out_timeout_seconds": 15,
            "csrf_trusted_origins": (ORIGIN,),
        }
    )

    session_statement = select(AccountSession).where(AccountSession.id.in_(session_ids))
    target_statement = select(AccountSession.id).where(AccountSession.id == target_id)
    profile_statement = select(UserProfile.id).where(UserProfile.id.in_(owner_ids))

    provider_calls: list[httpx2.Request] = []
    commit_attempts = 0

    def reject_provider(request: httpx2.Request) -> httpx2.Response:
        provider_calls.append(request)
        raise AssertionError("Sign-out must not contact the provider.")

    def make_http_client(**options: object) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.MockTransport(reject_provider),
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
        def inspect_first_commit(connection: Connection) -> None:
            nonlocal commit_attempts
            commit_attempts += 1

            # Later transactions belong to replay/idempotence checks.
            if commit_attempts != 1:
                return

            # Prove deletion happened before inducing the failure.
            assert connection.scalar(target_statement) is None

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
        with integration_engine.begin() as connection:
            connection.execute(
                insert(UserProfile).values([{"id": owner_id} for owner_id in owner_ids])
            )

            for index, session_id in enumerate(session_ids):
                owner_id = owner_ids[0] if index < 2 else owner_ids[1]
                now = func.statement_timestamp()

                connection.execute(
                    insert(AccountSession).values(
                        id=session_id,
                        user_id=owner_id,
                        provider_session_id=uuid4(),
                        token_hash=sha256(tokens[index].encode("ascii")).digest(),
                        access_token_ciphertext=cipher.encrypt(SecretStr("synthetic-access")),
                        refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-refresh")),
                        access_token_expires_at=now - timedelta(minutes=1),
                        created_at=now - timedelta(days=10),
                        last_seen_at=now - timedelta(days=1),
                        idle_expires_at=now + timedelta(days=6),
                        absolute_expires_at=now + timedelta(days=20),
                    )
                )

            before = {row.id: tuple(row) for row in connection.execute(session_statement)}

        with TestClient(
            create_app(settings),
            base_url="https://api.example.test",
            backend_options={"loop_factory": asyncio.SelectorEventLoop},
        ) as client:
            headers = {
                "Origin": ORIGIN,
                "Cookie": f"{COOKIE_NAME}={target_token}",
            }
            response = client.post(
                "/api/v1/account/sign-out",
                headers=headers,
            )

            assert commit_attempts == 1
            assert response.headers["Cache-Control"] == "no-store"
            assert target_token not in response.text
            assert provider_calls == []

            with integration_engine.connect() as observer:
                after = {row.id: tuple(row) for row in observer.execute(session_statement)}
                remaining_profiles = set(observer.scalars(profile_statement))

            assert remaining_profiles == set(owner_ids)

            if fail_commit:
                assert response.status_code == 503
                assert response.json() == {"detail": "Account sign-out is temporarily unavailable."}
                assert "set-cookie" not in response.headers
                assert after == before
                return

            assert response.status_code == 204
            assert response.content == b""

            expected = dict(before)
            del expected[target_id]
            assert after == expected

            cookies: SimpleCookie = SimpleCookie()
            cookies.load(response.headers["set-cookie"])
            assert set(cookies) == {COOKIE_NAME}

            cookie = cookies[COOKIE_NAME]
            assert cookie.value == ""
            assert cookie["max-age"] == "0"
            assert cookie["path"] == "/"
            assert cookie["domain"] == ""
            assert bool(cookie["secure"])
            assert bool(cookie["httponly"])
            assert cookie["samesite"] == "lax"

            # Explicitly replay the old credential despite cookie deletion.
            replay = client.post(
                "/api/v1/account/session",
                headers=headers,
            )
            assert replay.status_code == 401
            assert replay.json() == {"detail": "Invalid or expired account session."}
            assert replay.headers["Cache-Control"] == "no-store"

            repeated = client.post(
                "/api/v1/account/sign-out",
                headers=headers,
            )
            assert repeated.status_code == 204
            assert repeated.content == b""
            assert repeated.headers["Cache-Control"] == "no-store"
            assert commit_attempts == 3
            assert provider_calls == []

            with integration_engine.connect() as observer:
                final = {row.id: tuple(row) for row in observer.execute(session_statement)}
            assert final == expected
    finally:
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.id.in_(session_ids)))
            connection.execute(delete(UserProfile).where(UserProfile.id.in_(owner_ids)))
