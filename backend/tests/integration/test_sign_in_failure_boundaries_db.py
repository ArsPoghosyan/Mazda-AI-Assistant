"""Uncertain commits, retries and subject isolation with real session persistence."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app import account_sign_in_service as password_service
from app.account_google_exchange import ExchangedGoogleTokens
from app.account_google_session import create_google_account_session
from app.account_key_cache import AccountKeyCache
from app.account_sessions import AccountSessionAlreadyExists, CreatedAccountSession
from app.account_sign_in import SignedInAccountTokens
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration
ISSUER = "https://auth.example.test/auth/v1"
SHARED_EMAIL = "shared@example.test"


class UserStream(httpx2.AsyncByteStream):
    def __init__(self, subject: UUID) -> None:
        self.body = json.dumps(
            {"id": str(subject), "is_anonymous": False, "email": SHARED_EMAIL}
        ).encode()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


@dataclass
class Case:
    engine: AsyncEngine
    settings: Settings
    key_cache: AccountKeyCache
    signing_key: ec.EllipticCurvePrivateKey = field(repr=False)
    users: set[UUID] = field(default_factory=set)


type CaseFactory = Callable[[], AbstractAsyncContextManager[Case]]


@pytest.fixture
def case_factory(integration_engine: Engine) -> CaseFactory:
    @asynccontextmanager
    async def connect() -> AsyncIterator[Case]:
        engine = create_async_engine(
            integration_engine.url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={
                "connect_timeout": 5,
                "hostaddr": "127.0.0.1",
                "options": "-c role=askm6_app -c timezone=UTC -c statement_timeout=5000",
            },
        )

        @event.listens_for(engine.sync_engine, "begin")
        def restricted(connection: Connection) -> None:
            assert tuple(
                connection.execute(text("SELECT current_database(), current_user")).one()
            ) == ("askm6_test", "askm6_app")
            assert (
                connection.scalar(
                    text(
                        "SELECT NOT rolsuper AND NOT rolbypassrls "
                        "FROM pg_roles WHERE rolname=current_user"
                    )
                )
                is True
            )

        signing_key = ec.generate_private_key(ec.SECP256R1())
        jwk: dict[str, object] = json.loads(ECAlgorithm.to_jwk(signing_key.public_key()))
        jwk.update({"kid": "failure-boundary-key", "use": "sig", "alg": "ES256"})

        async def keys() -> dict[str, object]:
            return {"keys": [jwk]}

        settings = Settings.model_construct(
            database_url=None,
            migration_database_url=None,
            supabase_auth_issuer=ISSUER,
            supabase_auth_publishable_key=SecretStr("sb_publishable_synthetic_test_key"),
            account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii")),
        )
        case = Case(engine, settings, AccountKeyCache(keys), signing_key)
        try:
            yield case
        finally:
            try:
                if case.users:
                    async with engine.begin() as connection:
                        await connection.execute(
                            delete(AccountSession).where(AccountSession.user_id.in_(case.users))
                        )
                        await connection.execute(
                            delete(UserProfile).where(UserProfile.id.in_(case.users))
                        )
            finally:
                await engine.dispose()

    return connect


async def sign_in(
    case: Case,
    subject: UUID,
    provider_session: UUID,
    *,
    google: bool,
    monkeypatch: pytest.MonkeyPatch,
    engine: AsyncEngine | None = None,
) -> CreatedAccountSession:
    case.users.add(subject)
    metadata_subject = uuid4()
    # Track even the misleading metadata ID so a failing isolation regression
    # cannot leave one of its own synthetic profiles behind during teardown.
    case.users.add(metadata_subject)
    now = int(datetime.now(UTC).timestamp())
    access = SecretStr(
        jwt.encode(
            {
                "iss": ISSUER,
                "aud": "authenticated",
                "iat": now - 1,
                "exp": now + 300,
                "sub": str(subject),
                "session_id": str(provider_session),
                "role": "authenticated",
                "is_anonymous": False,
                "aal": "aal1",
                "email": SHARED_EMAIL,
                "user_metadata": {"user_id": str(metadata_subject)},
            },
            case.signing_key,
            algorithm="ES256",
            headers={"kid": "failure-boundary-key"},
        )
    )
    refresh = SecretStr("synthetic-refresh-" + str(provider_session))
    requests = 0

    def provider(request: httpx2.Request) -> httpx2.Response:
        nonlocal requests
        requests += 1
        assert request.method == "GET" and str(request.url) == ISSUER + "/user"
        assert request.headers["authorization"] == f"Bearer {access.get_secret_value()}"
        assert "cookie" not in request.headers
        return httpx2.Response(
            200, headers={"Content-Type": "application/json"}, stream=UserStream(subject)
        )

    try:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(provider), trust_env=False
        ) as client:
            target = case.engine if engine is None else engine
            if google:
                return await create_google_account_session(
                    target,
                    ExchangedGoogleTokens(access, refresh),
                    settings=case.settings,
                    client=client,
                    key_cache=case.key_cache,
                )
            provider_login = AsyncMock(return_value=SignedInAccountTokens(access, refresh))
            monkeypatch.setattr(password_service, "sign_in_with_password", provider_login)
            return await password_service.sign_in_account(
                target,
                SecretStr(SHARED_EMAIL),
                SecretStr("synthetic-password"),
                settings=case.settings,
                client=client,
                key_cache=case.key_cache,
            )
    finally:
        assert requests == 1  # No retry, logout or other provider side effect.


@pytest.mark.parametrize("google", [False, True], ids=["password", "google"])
@pytest.mark.parametrize("outcome", ["lost-ack", "cancel-after-commit"])
def test_uncertain_commit_returns_no_credential_and_retry_preserves_existing_session(
    case_factory: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
    google: bool,
    outcome: str,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            user, provider_session = uuid4(), uuid4()
            committed = False
            failure = (
                SQLAlchemyError("private-lost-ack")
                if outcome == "lost-ack"
                else asyncio.CancelledError("private-disconnect")
            )

            @asynccontextmanager
            async def uncertain() -> AsyncIterator[AsyncConnection]:
                nonlocal committed
                async with case.engine.begin() as connection:
                    yield connection
                committed = True
                # Model a missing acknowledgement AFTER actual commit/release.
                raise failure

            class UncertainEngine:
                def begin(self) -> AbstractAsyncContextManager[AsyncConnection]:
                    return uncertain()

            with pytest.raises(type(failure)) as caught:
                await sign_in(
                    case,
                    user,
                    provider_session,
                    google=google,
                    monkeypatch=monkeypatch,
                    engine=cast(AsyncEngine, UncertainEngine()),
                )
            assert caught.value is failure and committed
            statement = select(AccountSession).where(
                AccountSession.provider_session_id == provider_session
            )
            async with case.engine.connect() as observer:
                stored = (await observer.execute(statement)).one()
                assert stored.user_id == user
                before = tuple(stored)

            # Reusing that provider session cannot replace a committed browser
            # credential, and must not revoke the provider session automatically.
            with pytest.raises(AccountSessionAlreadyExists):
                await sign_in(
                    case, user, provider_session, google=not google, monkeypatch=monkeypatch
                )
            async with case.engine.connect() as observer:
                assert tuple((await observer.execute(statement)).one()) == before
            # A fresh provider login can succeed without overwriting the orphan.
            created = await sign_in(case, user, uuid4(), google=google, monkeypatch=monkeypatch)
            assert created.user_id == user and created.session_id != stored.id

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("same_subject", [True, False])
def test_email_and_google_follow_verified_subject_without_application_email_merging(
    case_factory: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
    same_subject: bool,
) -> None:
    async def check() -> None:
        async with case_factory() as case:
            first_subject = uuid4()
            second_subject = first_subject if same_subject else uuid4()
            email = await sign_in(
                case, first_subject, uuid4(), google=False, monkeypatch=monkeypatch
            )
            google = await sign_in(
                case, second_subject, uuid4(), google=True, monkeypatch=monkeypatch
            )
            assert email.user_id == first_subject and google.user_id == second_subject
            assert email.session_id != google.session_id and email.token != google.token
            async with case.engine.connect() as observer:
                profiles = set(
                    (
                        await observer.scalars(
                            select(UserProfile.id).where(UserProfile.id.in_(case.users))
                        )
                    ).all()
                )
                assert profiles == {first_subject, second_subject}
                sessions = (
                    await observer.execute(
                        select(AccountSession.user_id).where(AccountSession.user_id.in_(case.users))
                    )
                ).all()
                assert sorted(str(row.user_id) for row in sessions) == sorted(
                    [str(first_subject), str(second_subject)]
                )

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
