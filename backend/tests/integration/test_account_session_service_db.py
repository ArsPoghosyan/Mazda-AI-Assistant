"""Complete account-session coordination on guarded local PostgreSQL."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx2
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from app.account_key_cache import AccountKeyCache
from app.account_refresh import (
    AccountRefreshRejected,
    AccountRefreshUnavailable,
    RefreshedAccountTokens,
)
from app.account_session_auth import AuthenticatedAccountSession
from app.account_session_service import authenticate_account_session
from app.account_token_encryption import AccountTokenCipher
from app.config import Settings
from app.models import AccountSession, UserProfile

pytestmark = pytest.mark.integration

type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]

ISSUER = "https://auth.example.test/auth/v1"
OLD_REFRESH = "synthetic-old-refresh"


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


@dataclass(frozen=True)
class ServiceMaterial:
    settings: Settings
    user_id: UUID
    provider_session_id: UUID
    current_access: SecretStr
    current_expiry: datetime
    expired_access: SecretStr
    expired_expiry: datetime
    replacement: RefreshedAccountTokens
    cipher: AccountTokenCipher
    cache: AccountKeyCache
    download: AsyncMock


@pytest.fixture
def material() -> ServiceMaterial:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    encryption_key = SecretStr(Fernet.generate_key().decode("ascii"))
    user_id = uuid4()
    provider_session_id = uuid4()
    now = int(datetime.now(UTC).timestamp())

    def make_access(expiry: int) -> SecretStr:
        return SecretStr(
            jwt.encode(
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
                headers={"kid": "coordinator-db-test-key"},
            )
        )

    public_jwk = ECAlgorithm.to_jwk(
        signing_key.public_key(),
        as_dict=True,
    )
    public_jwk.update(
        {
            "kid": "coordinator-db-test-key",
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )
    download = AsyncMock(return_value={"keys": [public_jwk]})

    settings = IsolatedSettings.model_validate(
        {
            "database_url": None,
            "migration_database_url": None,
            "supabase_auth_issuer": ISSUER,
            "supabase_auth_audience": "authenticated",
            "supabase_auth_publishable_key": ("sb_publishable_synthetic_test_key"),
            "account_session_encryption_key": encryption_key,
            "account_session_inactivity_days": 7,
            "account_session_absolute_lifetime_days": 30,
        }
    )

    return ServiceMaterial(
        settings=settings,
        user_id=user_id,
        provider_session_id=provider_session_id,
        current_access=make_access(now + 300),
        current_expiry=datetime.fromtimestamp(now + 300, tz=UTC),
        expired_access=make_access(now - 60),
        expired_expiry=datetime.fromtimestamp(now - 60, tz=UTC),
        replacement=RefreshedAccountTokens(
            access_token=make_access(now + 600),
            refresh_token=SecretStr("synthetic-replacement-refresh"),
        ),
        cipher=AccountTokenCipher(encryption_key),
        cache=AccountKeyCache(download),
        download=download,
    )


async def seed_session(
    connection: AsyncConnection,
    material: ServiceMaterial,
    *,
    access_expired: bool = False,
    **overrides: object,
) -> tuple[UUID, SecretStr]:
    session_id = uuid4()
    token = SecretStr(token_urlsafe(32))
    now = func.statement_timestamp()

    access = material.expired_access if access_expired else material.current_access
    expiry = material.expired_expiry if access_expired else material.current_expiry

    values: dict[str, object] = {
        "id": session_id,
        "user_id": material.user_id,
        "provider_session_id": material.provider_session_id,
        "token_hash": sha256(token.get_secret_value().encode("ascii")).digest(),
        "access_token_ciphertext": material.cipher.encrypt(access),
        "refresh_token_ciphertext": material.cipher.encrypt(SecretStr(OLD_REFRESH)),
        "access_token_expires_at": expiry,
        "created_at": now - timedelta(days=10),
        "last_seen_at": now - timedelta(days=1),
        "idle_expires_at": now + timedelta(days=6),
        "absolute_expires_at": now + timedelta(days=20),
    }
    values.update(overrides)

    await connection.execute(insert(UserProfile).values(id=values["user_id"]))
    await connection.execute(insert(AccountSession).values(**values))
    return session_id, token


class ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body


def json_response(
    status: int,
    payload: dict[str, object],
) -> httpx2.Response:
    return httpx2.Response(
        status,
        headers={"Content-Type": "application/json"},
        stream=ResponseStream(json.dumps(payload).encode("utf-8")),
    )


def replacement_response(material: ServiceMaterial) -> httpx2.Response:
    return json_response(
        200,
        {
            "access_token": (material.replacement.access_token.get_secret_value()),
            "refresh_token": (material.replacement.refresh_token.get_secret_value()),
            "token_type": "bearer",
        },
    )


@pytest.mark.parametrize("access_expired", [False, True])
def test_coordinator_authenticates_and_preserves_other_session_data(
    async_app_connection_factory: ConnectionFactory,
    material: ServiceMaterial,
    access_expired: bool,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(
                connection,
                material,
                access_expired=access_expired,
            )
            other_id, _ = await seed_session(
                connection,
                material,
                user_id=uuid4(),
                provider_session_id=uuid4(),
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            other_statement = select(AccountSession).where(AccountSession.id == other_id)
            before = (await connection.execute(statement)).one()
            other_before = (await connection.execute(other_statement)).one()
            requests: list[httpx2.Request] = []

            def handler(request: httpx2.Request) -> httpx2.Response:
                requests.append(request)
                return replacement_response(material)

            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(handler),
                trust_env=False,
            ) as client:
                authenticated = await authenticate_account_session(
                    connection,
                    token,
                    settings=material.settings,
                    client=client,
                    key_cache=material.cache,
                )

            assert authenticated is not None
            assert authenticated.session_id == session_id
            assert authenticated.account.user_id == material.user_id
            assert authenticated.account.session_id == material.provider_session_id

            after = (await connection.execute(statement)).one()
            assert after.access_token_expires_at == authenticated.account.access_token_expires_at
            assert authenticated.idle_expires_at == after.idle_expires_at
            assert authenticated.absolute_expires_at == before.absolute_expires_at

            expected_access = (
                material.replacement.access_token if access_expired else material.current_access
            )
            expected_refresh = (
                material.replacement.refresh_token if access_expired else SecretStr(OLD_REFRESH)
            )
            assert material.cipher.decrypt(after.access_token_ciphertext) == expected_access
            assert material.cipher.decrypt(after.refresh_token_ciphertext) == expected_refresh

            assert len(requests) == int(access_expired)
            if access_expired:
                assert json.loads(requests[0].content) == {"refresh_token": OLD_REFRESH}

            assert after.last_seen_at > before.last_seen_at
            assert after.idle_expires_at == min(
                after.last_seen_at + timedelta(days=7),
                before.absolute_expires_at,
            )

            changed_columns = {"last_seen_at", "idle_expires_at"}
            if access_expired:
                changed_columns.update(
                    {
                        "access_token_ciphertext",
                        "refresh_token_ciphertext",
                        "access_token_expires_at",
                    }
                )

            for column in AccountSession.__table__.columns:
                if column.name not in changed_columns:
                    assert getattr(after, column.name) == getattr(before, column.name)

            assert (await connection.execute(other_statement)).one() == other_before
            assert connection.in_transaction()
            material.download.assert_awaited_once()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize(
    ("status", "expected_error"),
    [
        (400, AccountRefreshRejected),
        (503, AccountRefreshUnavailable),
    ],
)
def test_provider_failure_leaves_session_unchanged(
    async_app_connection_factory: ConnectionFactory,
    material: ServiceMaterial,
    status: int,
    expected_error: type[Exception],
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(
                connection,
                material,
                access_expired=True,
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()
            requests: list[httpx2.Request] = []

            def handler(request: httpx2.Request) -> httpx2.Response:
                requests.append(request)
                return json_response(
                    status,
                    {"error_code": "refresh_token_not_found"},
                )

            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(handler),
                trust_env=False,
            ) as client:
                with pytest.raises(expected_error):
                    await authenticate_account_session(
                        connection,
                        token,
                        settings=material.settings,
                        client=client,
                        key_cache=material.cache,
                    )

            assert len(requests) == 1
            assert (await connection.execute(statement)).one() == before
            assert connection.in_transaction()
            material.download.assert_not_awaited()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_coordinator_refresh_rolls_back_with_callers_savepoint(
    async_app_connection_factory: ConnectionFactory,
    material: ServiceMaterial,
) -> None:
    async def check() -> None:
        async with async_app_connection_factory() as connection:
            session_id, token = await seed_session(
                connection,
                material,
                access_expired=True,
            )
            statement = select(AccountSession).where(AccountSession.id == session_id)
            before = (await connection.execute(statement)).one()
            requests: list[httpx2.Request] = []

            def handler(request: httpx2.Request) -> httpx2.Response:
                requests.append(request)
                return replacement_response(material)

            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(handler),
                trust_env=False,
            ) as client:
                savepoint = await connection.begin_nested()
                try:
                    authenticated = await authenticate_account_session(
                        connection,
                        token,
                        settings=material.settings,
                        client=client,
                        key_cache=material.cache,
                    )
                    assert authenticated is not None

                    during = (await connection.execute(statement)).one()
                    assert during.access_token_ciphertext != before.access_token_ciphertext
                    assert during.refresh_token_ciphertext != before.refresh_token_ciphertext
                    assert during.last_seen_at > before.last_seen_at
                finally:
                    await savepoint.rollback()

            assert len(requests) == 1
            assert (await connection.execute(statement)).one() == before

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize(
    ("commit_first", "reject_recovery"),
    [
        (True, False),
        (False, False),
        (False, True),
    ],
    ids=["commit", "rollback-recovery", "rollback-recovery-rejected"],
)
def test_concurrent_requests_respect_first_refresh_transaction(
    integration_engine: Engine,
    async_app_connection_factory: ConnectionFactory,
    material: ServiceMaterial,
    commit_first: bool,
    reject_recovery: bool,
) -> None:
    session_id = uuid4()
    token = SecretStr(token_urlsafe(32))

    # Commit only this synthetic session so both requests can see it.
    with integration_engine.begin() as connection:
        connection.execute(insert(UserProfile).values(id=material.user_id))
        original = (
            connection.execute(
                insert(AccountSession)
                .values(
                    id=session_id,
                    user_id=material.user_id,
                    provider_session_id=material.provider_session_id,
                    token_hash=sha256(token.get_secret_value().encode("ascii")).digest(),
                    access_token_ciphertext=material.cipher.encrypt(material.expired_access),
                    refresh_token_ciphertext=material.cipher.encrypt(SecretStr(OLD_REFRESH)),
                    access_token_expires_at=material.expired_expiry,
                    created_at=(func.statement_timestamp() - timedelta(days=10)),
                    last_seen_at=(func.statement_timestamp() - timedelta(days=1)),
                    idle_expires_at=(func.statement_timestamp() + timedelta(days=6)),
                    absolute_expires_at=(func.statement_timestamp() + timedelta(days=20)),
                )
                .returning(*AccountSession.__table__.c)
            )
        ).one()

    async def check() -> None:
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

        try:
            async with asyncio.timeout(10):
                refresh_entered = asyncio.Event()
                release_refresh = asyncio.Event()
                requests: list[httpx2.Request] = []
                first_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()
                second_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()
                statement = select(AccountSession).where(AccountSession.id == session_id)

                async def handler(
                    request: httpx2.Request,
                ) -> httpx2.Response:
                    requests.append(request)
                    assert json.loads(request.content) == {"refresh_token": OLD_REFRESH}
                    if len(requests) == 1:
                        refresh_entered.set()
                        await release_refresh.wait()
                    else:
                        assert not commit_first
                        assert len(requests) == 2

                        if reject_recovery:
                            return json_response(
                                400,
                                {"error_code": "refresh_token_already_used"},
                            )

                        # Model recovery accepting the old parent token
                        # and returning the already active replacement pair.
                    return replacement_response(material)

                async with httpx2.AsyncClient(
                    transport=httpx2.MockTransport(handler),
                    trust_env=False,
                ) as client:

                    async def attempt(
                        ready: asyncio.Future[int],
                        *,
                        commit: bool = True,
                    ) -> tuple[
                        AuthenticatedAccountSession | None,
                        dict[str, object],
                    ]:
                        async with engine.connect() as connection:
                            transaction = await connection.begin()
                            try:
                                await connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
                                await connection.execute(text("SET LOCAL ROLE askm6_app"))
                                assert (
                                    await connection.scalar(text("SELECT current_user"))
                                    == "askm6_app"
                                )

                                pid = await connection.scalar(text("SELECT pg_backend_pid()"))
                                assert isinstance(pid, int)
                                ready.set_result(pid)

                                authenticated = await authenticate_account_session(
                                    connection,
                                    token,
                                    settings=material.settings,
                                    client=client,
                                    key_cache=material.cache,
                                )
                                assert authenticated is not None

                                snapshot = dict(
                                    (await connection.execute(statement)).one()._mapping
                                )

                                if commit:
                                    await transaction.commit()
                                else:
                                    await transaction.rollback()
                            finally:
                                if transaction.is_active:
                                    await transaction.rollback()

                        # A rolled-back caller discards the identity.
                        return authenticated if commit else None, snapshot

                    async def second_attempt() -> tuple[
                        AuthenticatedAccountSession | None,
                        dict[str, object],
                    ]:
                        if not reject_recovery:
                            return await attempt(second_ready)

                        with pytest.raises(
                            AccountRefreshRejected,
                            match="Account credentials were rejected",
                        ):
                            await attempt(second_ready)

                        return None, {}

                    async with async_app_connection_factory() as observer:
                        async with asyncio.TaskGroup() as group:
                            first_task = group.create_task(
                                attempt(first_ready, commit=commit_first)
                            )
                            await refresh_entered.wait()
                            first_pid = await first_ready

                            second_task = group.create_task(second_attempt())
                            second_pid = await second_ready

                            while True:
                                blocked = await observer.scalar(
                                    text("SELECT :first = ANY(pg_blocking_pids(:second))"),
                                    {
                                        "first": first_pid,
                                        "second": second_pid,
                                    },
                                )
                                if blocked:
                                    break
                                await asyncio.sleep(0.01)

                            assert not second_task.done()
                            assert len(requests) == 1

                            release_refresh.set()
                            first_result, first_snapshot = await first_task
                            second_result, second_snapshot = await second_task

                        if reject_recovery:
                            assert len(requests) == 2
                            assert first_result is None
                            assert second_result is None

                            stored = (await observer.execute(statement)).one()
                            assert dict(stored._mapping) == dict(original._mapping)

                            material.download.assert_awaited_once()
                            return

                        assert second_result is not None
                        assert second_result.session_id == session_id
                        assert second_result.account.user_id == material.user_id
                        assert second_result.account.session_id == material.provider_session_id

                        if commit_first:
                            assert len(requests) == 1
                            assert first_result is not None
                            assert first_result.session_id == session_id
                            assert first_result.account == second_result.account

                            # The waiter preserves the committed credentials.
                            for column in AccountSession.__table__.columns:
                                if column.name not in {
                                    "last_seen_at",
                                    "idle_expires_at",
                                }:
                                    assert (
                                        second_snapshot[column.name] == first_snapshot[column.name]
                                    )
                        else:
                            assert len(requests) == 2
                            assert first_result is None

                        stored = (await observer.execute(statement)).one()
                        assert dict(stored._mapping) == second_snapshot

                        assert (
                            material.cipher.decrypt(stored.access_token_ciphertext)
                            == material.replacement.access_token
                        )
                        assert (
                            material.cipher.decrypt(stored.refresh_token_ciphertext)
                            == material.replacement.refresh_token
                        )

                        assert stored.id == session_id
                        assert stored.user_id == material.user_id
                        assert stored.provider_session_id == material.provider_session_id
                        assert stored.token_hash == original.token_hash
                        assert stored.created_at == original.created_at
                        assert stored.absolute_expires_at == original.absolute_expires_at
                        assert stored.last_seen_at > original.last_seen_at
                        assert stored.idle_expires_at == min(
                            stored.last_seen_at + timedelta(days=7),
                            original.absolute_expires_at,
                        )
                        material.download.assert_awaited_once()
        finally:
            await engine.dispose()

    try:
        asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    finally:
        # Remove only the synthetic rows created by this test.
        with integration_engine.begin() as connection:
            connection.execute(delete(AccountSession).where(AccountSession.id == session_id))
            connection.execute(delete(UserProfile).where(UserProfile.id == material.user_id))
