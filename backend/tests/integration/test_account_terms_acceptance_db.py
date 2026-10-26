"""Terms record persistence on guarded local PostgreSQL as the runtime role.

Only random test-owned profiles are committed; deleting those profiles cleans
their acceptance records by foreign key. Provider authentication is tested at
the service/HTTP boundaries separately; storage tests supply synthetic identity.
"""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from secrets import token_urlsafe
from typing import Protocol, cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import httpx2
import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, event, func, insert, select, text, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

import app.account_terms as terms
from app.account_session_auth import AuthenticatedAccountSession
from app.account_terms import current_terms_accepted_at, record_terms_acceptance
from app.account_terms_requests import CURRENT_TERMS_VERSION, TermsAcceptanceRequest
from app.account_tokens import VerifiedAccount
from app.config import Settings
from app.models import AccountSession, AccountTermsAcceptance, UserProfile

pytestmark = pytest.mark.integration
ACCEPTANCE = TermsAcceptanceRequest(accepted=True, terms_version=CURRENT_TERMS_VERSION)


class IsolatedSettings(Settings):
    model_config = SettingsConfigDict(env_file=None)


class TermsMigration(Protocol):
    def downgrade(self) -> None: ...


@dataclass(frozen=True)
class TermsCase:
    engine: Engine
    target: UUID = field(default_factory=uuid4)
    other: UUID = field(default_factory=uuid4)


@pytest.fixture
def case(integration_engine: Engine) -> Iterator[TermsCase]:
    material = TermsCase(integration_engine)
    try:
        with integration_engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE askm6_app"))
            connection.execute(
                insert(UserProfile).values(
                    [
                        {"id": material.target},
                        {"id": material.other},
                    ]
                )
            )
        yield material
    finally:
        with integration_engine.begin() as connection:
            connection.execute(text("SET LOCAL ROLE askm6_app"))
            connection.execute(
                delete(UserProfile).where(
                    UserProfile.id.in_(
                        [
                            material.target,
                            material.other,
                        ]
                    )
                )
            )
        with integration_engine.connect() as connection:
            assert (
                connection.scalar(
                    select(func.count())
                    .select_from(AccountTermsAcceptance)
                    .where(AccountTermsAcceptance.user_id.in_([material.target, material.other]))
                )
                == 0
            )


def session(user_id: UUID) -> AuthenticatedAccountSession:
    now = datetime.now(UTC)
    return AuthenticatedAccountSession(
        session_id=uuid4(),
        account=VerifiedAccount(
            user_id=user_id,
            session_id=uuid4(),
            assurance_level="aal1",
            access_token_expires_at=now + timedelta(minutes=5),
        ),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )


def async_engine(case: TermsCase) -> AsyncEngine:
    return create_async_engine(
        case.engine.url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
        hide_parameters=True,
    )


@asynccontextmanager
async def app_transaction(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as connection:
        await connection.execute(text("SET LOCAL ROLE askm6_app"))
        await connection.execute(text("SET LOCAL statement_timeout = '5s'"))
        await connection.execute(text("SET LOCAL lock_timeout = '3s'"))
        assert await connection.scalar(text("SELECT current_user")) == "askm6_app"
        yield connection


def test_committed_repeat_preserves_first_time_and_other_account_is_separate(
    case: TermsCase,
) -> None:
    async def check() -> None:
        engine = async_engine(case)
        try:
            async with app_transaction(engine) as connection:
                assert await current_terms_accepted_at(connection, case.target) is None
                before = await connection.scalar(select(func.clock_timestamp()))
                first = await record_terms_acceptance(connection, session(case.target), ACCEPTANCE)
                after = await connection.scalar(select(func.clock_timestamp()))
                assert isinstance(before, datetime) and isinstance(after, datetime)
                assert before <= first <= after
                assert first.utcoffset() == timedelta(0)
                assert await current_terms_accepted_at(connection, case.other) is None
            async with app_transaction(engine) as connection:
                repeated = await record_terms_acceptance(
                    connection, session(case.target), ACCEPTANCE
                )
                assert repeated == first
                await record_terms_acceptance(connection, session(case.other), ACCEPTANCE)
                assert await current_terms_accepted_at(connection, case.target) == first
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_prior_revision_does_not_count_as_current_acceptance(case: TermsCase) -> None:
    async def check() -> None:
        engine = async_engine(case)
        try:
            async with app_transaction(engine) as connection:
                old_time = await connection.scalar(
                    insert(AccountTermsAcceptance)
                    .values(
                        user_id=case.target,
                        terms_version="previous-revision",
                    )
                    .returning(AccountTermsAcceptance.accepted_at)
                )
                assert await current_terms_accepted_at(connection, case.target) is None
                await record_terms_acceptance(connection, session(case.target), ACCEPTANCE)
                assert (
                    await connection.scalar(
                        select(AccountTermsAcceptance.accepted_at).where(
                            AccountTermsAcceptance.user_id == case.target,
                            AccountTermsAcceptance.terms_version == "previous-revision",
                        )
                    )
                    == old_time
                )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_rollback_leaves_no_acceptance(case: TermsCase) -> None:
    async def check() -> None:
        engine = async_engine(case)
        try:
            with pytest.raises(RuntimeError, match="synthetic rollback"):
                async with app_transaction(engine) as connection:
                    await record_terms_acceptance(connection, session(case.target), ACCEPTANCE)
                    raise RuntimeError("synthetic rollback")
            async with app_transaction(engine) as connection:
                assert await current_terms_accepted_at(connection, case.target) is None
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_concurrent_duplicate_submissions_share_one_original_record(case: TermsCase) -> None:
    async def check() -> None:
        engine = async_engine(case)
        ready = asyncio.Event()
        arrived = 0

        async def accept() -> datetime:
            nonlocal arrived
            async with app_transaction(engine) as connection:
                arrived += 1
                if arrived == 2:
                    ready.set()
                await ready.wait()
                return await record_terms_acceptance(connection, session(case.target), ACCEPTANCE)

        try:
            first, second = await asyncio.wait_for(asyncio.gather(accept(), accept()), timeout=10)
            assert first == second
            async with app_transaction(engine) as connection:
                assert (
                    await connection.scalar(
                        select(func.count())
                        .select_from(AccountTermsAcceptance)
                        .where(AccountTermsAcceptance.user_id == case.target)
                    )
                    == 1
                )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_profile_deletion_removes_only_its_acceptance(case: TermsCase) -> None:
    with case.engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(
            insert(AccountTermsAcceptance).values(
                [
                    {"user_id": case.target, "terms_version": CURRENT_TERMS_VERSION},
                    {"user_id": case.other, "terms_version": CURRENT_TERMS_VERSION},
                ]
            )
        )
        connection.execute(delete(UserProfile).where(UserProfile.id == case.target))
        assert (
            connection.scalar(
                select(func.count())
                .select_from(AccountTermsAcceptance)
                .where(
                    AccountTermsAcceptance.user_id == case.target,
                )
            )
            == 0
        )
        assert (
            connection.scalar(
                select(func.count())
                .select_from(AccountTermsAcceptance)
                .where(
                    AccountTermsAcceptance.user_id == case.other,
                )
            )
            == 1
        )


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_runtime_role_cannot_modify_or_directly_delete_records(
    case: TermsCase, operation: str
) -> None:
    with case.engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(
            insert(AccountTermsAcceptance).values(
                user_id=case.target,
                terms_version=CURRENT_TERMS_VERSION,
            )
        )
        with pytest.raises(ProgrammingError) as caught:
            with connection.begin_nested():
                if operation == "update":
                    connection.execute(
                        update(AccountTermsAcceptance)
                        .where(
                            AccountTermsAcceptance.user_id == case.target,
                        )
                        .values(accepted_at=func.clock_timestamp())
                    )
                else:
                    connection.execute(
                        delete(AccountTermsAcceptance).where(
                            AccountTermsAcceptance.user_id == case.target,
                        )
                    )
        assert getattr(caught.value.orig, "sqlstate", None) == "42501"


@pytest.mark.parametrize("invalid", ["unknown-owner", "empty-version", "null-time"])
def test_database_rejects_incomplete_or_orphaned_records(case: TermsCase, invalid: str) -> None:
    values: dict[str, object] = {"user_id": case.target, "terms_version": CURRENT_TERMS_VERSION}
    if invalid == "unknown-owner":
        values["user_id"] = uuid4()
    elif invalid == "empty-version":
        values["terms_version"] = ""
    else:
        values["accepted_at"] = None
    with case.engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        with pytest.raises(IntegrityError) as caught:
            with connection.begin_nested():
                connection.execute(insert(AccountTermsAcceptance).values(**values))
        assert getattr(caught.value.orig, "sqlstate", None) in {"23503", "23514", "23502"}


def test_migration_refuses_to_remove_populated_acceptance_records(case: TermsCase) -> None:
    backend = Path(__file__).resolve().parents[2]
    scripts = ScriptDirectory.from_config(Config(str(backend / "alembic.ini")))
    revision = scripts.get_revision("b4d7e2806a12")
    assert revision is not None
    # This probe always rolls back. It never changes the recorded migration head.
    with case.engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET LOCAL ROLE askm6_migrator"))
            connection.execute(text("SET LOCAL statement_timeout = '5s'"))
            connection.execute(
                insert(AccountTermsAcceptance).values(
                    user_id=case.target,
                    terms_version=CURRENT_TERMS_VERSION,
                )
            )
            with pytest.raises(DBAPIError) as caught:
                with connection.begin_nested():
                    with Operations.context(MigrationContext.configure(connection)):
                        cast(TermsMigration, revision.module).downgrade()
            assert getattr(caught.value.orig, "sqlstate", None) == "P0001"
            assert (
                connection.scalar(
                    select(func.count())
                    .select_from(AccountTermsAcceptance)
                    .where(
                        AccountTermsAcceptance.user_id == case.target,
                    )
                )
                == 1
            )
        finally:
            transaction.rollback()


def test_authenticated_status_and_gate_use_only_current_verified_accounts_records(
    case: TermsCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = session(case.target)
    monkeypatch.setattr(terms, "authenticate_account_session", AsyncMock(return_value=verified))
    settings = IsolatedSettings(account_terms_api_enabled=True)
    client = cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient))

    async def check() -> None:
        engine = async_engine(case)
        # Exercise actual transactions under the runtime role, mocking only identity verification.
        runtime_engine = Mock(spec=AsyncEngine)
        runtime_engine.begin.side_effect = lambda: app_transaction(engine)
        token = SecretStr("A" * 43)
        try:
            async with app_transaction(engine) as connection:
                await record_terms_acceptance(connection, session(case.other), ACCEPTANCE)
                await connection.execute(
                    insert(AccountTermsAcceptance).values(
                        user_id=case.target,
                        terms_version="previous-revision",
                    )
                )
            status = await terms.account_terms_status_transaction(
                cast(AsyncEngine, runtime_engine),
                token,
                settings=settings,
                client=client,
                key_cache=None,
            )
            assert status is not None and status.accepted_at is None
            with pytest.raises(terms.AccountTermsRequired):
                async with terms.terms_account_transaction(
                    cast(AsyncEngine, runtime_engine),
                    token,
                    settings=settings,
                    client=client,
                    key_cache=None,
                ):
                    raise AssertionError("Missing acceptance must block resource work.")
            async with app_transaction(engine) as connection:
                # Reading status and denying access must not create current acceptance.
                assert await current_terms_accepted_at(connection, case.target) is None
                accepted_at = await record_terms_acceptance(connection, verified, ACCEPTANCE)
            status = await terms.account_terms_status_transaction(
                cast(AsyncEngine, runtime_engine),
                token,
                settings=settings,
                client=client,
                key_cache=None,
            )
            assert status is not None and status.accepted_at == accepted_at
            async with terms.terms_account_transaction(
                cast(AsyncEngine, runtime_engine),
                token,
                settings=settings,
                client=client,
                key_cache=None,
            ) as access:
                assert access.session.account.user_id == case.target
                assert await access.connection.scalar(text("SELECT current_user")) == "askm6_app"
                assert (
                    await access.connection.scalar(
                        select(UserProfile.id).where(
                            UserProfile.id == access.session.account.user_id,
                        )
                    )
                    == case.target
                )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_resource_write_failure_rolls_back_without_losing_prior_acceptance(
    case: TermsCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = session(case.target)
    monkeypatch.setattr(terms, "authenticate_account_session", AsyncMock(return_value=verified))

    async def check() -> None:
        engine = async_engine(case)
        runtime_engine = Mock(spec=AsyncEngine)
        runtime_engine.begin.side_effect = lambda: app_transaction(engine)
        try:
            async with app_transaction(engine) as connection:
                accepted_at = await record_terms_acceptance(connection, verified, ACCEPTANCE)
            with pytest.raises(RuntimeError, match="synthetic resource failure"):
                async with terms.terms_account_transaction(
                    cast(AsyncEngine, runtime_engine),
                    SecretStr("A" * 43),
                    settings=IsolatedSettings(account_terms_api_enabled=True),
                    client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
                    key_cache=None,
                ) as access:
                    await access.connection.execute(
                        delete(UserProfile).where(
                            UserProfile.id == access.session.account.user_id,
                        )
                    )
                    raise RuntimeError("synthetic resource failure")
            async with app_transaction(engine) as connection:
                assert (
                    await connection.scalar(
                        select(UserProfile.id).where(
                            UserProfile.id == case.target,
                        )
                    )
                    == case.target
                )
                assert await current_terms_accepted_at(connection, case.target) == accepted_at
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("matches", [False, True])
def test_cookie_owner_precondition_uses_locked_database_identity_before_verification(
    case: TermsCase,
    monkeypatch: pytest.MonkeyPatch,
    matches: bool,
) -> None:
    verified = session(case.target)
    authenticate = AsyncMock(return_value=verified)
    monkeypatch.setattr(terms, "authenticate_account_session", authenticate)
    token = SecretStr(token_urlsafe(32))

    async def check() -> None:
        engine = async_engine(case)
        runtime = Mock(spec=AsyncEngine)
        runtime.begin.side_effect = lambda: app_transaction(engine)
        try:
            async with app_transaction(engine) as connection:
                now = func.statement_timestamp()
                await connection.execute(
                    insert(AccountSession).values(
                        user_id=case.target,
                        provider_session_id=verified.account.session_id,
                        token_hash=sha256(token.get_secret_value().encode("ascii")).digest(),
                        access_token_ciphertext=b"synthetic",
                        refresh_token_ciphertext=b"synthetic",
                        access_token_expires_at=now + timedelta(minutes=5),
                        created_at=now,
                        last_seen_at=now,
                        idle_expires_at=now + timedelta(days=1),
                        absolute_expires_at=now + timedelta(days=2),
                    )
                )

            async def accept() -> None:
                result = await terms.accept_account_terms_transaction(
                    cast(AsyncEngine, runtime),
                    token,
                    ACCEPTANCE,
                    settings=IsolatedSettings(account_terms_api_enabled=True),
                    client=cast(httpx2.AsyncClient, Mock(spec=httpx2.AsyncClient)),
                    key_cache=None,
                    expected_user_id=case.target if matches else case.other,
                )
                assert result is not None

            if matches:
                await accept()
                authenticate.assert_awaited_once()
            else:
                with pytest.raises(terms.AccountTermsSessionChanged):
                    await accept()
                authenticate.assert_not_awaited()
            async with app_transaction(engine) as connection:
                assert (
                    await current_terms_accepted_at(connection, case.target) is not None
                ) is matches
                assert await current_terms_accepted_at(connection, case.other) is None
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


@pytest.mark.parametrize("kind", ["confirmed", "unconfirmed", "other-account", "rollback"])
def test_registration_receipt_records_original_time_only_for_verified_subject(
    case: TermsCase, kind: str
) -> None:
    from app.account_sessions import CreatedAccountSession
    from app.account_signup_terms import make_signup_terms_receipt
    from app.account_terms import record_signup_terms_acceptance

    now = datetime.now(UTC)
    receipt = make_signup_terms_receipt(SecretStr("synthetic@example.test")).model_copy(
        update={
            "accepted_at": now - timedelta(minutes=5),
            "expires_at": now + timedelta(minutes=55),
            "confirmed_user_id": None
            if kind == "unconfirmed"
            else case.other
            if kind == "other-account"
            else case.target,
        }
    )
    account = CreatedAccountSession(
        session_id=uuid4(),
        user_id=case.target,
        token=SecretStr("A" * 43),
        idle_expires_at=now + timedelta(days=7),
        absolute_expires_at=now + timedelta(days=30),
    )

    async def check() -> None:
        engine = async_engine(case)
        try:
            if kind == "rollback":
                with pytest.raises(RuntimeError):
                    async with app_transaction(engine) as connection:
                        await record_signup_terms_acceptance(connection, account, receipt)
                        raise RuntimeError("synthetic rollback")
            else:
                async with app_transaction(engine) as connection:
                    await record_signup_terms_acceptance(connection, account, receipt)
            async with app_transaction(engine) as connection:
                assert await current_terms_accepted_at(connection, case.target) == (
                    receipt.accepted_at if kind == "confirmed" else None
                )
                assert await current_terms_accepted_at(connection, case.other) is None
                if kind == "confirmed":
                    await record_signup_terms_acceptance(
                        connection, account, receipt.model_copy(update={"accepted_at": now})
                    )
                    assert (
                        await current_terms_accepted_at(connection, case.target)
                        == receipt.accepted_at
                    )
        finally:
            await engine.dispose()

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)


def test_downgrade_locks_writers_before_empty_check_without_dropping_table(case: TermsCase) -> None:
    backend = Path(__file__).resolve().parents[2]
    scripts = ScriptDirectory.from_config(Config(str(backend / "alembic.ini")))
    revision = scripts.get_revision("b4d7e2806a12")
    assert revision is not None

    class StopProbe(Exception):
        pass

    probed = False

    def before_check(
        connection: Connection,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        nonlocal probed
        if not statement.startswith("DO $$ BEGIN IF EXISTS"):
            assert not statement.startswith("DROP TABLE")
            return
        # A concurrent runtime writer must be blocked before the emptiness check.
        # The savepoint and enclosing migration transaction are always rolled back.
        with case.engine.begin() as writer:
            writer.execute(text("SET LOCAL ROLE askm6_app"))
            writer.execute(text("SET LOCAL lock_timeout = '100ms'"))
            with pytest.raises(DBAPIError) as caught:
                with writer.begin_nested():
                    writer.execute(
                        insert(AccountTermsAcceptance).values(
                            user_id=case.target, terms_version=CURRENT_TERMS_VERSION
                        )
                    )
            assert getattr(caught.value.orig, "sqlstate", None) == "55P03"
        probed = True
        raise StopProbe

    with case.engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET LOCAL ROLE askm6_migrator"))
            connection.execute(text("SET LOCAL lock_timeout = '2s'"))
            event.listen(connection, "before_cursor_execute", before_check)
            with pytest.raises(StopProbe):
                with Operations.context(MigrationContext.configure(connection)):
                    cast(TermsMigration, revision.module).downgrade()
        finally:
            event.remove(connection, "before_cursor_execute", before_check)
            transaction.rollback()
    assert probed
    with case.engine.connect() as connection:
        assert (
            connection.scalar(text("SELECT to_regclass('app.account_terms_acceptances')"))
            is not None
        )
        assert (
            connection.scalar(
                select(func.count())
                .select_from(AccountTermsAcceptance)
                .where(AccountTermsAcceptance.user_id == case.target)
            )
            == 0
        )
