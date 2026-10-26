"""Rehearse manual deletion steps on local PostgreSQL; not a deletion service.

Provider outcomes and lost acknowledgements are simulated. All committed fixture
rows have random test-owned IDs; the shared integration fixture guards the DB.
"""

import asyncio
from collections.abc import Callable, Iterator
from contextlib import AbstractAsyncContextManager, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import AsyncConnection

from app import account_sessions
from app.account_token_encryption import AccountTokenCipher
from app.account_tokens import VerifiedAccount
from app.config import Settings
from app.models import AccountSession, AuthRateLimit, GuestSession, OAuthLoginAttempt, UserProfile

pytestmark = pytest.mark.integration

type Snapshot = dict[str, list[tuple[object, ...]]]
type ConnectionFactory = Callable[[], AbstractAsyncContextManager[AsyncConnection]]


@dataclass(frozen=True)
class Rehearsal:
    engine: Engine
    target: UUID = field(default_factory=uuid4)
    other: UUID = field(default_factory=uuid4)
    guest: UUID = field(default_factory=uuid4)
    oauth: UUID = field(default_factory=uuid4)
    fingerprint: bytes = field(default_factory=lambda: token_bytes(32), repr=False)


@contextmanager
def app_transaction(case: Rehearsal) -> Iterator[Connection]:
    with case.engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE askm6_app"))
        connection.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        connection.execute(text("SET LOCAL statement_timeout = '5s'"))
        connection.execute(text("SET LOCAL lock_timeout = '1s'"))
        assert tuple(connection.execute(text("SELECT current_database(), current_user")).one()) == (
            "askm6_test",
            "askm6_app",
        )
        assert (
            connection.scalar(
                text(
                    "SELECT NOT rolsuper AND NOT rolbypassrls "
                    "FROM pg_roles WHERE rolname=current_user"
                )
            )
            is True
        )
        yield connection


@pytest.fixture
def case(integration_engine: Engine) -> Iterator[Rehearsal]:
    rehearsal = Rehearsal(integration_engine)
    cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    try:
        with app_transaction(rehearsal) as connection:
            now = func.statement_timestamp()
            connection.execute(
                insert(UserProfile).values(
                    [
                        {"id": rehearsal.target},
                        {"id": rehearsal.other},
                    ]
                )
            )
            for owner, idle_expired, absolute_expired in (
                (rehearsal.target, False, False),
                (rehearsal.target, True, False),
                (rehearsal.target, True, True),
                (rehearsal.other, False, False),
            ):
                age = 40 if absolute_expired else 10 if idle_expired else 2
                last_seen = now - timedelta(days=age - 1)
                connection.execute(
                    insert(AccountSession).values(
                        id=uuid4(),
                        user_id=owner,
                        provider_session_id=uuid4(),
                        token_hash=token_bytes(32),
                        access_token_ciphertext=cipher.encrypt(SecretStr("synthetic-access")),
                        refresh_token_ciphertext=cipher.encrypt(SecretStr("synthetic-refresh")),
                        access_token_expires_at=now + timedelta(hours=1),
                        created_at=now - timedelta(days=age),
                        last_seen_at=last_seen,
                        idle_expires_at=last_seen + timedelta(days=7),
                        absolute_expires_at=now + timedelta(days=30 - age),
                    )
                )
            connection.execute(
                insert(GuestSession).values(
                    id=rehearsal.guest,
                    token_hash=token_bytes(32),
                    created_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(days=30),
                )
            )
            connection.execute(
                insert(OAuthLoginAttempt).values(
                    id=rehearsal.oauth,
                    browser_token_hash=token_bytes(32),
                    pkce_verifier_ciphertext=cipher.encrypt(SecretStr("synthetic-verifier")),
                    provider="google",
                    purpose="sign_in",
                    created_at=now,
                    expires_at=now + timedelta(minutes=10),
                )
            )
            connection.execute(
                insert(AuthRateLimit).values(
                    purpose="sign_in",
                    key_hash=rehearsal.fingerprint,
                    request_times=[datetime.now(UTC)],
                    expires_at=now + timedelta(minutes=10),
                )
            )
        yield rehearsal
    finally:
        # Delete only this fixture's random IDs; never truncate shared tables.
        with app_transaction(rehearsal) as connection:
            connection.execute(
                delete(UserProfile).where(UserProfile.id.in_((rehearsal.target, rehearsal.other)))
            )
            connection.execute(delete(GuestSession).where(GuestSession.id == rehearsal.guest))
            connection.execute(
                delete(OAuthLoginAttempt).where(OAuthLoginAttempt.id == rehearsal.oauth)
            )
            connection.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.purpose == "sign_in",
                    AuthRateLimit.key_hash == rehearsal.fingerprint,
                )
            )
        assert all(not rows for rows in snapshot(rehearsal).values())


def snapshot(case: Rehearsal) -> Snapshot:
    """Read only the synthetic records, including full unrelated-row values."""
    with app_transaction(case) as connection:
        statements = {
            "target_profile": select(UserProfile).where(UserProfile.id == case.target),
            "target_sessions": select(AccountSession)
            .where(AccountSession.user_id == case.target)
            .order_by(AccountSession.id),
            "other_profile": select(UserProfile).where(UserProfile.id == case.other),
            "other_sessions": select(AccountSession)
            .where(AccountSession.user_id == case.other)
            .order_by(AccountSession.id),
            "guest": select(GuestSession).where(GuestSession.id == case.guest),
            "oauth": select(OAuthLoginAttempt).where(OAuthLoginAttempt.id == case.oauth),
            "limiter": select(AuthRateLimit).where(
                AuthRateLimit.purpose == "sign_in",
                AuthRateLimit.key_hash == case.fingerprint,
            ),
        }
        return {
            name: [tuple(row) for row in connection.execute(statement)]
            for name, statement in statements.items()
        }


def remove_profile(connection: Connection, target: UUID) -> UUID | None:
    return connection.scalar(
        delete(UserProfile).where(UserProfile.id == target).returning(UserProfile.id)
    )


def assert_deleted(before: Snapshot, after: Snapshot) -> None:
    assert len(before["target_profile"]) == 1
    assert len(before["target_sessions"]) == 3
    assert after == {**before, "target_profile": [], "target_sessions": []}


def test_manual_sequence_commits_only_target_profile_and_all_its_sessions(case: Rehearsal) -> None:
    before = snapshot(case)
    delete_provider = Mock(return_value=None)
    delete_provider(case.target)
    with app_transaction(case) as connection:
        assert remove_profile(connection, case.target) == case.target
    # A separate connection observes a real commit, including the FK cascade.
    assert_deleted(before, snapshot(case))
    delete_provider.assert_called_once_with(case.target)


def test_provider_failure_stops_before_any_local_deletion(case: Rehearsal) -> None:
    before = snapshot(case)
    delete_provider = Mock(side_effect=RuntimeError("synthetic provider failure"))
    with pytest.raises(RuntimeError, match="synthetic provider failure"):
        delete_provider(case.target)
        with app_transaction(case) as connection:
            remove_profile(connection, case.target)
    assert snapshot(case) == before
    delete_provider.assert_called_once_with(case.target)


def test_provider_removed_but_local_rollback_requires_only_local_repair(case: Rehearsal) -> None:
    before = snapshot(case)
    delete_provider = Mock(return_value=None)
    delete_provider(case.target)
    with pytest.raises(RuntimeError, match="synthetic local failure"):
        with app_transaction(case) as connection:
            assert remove_profile(connection, case.target) == case.target
            assert (
                connection.scalar(
                    select(AccountSession.id).where(AccountSession.user_id == case.target)
                )
                is None
            )
            raise RuntimeError("synthetic local failure")
    assert snapshot(case) == before
    # Operator has confirmed provider absence; repair the local step, not the provider.
    with app_transaction(case) as connection:
        assert remove_profile(connection, case.target) == case.target
    assert_deleted(before, snapshot(case))
    delete_provider.assert_called_once_with(case.target)


@pytest.mark.parametrize("committed", [False, True], ids=["rolled-back", "committed"])
def test_unknown_local_outcome_is_read_back_before_any_repair(
    case: Rehearsal,
    committed: bool,
) -> None:
    before = snapshot(case)
    delete_provider = Mock(return_value=None)
    delete_provider(case.target)
    # Simulate the operator losing the result; not an injected network/driver fault.
    with pytest.raises(RuntimeError, match="synthetic acknowledgement lost"):
        with app_transaction(case) as connection:
            assert remove_profile(connection, case.target) == case.target
            if not committed:
                raise RuntimeError("synthetic acknowledgement lost")
        raise RuntimeError("synthetic acknowledgement lost")
    observed = snapshot(case)
    if committed:
        assert_deleted(before, observed)
    else:
        assert observed == before
        with app_transaction(case) as connection:
            assert remove_profile(connection, case.target) == case.target
        assert_deleted(before, snapshot(case))
    delete_provider.assert_called_once_with(case.target)


def test_absent_local_profile_is_a_scoped_no_op(case: Rehearsal) -> None:
    before = snapshot(case)
    # A provider identity can exist without a local profile. This tests local SQL
    # scope only; absence here does not establish absence at Supabase.
    with app_transaction(case) as connection:
        assert remove_profile(connection, uuid4()) is None
    assert snapshot(case) == before


def test_already_authorized_session_work_can_recreate_profile_without_write_drain(
    case: Rehearsal,
    async_app_connection_factory: ConnectionFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Counterexample explaining the maintenance pause, not a new deletion guard."""
    before = snapshot(case)
    Mock(return_value=None)(case.target)
    with app_transaction(case) as connection:
        assert remove_profile(connection, case.target) == case.target
    assert_deleted(before, snapshot(case))

    class IsolatedSettings(Settings):
        model_config = SettingsConfigDict(env_file=None)

    settings = IsolatedSettings(
        account_session_encryption_key=SecretStr(Fernet.generate_key().decode("ascii")),
    )
    previously_authorized = VerifiedAccount(
        user_id=case.target,
        session_id=uuid4(),
        assurance_level="aal1",
        access_token_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    verification = AsyncMock(return_value=previously_authorized)
    monkeypatch.setattr(account_sessions, "authenticate_account_token", verification)

    async def check() -> None:
        async with async_app_connection_factory() as connection:
            created = await account_sessions.create_account_session(
                connection,
                settings,
                access_token=SecretStr("synthetic-access"),
                refresh_token=SecretStr("synthetic-refresh"),
                key_cache=None,
            )
            assert created.user_id == case.target
            assert (
                await connection.scalar(select(UserProfile.id).where(UserProfile.id == case.target))
                == case.target
            )
            # Fixture rolls this hypothetical late write back; no resurrection
            # committed. Real operators must pause and drain before deletion.

    asyncio.run(check(), loop_factory=asyncio.SelectorEventLoop)
    assert_deleted(before, snapshot(case))
    verification.assert_awaited_once()
