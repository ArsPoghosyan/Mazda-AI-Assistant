"""Optional application-owned scheduling for bounded authentication housekeeping."""

import logging
from asyncio import CancelledError, create_task, sleep
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_oauth_cleanup import commit_expired_oauth_login_attempt_cleanup
from app.auth_rate_limit_cleanup import commit_expired_auth_rate_limit_cleanup
from app.config import Settings
from app.session_cleanup import (
    commit_expired_account_session_cleanup,
    commit_expired_guest_session_cleanup,
)

logger = logging.getLogger(__name__)


async def _run_cleanup(engine: AsyncEngine, settings: Settings) -> None:
    """Run one batch per table serially; never overlap passes or catch up missed runs."""
    operations = (
        (
            commit_expired_auth_rate_limit_cleanup,
            "Authentication limiter cleanup failed; waiting for the next interval.",
            "Deleted %d expired authentication limiter records.",
        ),
        (
            commit_expired_oauth_login_attempt_cleanup,
            "Pending Google login-attempt cleanup failed; waiting for the next interval.",
            "Deleted %d expired pending Google login attempts.",
        ),
        (
            commit_expired_guest_session_cleanup,
            "Guest-session cleanup failed; waiting for the next interval.",
            "Deleted %d expired guest sessions.",
        ),
        (
            commit_expired_account_session_cleanup,
            "Account-session cleanup failed; waiting for the next interval.",
            "Deleted %d expired account sessions.",
        ),
    )
    while True:
        await sleep(settings.auth_rate_limit_cleanup_interval_seconds)
        for cleanup, failure_message, success_message in operations:
            try:
                # Each helper owns a transaction and deadline. A failed batch
                # leaves later operations available; cancellation stops the task.
                deleted = await cleanup(
                    engine,
                    batch_size=settings.auth_rate_limit_cleanup_batch_size,
                    timeout_seconds=settings.auth_rate_limit_cleanup_timeout_seconds,
                )
            except Exception:
                # Exception text/tracebacks can contain private connection or
                # query values. Log only the fixed operation-specific warning.
                logger.warning(failure_message)
            else:
                if deleted:
                    logger.info(success_message, deleted)


@asynccontextmanager
async def auth_rate_limit_cleanup_lifespan(
    engine: AsyncEngine | None, settings: Settings
) -> AsyncIterator[None]:
    """Own one optional task and stop it before the application disposes its engine."""
    if not settings.auth_rate_limit_cleanup_enabled or engine is None:
        yield
        return

    task = create_task(_run_cleanup(engine, settings), name="auth-rate-limit-cleanup")
    try:
        yield
    finally:
        task.cancel()
        with suppress(CancelledError):
            await task
