"""Run one bounded limiter-cleanup batch against a local database."""

import argparse
import asyncio
import sys
from typing import NoReturn

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.auth_rate_limit_cleanup import commit_expired_auth_rate_limit_cleanup
from app.config import Settings


class _MaintenanceArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        """Do not echo unknown arguments or values that may contain credentials."""
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid maintenance arguments. Use --help for options and limits.\n")


async def cleanup_local(
    settings: Settings,
    *,
    batch_size: int,
    timeout_seconds: float,
) -> int:
    """Check the local target, run one batch and dispose the dedicated engine."""
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("Cleanup batch size must be between 1 and 1000.")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise ValueError("Cleanup timeout must be greater than 0 and at most 30 seconds.")
    if settings.database_url is None:
        raise ValueError("Runtime database is not configured.")

    url = make_url(settings.database_url.get_secret_value())
    if (
        url.drivername != "postgresql+psycopg"
        or url.host != "127.0.0.1"
        or url.port != 15432
        or url.database not in {"mazda6", "askm6_test"}
        or url.username != "askm6_app"
        or url.query
    ):
        raise ValueError("Cleanup requires the restricted local database target.")

    # Pin the network address as well as the URL: libpq environment settings
    # must not redirect maintenance to another host. This one-shot engine does
    # not need a persistent pool or the application's ordinary runtime engine.
    engine = create_async_engine(
        url,
        poolclass=NullPool,
        hide_parameters=True,
        echo=False,
        connect_args={
            "connect_timeout": settings.db_connect_timeout_seconds,
            "hostaddr": "127.0.0.1",
        },
    )
    try:
        async with asyncio.timeout(timeout_seconds):
            async with engine.connect() as connection:
                identity = (
                    await connection.execute(
                        text(
                            "SELECT current_database(), current_user, "
                            "NOT rolsuper AND NOT rolbypassrls "
                            "FROM pg_roles WHERE rolname = current_user"
                        )
                    )
                ).one()
                if tuple(identity) != (url.database, "askm6_app", True):
                    raise ValueError("Unexpected database identity.")

            return await commit_expired_auth_rate_limit_cleanup(
                engine,
                batch_size=batch_size,
                timeout_seconds=timeout_seconds,
            )
    finally:
        await engine.dispose()


def main() -> int:
    parser = _MaintenanceArgumentParser(
        description=(
            "Delete one batch of expired local authentication limiter rows, "
            "including email confirmation, password reset, guest creation and Google initiation."
        )
    )
    parser.add_argument(
        "--batch-size", type=int, default=100, help="Rows per batch: 1–1000 (default 100)."
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=5,
        help="Deadline: greater than 0 through 30 seconds (default 5).",
    )
    arguments = parser.parse_args()

    if not 1 <= arguments.batch_size <= 1000:
        parser.error("--batch-size must be between 1 and 1000.")
    if not 0 < arguments.timeout_seconds <= 30:
        parser.error("--timeout-seconds must be greater than 0 and at most 30.")

    try:
        deleted = asyncio.run(
            cleanup_local(
                Settings(),
                batch_size=arguments.batch_size,
                timeout_seconds=arguments.timeout_seconds,
            ),
            loop_factory=asyncio.SelectorEventLoop,
        )
    except (SQLAlchemyError, TimeoutError, ValueError, RuntimeError, OSError):
        print(
            "Cleanup did not complete. Check local configuration and migration; "
            "an interrupted commit may have an uncertain outcome.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Cleanup interrupted; its outcome may be uncertain.", file=sys.stderr)
        return 130

    print(f"Cleanup committed: {deleted} expired rows deleted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
