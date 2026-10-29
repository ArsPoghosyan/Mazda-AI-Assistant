"""Import NHTSA Mazda 6 recall listings into a local database (dry run by default)."""

import argparse
import asyncio
import os
import sys
from datetime import UTC, datetime
from typing import NoReturn

import httpx2
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from app.nhtsa_recall_ingestion import IngestionReport, apply_recall_batch
from app.nhtsa_recalls import SUPPORTED_YEARS, NhtsaRecallError, RecallBatch, fetch_recalls

_DATABASE_TIMEOUT_SECONDS = 30
# The website's local database only; integration tests expect askm6_test untouched.
_LOCAL_DATABASE = "mazda6"


class ImportTargetError(ValueError):
    """The database target is not the local one this command may write to."""


class _ImportArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        """Do not echo unknown arguments or values that may contain credentials."""
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid import arguments. Use --help for options.\n")


def parse_years(value: str) -> tuple[int, ...]:
    """Accept one year (2021) or a range (2018-2021) inside the supported range."""
    first, separator, last = value.partition("-")
    try:
        start = int(first)
        end = int(last) if separator else start
    except ValueError:
        raise ValueError("Years must look like 2021 or 2018-2021.") from None
    if start > end or start not in SUPPORTED_YEARS or end not in SUPPORTED_YEARS:
        raise ValueError("Years must be within 2018-2021.")
    return tuple(range(start, end + 1))


def local_import_target(database_url: SecretStr) -> URL:
    """Only the local website database, as the owner role; production needs separate review."""
    try:
        url = make_url(database_url.get_secret_value())
    except (ArgumentError, ValueError):
        raise ImportTargetError("Import database URL is invalid.") from None
    if (
        url.drivername != "postgresql+psycopg"
        or url.host != "127.0.0.1"
        or url.port != 15432
        or url.database != _LOCAL_DATABASE
        or url.username != "askm6_migrator"
        or url.query
    ):
        raise ImportTargetError("Import requires the local mazda6 database as askm6_migrator.")
    return url


async def apply_in_transaction(
    connection: AsyncConnection,
    batch: RecallBatch,
    *,
    database: str,
    write: bool,
) -> IngestionReport:
    """Check identity and apply the batch in one transaction; commit only on write."""
    transaction = await connection.begin()
    try:
        identity = (await connection.execute(text("SELECT current_database(), current_user"))).one()
        if tuple(identity) != (database, "askm6_migrator"):
            raise ImportTargetError("Unexpected database identity.")

        report = await connection.run_sync(apply_recall_batch, batch, seen_at=datetime.now(UTC))
        if write:
            await transaction.commit()
    finally:
        if transaction.is_active:
            await transaction.rollback()
    return report


async def run_import(
    database_url: SecretStr,
    model_years: tuple[int, ...],
    *,
    write: bool,
    transport: httpx2.AsyncBaseTransport | None = None,
    pause_seconds: float = 1.0,
) -> tuple[RecallBatch, IngestionReport]:
    """Fetch everything first, then apply it in one transaction that commits only on --write."""
    url = local_import_target(database_url)

    async with httpx2.AsyncClient(
        transport=transport, trust_env=False, follow_redirects=False
    ) as client:
        batch = await fetch_recalls(client, model_years, pause_seconds=pause_seconds)

    # Pin the address too: libpq environment settings must not redirect the import.
    engine = create_async_engine(
        url,
        poolclass=NullPool,
        hide_parameters=True,
        echo=False,
        connect_args={"connect_timeout": 5, "hostaddr": "127.0.0.1"},
    )
    try:
        async with asyncio.timeout(_DATABASE_TIMEOUT_SECONDS):
            async with engine.connect() as connection:
                report = await apply_in_transaction(
                    connection, batch, database=url.database or "", write=write
                )
    finally:
        await engine.dispose()

    return batch, report


def describe(batch: RecallBatch, report: IngestionReport, *, database: str, write: bool) -> str:
    """Summarise a run without printing record text or credentials."""
    per_year = ", ".join(
        f"{year}: {sum(year in years for years in batch.listings.values())}"
        for year in batch.model_years
    )
    urgent = sorted(
        number
        for number, record in batch.campaigns.items()
        if record.park_it or record.park_outside
    )
    lines = [
        f"Target: local database '{database}' ({'write' if write else 'dry run'}).",
        f"NHTSA campaigns listed per model year: {per_year}.",
        f"Campaigns: {report.added} added, {report.changed} changed, "
        f"{report.unchanged} unchanged; {report.listings_added} model-year listings added.",
        f"Park-it / park-outside campaigns: {', '.join(urgent) or 'none'}.",
        "Stored but not listed this run (kept): " + (", ".join(report.not_seen) or "none") + ".",
    ]
    if batch.empty_years:
        years = ", ".join(map(str, batch.empty_years))
        lines.append(
            f"Note: NHTSA listed no campaigns for {years}. That is not proof that no recalls "
            "exist; recalls apply per VIN (check at nhtsa.gov/recalls)."
        )
    lines.append("Committed." if write else "Rolled back; nothing saved. Re-run with --write.")
    return "\n".join(lines)


def main() -> int:
    parser = _ImportArgumentParser(
        description=(
            "Fetch NHTSA recall listings for the Mazda 6 and apply them to the local "
            "database. Reads MIGRATION_DATABASE_URL from the environment only."
        )
    )
    parser.add_argument(
        "--years", default="2018-2021", help="One year or a range within 2018-2021 (default)."
    )
    parser.add_argument(
        "--write", action="store_true", help="Commit the changes (default: dry run)."
    )
    arguments = parser.parse_args()

    try:
        model_years = parse_years(arguments.years)
    except ValueError:
        parser.error("--years must be one year or a range within 2018-2021.")

    # Deliberately not MigrationSettings: its default env file targets production.
    raw_url = os.environ.get("MIGRATION_DATABASE_URL")
    if not raw_url:
        print("Set MIGRATION_DATABASE_URL (for example via .env.migrations.dev).", file=sys.stderr)
        return 1
    database_url = SecretStr(raw_url)

    try:
        database = local_import_target(database_url).database or ""
        batch, report = asyncio.run(
            run_import(database_url, model_years, write=arguments.write),
            loop_factory=asyncio.SelectorEventLoop,
        )
    except (NhtsaRecallError, ImportTargetError) as error:
        print(f"Import stopped, nothing saved: {error}", file=sys.stderr)
        return 1
    except (SQLAlchemyError, TimeoutError, ValueError, OSError):
        # A failure during the final commit has an uncertain outcome; re-running is safe.
        print(
            "Import stopped by a database or network failure. Changes are saved only "
            "when 'Committed.' is printed; re-run to confirm (repeating is safe).",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print(
            "Import interrupted; re-run to confirm the outcome (repeating is safe).",
            file=sys.stderr,
        )
        return 130

    print(describe(batch, report, database=database, write=arguments.write))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
