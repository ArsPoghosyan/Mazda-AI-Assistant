"""track recall listing times

Revision ID: c7e2d5a8f1b3
Revises: a9c4e1f7b2d6
Create Date: 2026-11-01

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c7e2d5a8f1b3"
down_revision: str | Sequence[str] | None = "a9c4e1f7b2d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Date each campaign/model-year listing so dropped listings are not shown as current.

    Existing listings start with unknown dates. Campaign-level times cannot say
    which model years were confirmed, so the next import supplies real dates.
    """
    for column in ("first_listed_at", "last_listed_at"):
        op.add_column(
            "recall_applicability",
            sa.Column(column, sa.DateTime(timezone=True), nullable=True),
            schema="app",
        )
    op.create_check_constraint(
        op.f("ck_recall_applicability_listed_times_ordered"),
        "recall_applicability",
        "(first_listed_at IS NULL AND last_listed_at IS NULL) OR "
        "(first_listed_at IS NOT NULL AND last_listed_at IS NOT NULL "
        "AND first_listed_at <= last_listed_at)",
        schema="app",
    )


def downgrade() -> None:
    """Drop the per-listing times; campaign-level times remain."""
    op.drop_constraint(
        op.f("ck_recall_applicability_listed_times_ordered"),
        "recall_applicability",
        schema="app",
        type_="check",
    )
    for column in ("last_listed_at", "first_listed_at"):
        op.drop_column("recall_applicability", column, schema="app")
