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
    """Date each campaign/model-year listing so dropped listings are not shown as current."""
    for column in ("first_listed_at", "last_listed_at"):
        op.add_column(
            "recall_applicability",
            sa.Column(column, sa.DateTime(timezone=True), nullable=True),
            schema="app",
        )
    # Existing rows only know their campaign's times; the next import refines them.
    op.execute(
        "UPDATE app.recall_applicability AS listing "
        "SET first_listed_at = campaign.first_seen_at, "
        "last_listed_at = campaign.last_seen_at "
        "FROM app.recall_campaigns AS campaign "
        "WHERE campaign.id = listing.campaign_id"
    )
    for column in ("first_listed_at", "last_listed_at"):
        op.alter_column("recall_applicability", column, nullable=False, schema="app")
    op.create_check_constraint(
        op.f("ck_recall_applicability_listed_times_ordered"),
        "recall_applicability",
        "first_listed_at <= last_listed_at",
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
