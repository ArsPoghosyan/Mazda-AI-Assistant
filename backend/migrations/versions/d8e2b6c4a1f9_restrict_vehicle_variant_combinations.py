"""restrict vehicle variant combinations

Revision ID: d8e2b6c4a1f9
Revises: c3f1a9d2e7b4
Create Date: 2026-10-29

"""

from collections.abc import Sequence

from alembic import op

revision: str = "d8e2b6c4a1f9"
down_revision: str | Sequence[str] | None = "c3f1a9d2e7b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Reject manual configurations that EPA does not list (all seeded rows comply)."""
    op.create_check_constraint(
        op.f("ck_vehicle_variants_manual_configuration_supported"),
        "vehicle_variants",
        "transmission <> '6MT' OR "
        "(aspiration = 'naturally_aspirated' AND model_year IN (2018, 2019))",
        schema="app",
    )


def downgrade() -> None:
    """Drop only the combination rule; per-column rules and data are unchanged."""
    op.drop_constraint(
        op.f("ck_vehicle_variants_manual_configuration_supported"),
        "vehicle_variants",
        schema="app",
        type_="check",
    )
