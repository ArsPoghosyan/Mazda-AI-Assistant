"""create recall model year checks

Revision ID: a9c4e1f7b2d6
Revises: f4a7c2d9b351
Create Date: 2026-11-01

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a9c4e1f7b2d6"
down_revision: str | Sequence[str] | None = "f4a7c2d9b351"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Record when each model year was checked, so empty results carry a date."""
    op.create_table(
        "recall_model_year_checks",
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("make", sa.String(16), nullable=False),
        sa.Column("model", sa.String(16), nullable=False),
        sa.Column("model_year", sa.SmallInteger(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("campaigns_listed", sa.SmallInteger(), nullable=False),
        sa.PrimaryKeyConstraint(
            "source_id",
            "make",
            "model",
            "model_year",
            name=op.f("pk_recall_model_year_checks"),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["app.evidence_sources.id"],
            name=op.f("fk_recall_model_year_checks_source_id_evidence_sources"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "make = 'MAZDA'",
            name=op.f("ck_recall_model_year_checks_make_supported"),
        ),
        sa.CheckConstraint(
            "model = 'MAZDA6'",
            name=op.f("ck_recall_model_year_checks_model_supported"),
        ),
        sa.CheckConstraint(
            "model_year BETWEEN 2018 AND 2021",
            name=op.f("ck_recall_model_year_checks_model_year_supported"),
        ),
        sa.CheckConstraint(
            "campaigns_listed BETWEEN 0 AND 100",
            name=op.f("ck_recall_model_year_checks_campaigns_listed_range"),
        ),
        schema="app",
    )
    # The website only reads evidence; ingestion writes it as the owner role.
    op.execute("REVOKE ALL ON TABLE app.recall_model_year_checks FROM PUBLIC")
    op.execute("REVOKE ALL ON TABLE app.recall_model_year_checks FROM askm6_app")
    op.execute("GRANT SELECT ON TABLE app.recall_model_year_checks TO askm6_app")


def downgrade() -> None:
    """Drop the check log; it is rebuilt by the next import."""
    op.drop_table("recall_model_year_checks", schema="app")
