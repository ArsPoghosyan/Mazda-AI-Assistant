"""create account Terms acceptances

Revision ID: b4d7e2806a12
Revises: 46250b6b2d17
Create Date: 2026-10-26

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b4d7e2806a12"
down_revision: str | Sequence[str] | None = "46250b6b2d17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add empty records without assuming any existing account agreed to Terms."""
    op.create_table(
        "account_terms_acceptances",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("terms_version", sa.String(64), nullable=False),
        sa.Column(
            "accepted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("statement_timestamp()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "user_id", "terms_version", name=op.f("pk_account_terms_acceptances")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app.user_profiles.id"],
            ondelete="CASCADE",
            name=op.f("fk_account_terms_acceptances_user_id_user_profiles"),
        ),
        sa.CheckConstraint(
            "terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            name=op.f("ck_account_terms_acceptances_version_format"),
        ),
        schema="app",
    )
    op.execute("REVOKE ALL ON TABLE app.account_terms_acceptances FROM PUBLIC")
    op.execute("REVOKE ALL ON TABLE app.account_terms_acceptances FROM askm6_app")
    op.execute("GRANT SELECT, INSERT ON TABLE app.account_terms_acceptances TO askm6_app")


def downgrade() -> None:
    """Refuse rollback with real acceptance records instead of discarding them."""
    # Keep writers out between the emptiness check and DROP, in this transaction.
    op.execute("LOCK TABLE app.account_terms_acceptances IN ACCESS EXCLUSIVE MODE")
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM app.account_terms_acceptances) THEN "
        "RAISE EXCEPTION 'Cannot remove populated Terms acceptance records'; "
        "END IF; END $$"
    )
    op.drop_table("account_terms_acceptances", schema="app")
