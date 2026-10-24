"""allow sign-in auth rate limits

Revision ID: 0f42bd53f47a
Revises: 0826d9fbcef3
Create Date: 2026-10-24 16:03:47.456096

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0f42bd53f47a"
down_revision: str | Sequence[str] | None = "0826d9fbcef3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Allow sign-in state without changing recovery rows, keys or grants."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_password_recovery_only"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )


def downgrade() -> None:
    """Refuse rollback while sign-in rows exist; never delete limiter state."""
    # Validate the narrower constraint before removing the broader one. Existing
    # sign-in rows make this fail, preserving the current schema and all data.
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_password_recovery_only"),
        "auth_rate_limits",
        "purpose = 'password_recovery'",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )
