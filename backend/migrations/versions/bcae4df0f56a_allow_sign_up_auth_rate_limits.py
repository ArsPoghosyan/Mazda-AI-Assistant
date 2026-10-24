"""allow sign-up auth rate limits

Revision ID: bcae4df0f56a
Revises: 0f42bd53f47a
Create Date: 2026-10-24 17:44:32.110290

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bcae4df0f56a"
down_revision: str | Sequence[str] | None = "0f42bd53f47a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Permit sign-up state without changing existing rows or privileges."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_sign_up"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )


def downgrade() -> None:
    """Refuse rollback while sign-up rows exist; never discard limiter data."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_sign_up"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )
