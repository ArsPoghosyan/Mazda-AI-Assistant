"""allow email-confirmation auth rate limits

Revision ID: 6ef221a79f00
Revises: bcae4df0f56a
Create Date: 2026-10-24 20:18:35.284074

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6ef221a79f00"
down_revision: str | Sequence[str] | None = "bcae4df0f56a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Permit confirmation state without changing existing rows or privileges."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_confirmation"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_sign_up"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )


def downgrade() -> None:
    """Refuse rollback while confirmation rows exist; never discard limiter data."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_sign_up"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_confirmation"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )
