"""allow password-reset auth rate limits

Revision ID: 0ffc842c5360
Revises: 6ef221a79f00
Create Date: 2026-10-24 21:03:32.879197

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0ffc842c5360"
down_revision: str | Sequence[str] | None = "6ef221a79f00"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Permit password-reset state without changing existing rows or privileges."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_password_reset"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation', "
        "'password_reset')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_confirmation"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )


def downgrade() -> None:
    """Refuse rollback while password-reset rows exist; never discard limiter data."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_confirmation"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_password_reset"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )
