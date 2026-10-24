"""allow guest-creation auth rate limits

Revision ID: aefd9866f033
Revises: 0ffc842c5360
Create Date: 2026-10-24 21:54:01.857273

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aefd9866f033"
down_revision: str | Sequence[str] | None = "0ffc842c5360"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Permit guest-creation state without changing existing rows or privileges."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_guest_creation"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation', "
        "'password_reset', 'guest_creation')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_password_reset"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )


def downgrade() -> None:
    """Refuse rollback while guest-creation rows exist; never discard limiter data."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_password_reset"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation', "
        "'password_reset')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_guest_creation"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )
