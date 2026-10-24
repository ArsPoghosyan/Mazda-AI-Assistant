"""allow Google-start auth rate limits

Revision ID: 46250b6b2d17
Revises: aefd9866f033
Create Date: 2026-10-24

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "46250b6b2d17"
down_revision: str | Sequence[str] | None = "aefd9866f033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Permit Google-start state without changing existing rows or privileges."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_google_start"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation', "
        "'password_reset', 'guest_creation', 'google_start')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_guest_creation"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )


def downgrade() -> None:
    """Refuse rollback while Google-start rows exist; never discard limiter data."""
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_guest_creation"),
        "auth_rate_limits",
        "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation', "
        "'password_reset', 'guest_creation')",
        schema="app",
    )
    op.drop_constraint(
        op.f("ck_auth_rate_limits_purpose_supported_with_google_start"),
        "auth_rate_limits",
        type_="check",
        schema="app",
    )
