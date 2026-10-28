"""Shared SQLAlchemy model foundation."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Keep application tables in the app schema."""

    metadata = MetaData(
        schema="app",
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_N_name)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": ("fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s"),
            "pk": "pk_%(table_name)s",
        },
    )


class UserProfile(Base):
    """Account record keyed by the backend-verified authentication subject."""

    __tablename__ = "user_profiles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class AccountTermsAcceptance(Base):
    """Minimal per-account record of an explicitly accepted Terms revision."""

    __tablename__ = "account_terms_acceptances"
    __table_args__ = (
        CheckConstraint(
            "terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            name="version_format",
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("app.user_profiles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    terms_version: Mapped[str] = mapped_column(String(64), primary_key=True)
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.statement_timestamp(),
    )


class GuestSession(Base):
    """Guest identity storing a token verifier rather than the cookie token."""

    __tablename__ = "guest_sessions"
    __table_args__ = (
        CheckConstraint(
            "octet_length(token_hash) = 32",
            name="token_hash_length",
        ),
        CheckConstraint(
            "last_seen_at >= created_at",
            name="last_seen_after_creation",
        ),
        CheckConstraint(
            "expires_at > last_seen_at",
            name="expiry_after_last_seen",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid4,
    )
    token_hash: Mapped[bytes] = mapped_column(
        LargeBinary,
        unique=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )


class AccountSession(Base):
    """Account session with a browser-token hash and encrypted provider tokens."""

    __tablename__ = "account_sessions"
    __table_args__ = (
        CheckConstraint(
            "octet_length(token_hash) = 32",
            name="token_hash_length",
        ),
        CheckConstraint(
            "octet_length(access_token_ciphertext) BETWEEN 1 AND 12288",
            name="access_ciphertext_size",
        ),
        CheckConstraint(
            "octet_length(refresh_token_ciphertext) BETWEEN 1 AND 12288",
            name="refresh_ciphertext_size",
        ),
        CheckConstraint(
            "last_seen_at >= created_at",
            name="last_seen_after_creation",
        ),
        CheckConstraint(
            "idle_expires_at > last_seen_at",
            name="idle_expiry_after_last_seen",
        ),
        CheckConstraint(
            "absolute_expires_at > created_at",
            name="absolute_expiry_after_creation",
        ),
        CheckConstraint(
            "idle_expires_at <= absolute_expires_at",
            name="idle_expiry_within_absolute",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid4,
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("app.user_profiles.id", ondelete="CASCADE"),
        index=True,
    )
    token_hash: Mapped[bytes] = mapped_column(
        LargeBinary,
        unique=True,
    )
    provider_session_id: Mapped[UUID] = mapped_column(
        Uuid,
        unique=True,
    )
    access_token_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    refresh_token_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    access_token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    idle_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )


class OAuthLoginAttempt(Base):
    """Pending browser-bound OAuth attempt; not an authenticated session."""

    __tablename__ = "oauth_login_attempts"
    __table_args__ = (
        CheckConstraint(
            "octet_length(browser_token_hash) = 32",
            name="browser_token_hash_length",
        ),
        CheckConstraint(
            "octet_length(pkce_verifier_ciphertext) BETWEEN 1 AND 1024",
            name="pkce_ciphertext_size",
        ),
        CheckConstraint(
            "provider = 'google'",
            name="provider_google_only",
        ),
        CheckConstraint(
            "purpose = 'sign_in'",
            name="purpose_sign_in_only",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="expiry_after_creation",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid4,
    )
    browser_token_hash: Mapped[bytes] = mapped_column(
        LargeBinary,
        unique=True,
    )
    pkce_verifier_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    provider: Mapped[str] = mapped_column(
        String(16),
        default="google",
    )
    purpose: Mapped[str] = mapped_column(
        String(16),
        default="sign_in",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )


class AuthRateLimit(Base):
    """Recent authentication attempts keyed by a protected client fingerprint."""

    __tablename__ = "auth_rate_limits"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('password_recovery', 'sign_in', 'sign_up', 'email_confirmation', "
            "'password_reset', 'guest_creation', 'google_start')",
            name="purpose_supported_with_google_start",
        ),
        CheckConstraint(
            "octet_length(key_hash) = 32",
            name="key_hash_length",
        ),
        CheckConstraint(
            "cardinality(request_times) <= 1000",
            name="request_times_size",
        ),
        CheckConstraint(
            "cardinality(request_times) = 0 OR "
            "(array_ndims(request_times) = 1 AND "
            "array_lower(request_times, 1) = 1)",
            name="request_times_shape",
        ),
        CheckConstraint(
            "array_position(request_times, NULL) IS NULL",
            name="request_times_no_nulls",
        ),
    )

    purpose: Mapped[str] = mapped_column(
        String(32),
        primary_key=True,
    )
    key_hash: Mapped[bytes] = mapped_column(
        LargeBinary,
        primary_key=True,
    )
    request_times: Mapped[list[datetime]] = mapped_column(
        ARRAY(DateTime(timezone=True), dimensions=1),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )


class VehicleVariant(Base):
    """Verified Mazda 6 configuration; shared catalogue data, read-only at runtime."""

    __tablename__ = "vehicle_variants"
    __table_args__ = (
        # Allowed values mirror the verified data only; widening scope is a migration.
        CheckConstraint(
            "model_year BETWEEN 2018 AND 2021",
            name="model_year_supported",
        ),
        CheckConstraint(
            "market = 'US'",
            name="market_supported",
        ),
        CheckConstraint(
            "engine = '2.5L_I4_SKYACTIV_G'",
            name="engine_supported",
        ),
        CheckConstraint(
            "aspiration IN ('naturally_aspirated', 'turbo')",
            name="aspiration_supported",
        ),
        CheckConstraint(
            "transmission IN ('6AT', '6MT')",
            name="transmission_supported",
        ),
        CheckConstraint(
            "drive = 'FWD'",
            name="drive_supported",
        ),
        CheckConstraint(
            "trim_level IS NULL OR trim_level ~ '^[A-Za-z0-9][A-Za-z0-9 .-]{0,63}$'",
            name="trim_level_format",
        ),
        CheckConstraint(
            "epa_vehicle_id IS NULL OR epa_vehicle_id > 0",
            name="epa_vehicle_id_positive",
        ),
        CheckConstraint(
            "char_length(source_note) BETWEEN 1 AND 200 AND source_note !~ '[[:cntrl:]]'",
            name="source_note_format",
        ),
        # NULLS NOT DISTINCT: two rows with no trim still count as duplicates.
        UniqueConstraint(
            "model_year",
            "market",
            "engine",
            "aspiration",
            "transmission",
            "drive",
            "trim_level",
            name="uq_vehicle_variants_configuration",
            postgresql_nulls_not_distinct=True,
        ),
    )

    # Explicit IDs keep references stable across every environment.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    model_year: Mapped[int] = mapped_column(SmallInteger)
    market: Mapped[str] = mapped_column(String(8))
    engine: Mapped[str] = mapped_column(String(32))
    aspiration: Mapped[str] = mapped_column(String(32))
    transmission: Mapped[str] = mapped_column(String(8))
    drive: Mapped[str] = mapped_column(String(8))
    trim_level: Mapped[str | None] = mapped_column(String(64))
    epa_vehicle_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    source_note: Mapped[str] = mapped_column(String(200))
