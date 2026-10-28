"""create vehicle variants catalogue

Revision ID: c3f1a9d2e7b4
Revises: b4d7e2806a12
Create Date: 2026-10-29

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c3f1a9d2e7b4"
down_revision: str | Sequence[str] | None = "b4d7e2806a12"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENGINE = "2.5L_I4_SKYACTIV_G"
SOURCE_NOTE = "US EPA fueleconomy.gov vehicle record; verified 2026-10-29"

# Every US-market Mazda 6 configuration EPA lists for 2018-2021 (public domain
# data). Trim is not published by a government source, so it stays empty.
VARIANTS = [
    (1, 2018, "naturally_aspirated", "6MT", 39845),
    (2, 2018, "naturally_aspirated", "6AT", 39846),
    (3, 2018, "turbo", "6AT", 39847),
    (4, 2019, "naturally_aspirated", "6MT", 41263),
    (5, 2019, "naturally_aspirated", "6AT", 41264),
    (6, 2019, "turbo", "6AT", 41265),
    (7, 2020, "naturally_aspirated", "6AT", 42304),
    (8, 2020, "turbo", "6AT", 42305),
    (9, 2021, "naturally_aspirated", "6AT", 43300),
    (10, 2021, "turbo", "6AT", 43301),
]


def upgrade() -> None:
    """Create the shared catalogue and seed the verified configurations."""
    table = op.create_table(
        "vehicle_variants",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("model_year", sa.SmallInteger(), nullable=False),
        sa.Column("market", sa.String(8), nullable=False),
        sa.Column("engine", sa.String(32), nullable=False),
        sa.Column("aspiration", sa.String(32), nullable=False),
        sa.Column("transmission", sa.String(8), nullable=False),
        sa.Column("drive", sa.String(8), nullable=False),
        sa.Column("trim_level", sa.String(64), nullable=True),
        sa.Column("epa_vehicle_id", sa.Integer(), nullable=True),
        sa.Column("source_note", sa.String(200), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vehicle_variants")),
        sa.UniqueConstraint("epa_vehicle_id", name=op.f("uq_vehicle_variants_epa_vehicle_id")),
        sa.UniqueConstraint(
            "model_year",
            "market",
            "engine",
            "aspiration",
            "transmission",
            "drive",
            "trim_level",
            name=op.f("uq_vehicle_variants_configuration"),
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(
            "model_year BETWEEN 2018 AND 2021",
            name=op.f("ck_vehicle_variants_model_year_supported"),
        ),
        sa.CheckConstraint(
            "market = 'US'",
            name=op.f("ck_vehicle_variants_market_supported"),
        ),
        sa.CheckConstraint(
            f"engine = '{ENGINE}'",
            name=op.f("ck_vehicle_variants_engine_supported"),
        ),
        sa.CheckConstraint(
            "aspiration IN ('naturally_aspirated', 'turbo')",
            name=op.f("ck_vehicle_variants_aspiration_supported"),
        ),
        sa.CheckConstraint(
            "transmission IN ('6AT', '6MT')",
            name=op.f("ck_vehicle_variants_transmission_supported"),
        ),
        sa.CheckConstraint(
            "drive = 'FWD'",
            name=op.f("ck_vehicle_variants_drive_supported"),
        ),
        sa.CheckConstraint(
            "trim_level IS NULL OR trim_level ~ '^[A-Za-z0-9][A-Za-z0-9 .-]{0,63}$'",
            name=op.f("ck_vehicle_variants_trim_level_format"),
        ),
        sa.CheckConstraint(
            "epa_vehicle_id IS NULL OR epa_vehicle_id > 0",
            name=op.f("ck_vehicle_variants_epa_vehicle_id_positive"),
        ),
        sa.CheckConstraint(
            "char_length(source_note) BETWEEN 1 AND 200 AND source_note !~ '[[:cntrl:]]'",
            name=op.f("ck_vehicle_variants_source_note_format"),
        ),
        schema="app",
    )
    op.bulk_insert(
        table,
        [
            {
                "id": variant_id,
                "model_year": model_year,
                "market": "US",
                "engine": ENGINE,
                "aspiration": aspiration,
                "transmission": transmission,
                "drive": "FWD",
                "trim_level": None,
                "epa_vehicle_id": epa_vehicle_id,
                "source_note": SOURCE_NOTE,
            }
            for variant_id, model_year, aspiration, transmission, epa_vehicle_id in VARIANTS
        ],
    )
    # The website only reads the catalogue; changes go through migrations.
    op.execute("REVOKE ALL ON TABLE app.vehicle_variants FROM PUBLIC")
    op.execute("REVOKE ALL ON TABLE app.vehicle_variants FROM askm6_app")
    op.execute("GRANT SELECT ON TABLE app.vehicle_variants TO askm6_app")


def downgrade() -> None:
    """Drop the catalogue; it holds only reproducible public reference data."""
    op.drop_table("vehicle_variants", schema="app")
