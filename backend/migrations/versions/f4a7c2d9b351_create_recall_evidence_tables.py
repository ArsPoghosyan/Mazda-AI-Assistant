"""create recall evidence tables

Revision ID: f4a7c2d9b351
Revises: d8e2b6c4a1f9
Create Date: 2026-10-29

"""

import datetime
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f4a7c2d9b351"
down_revision: str | Sequence[str] | None = "d8e2b6c4a1f9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("evidence_sources", "recall_campaigns", "recall_applicability")
TEXT_RULE = "char_length({column}) BETWEEN 1 AND {limit} AND {column} !~ '[[:cntrl:]]'"
HTTPS_RULE = "{column} ~ '^https://[^[:space:][:cntrl:]]+$'"


def text_rule(column: str, limit: int) -> str:
    return TEXT_RULE.format(column=column, limit=limit)


def upgrade() -> None:
    """Create the recall evidence layer and register NHTSA as its first source."""
    sources = op.create_table(
        "evidence_sources",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("publisher", sa.String(120), nullable=False),
        sa.Column("url", sa.String(300), nullable=False),
        sa.Column("terms_url", sa.String(300), nullable=False),
        sa.Column("terms_note", sa.String(300), nullable=False),
        sa.Column("terms_checked_on", sa.Date(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_sources")),
        sa.UniqueConstraint("slug", name=op.f("uq_evidence_sources_slug")),
        sa.CheckConstraint(
            "slug ~ '^[a-z0-9][a-z0-9_]{0,63}$'",
            name=op.f("ck_evidence_sources_slug_format"),
        ),
        sa.CheckConstraint(text_rule("name", 120), name=op.f("ck_evidence_sources_name_format")),
        sa.CheckConstraint(
            text_rule("publisher", 120),
            name=op.f("ck_evidence_sources_publisher_format"),
        ),
        sa.CheckConstraint(
            HTTPS_RULE.format(column="url"),
            name=op.f("ck_evidence_sources_url_https"),
        ),
        sa.CheckConstraint(
            HTTPS_RULE.format(column="terms_url"),
            name=op.f("ck_evidence_sources_terms_url_https"),
        ),
        sa.CheckConstraint(
            text_rule("terms_note", 300),
            name=op.f("ck_evidence_sources_terms_note_format"),
        ),
        schema="app",
    )
    op.create_table(
        "recall_campaigns",
        sa.Column("id", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("campaign_number", sa.String(9), nullable=False),
        sa.Column("report_received_on", sa.Date(), nullable=False),
        sa.Column("manufacturer", sa.String(120), nullable=False),
        sa.Column("component", sa.String(300), nullable=False),
        sa.Column("summary", sa.String(4000), nullable=False),
        sa.Column("consequence", sa.String(2000), nullable=False),
        sa.Column("remedy", sa.String(2000), nullable=False),
        sa.Column("notes", sa.String(2000), nullable=True),
        sa.Column("park_it", sa.Boolean(), nullable=False),
        sa.Column("park_outside", sa.Boolean(), nullable=False),
        sa.Column("over_the_air_update", sa.Boolean(), nullable=False),
        sa.Column("record_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recall_campaigns")),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["app.evidence_sources.id"],
            name=op.f("fk_recall_campaigns_source_id_evidence_sources"),
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "source_id",
            "campaign_number",
            name=op.f("uq_recall_campaigns_source_campaign"),
        ),
        sa.CheckConstraint(
            "campaign_number ~ '^[0-9]{2}V[0-9]{6}$'",
            name=op.f("ck_recall_campaigns_campaign_number_format"),
        ),
        sa.CheckConstraint(
            text_rule("manufacturer", 120),
            name=op.f("ck_recall_campaigns_manufacturer_format"),
        ),
        sa.CheckConstraint(
            text_rule("component", 300),
            name=op.f("ck_recall_campaigns_component_format"),
        ),
        sa.CheckConstraint(
            text_rule("summary", 4000),
            name=op.f("ck_recall_campaigns_summary_format"),
        ),
        sa.CheckConstraint(
            text_rule("consequence", 2000),
            name=op.f("ck_recall_campaigns_consequence_format"),
        ),
        sa.CheckConstraint(
            text_rule("remedy", 2000),
            name=op.f("ck_recall_campaigns_remedy_format"),
        ),
        sa.CheckConstraint(
            f"notes IS NULL OR ({text_rule('notes', 2000)})",
            name=op.f("ck_recall_campaigns_notes_format"),
        ),
        sa.CheckConstraint(
            "octet_length(record_sha256) = 32",
            name=op.f("ck_recall_campaigns_record_sha256_length"),
        ),
        sa.CheckConstraint(
            "first_seen_at <= content_updated_at AND content_updated_at <= last_seen_at",
            name=op.f("ck_recall_campaigns_seen_times_ordered"),
        ),
        schema="app",
    )
    op.create_table(
        "recall_applicability",
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("make", sa.String(16), nullable=False),
        sa.Column("model", sa.String(16), nullable=False),
        sa.Column("model_year", sa.SmallInteger(), nullable=False),
        sa.PrimaryKeyConstraint(
            "campaign_id",
            "make",
            "model",
            "model_year",
            name=op.f("pk_recall_applicability"),
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["app.recall_campaigns.id"],
            name=op.f("fk_recall_applicability_campaign_id_recall_campaigns"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("make = 'MAZDA'", name=op.f("ck_recall_applicability_make_supported")),
        sa.CheckConstraint(
            "model = 'MAZDA6'",
            name=op.f("ck_recall_applicability_model_supported"),
        ),
        sa.CheckConstraint(
            "model_year BETWEEN 2018 AND 2021",
            name=op.f("ck_recall_applicability_model_year_supported"),
        ),
        schema="app",
    )
    op.bulk_insert(
        sources,
        [
            {
                "id": 1,
                "slug": "nhtsa_recalls",
                "name": "NHTSA recalls API",
                "publisher": "US National Highway Traffic Safety Administration",
                "url": "https://api.nhtsa.gov/recalls/recallsByVehicle",
                "terms_url": "https://www.nhtsa.gov/about-nhtsa/terms-use",
                "terms_note": (
                    "Public information that may be distributed or copied; "
                    "no accuracy warranty; not a per-VIN recall check"
                ),
                "terms_checked_on": datetime.date(2026, 10, 29),
            }
        ],
    )
    # The website only reads evidence; ingestion writes it as the owner role.
    for table in TABLES:
        op.execute(f"REVOKE ALL ON TABLE app.{table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON TABLE app.{table} FROM askm6_app")
        op.execute(f"GRANT SELECT ON TABLE app.{table} TO askm6_app")


def downgrade() -> None:
    """Drop the evidence layer; it holds only re-ingestible public data."""
    for table in reversed(TABLES):
        op.drop_table(table, schema="app")
