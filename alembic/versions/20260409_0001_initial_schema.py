"""Initial schema — scans and findings tables.

D-059: First Alembic migration. Derived from schema.sql.
Supports both PostgreSQL (production) and SQLite (development).

Revision ID: 0001
Revises:
Create Date: 2026-04-09 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgres() -> bool:
    """Detect if running against PostgreSQL (vs SQLite)."""
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    """Create scans and findings tables with all indexes."""

    # PostgreSQL-only extension for UUID generation
    if _is_postgres():
        op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # --- scans table ---
    # UUID primary key — use server_default appropriate for each DB dialect
    if _is_postgres():
        scans_pk = sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("uuid_generate_v4()"),
            nullable=False,
        )
    else:
        # SQLite: store UUID as TEXT
        scans_pk = sa.Column(
            "id",
            sa.String(36),
            primary_key=True,
            nullable=False,
        )

    op.create_table(
        "scans",
        scans_pk,
        sa.Column("repo_url", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=True),
        sa.Column(
            "status",
            sa.Text,
            nullable=False,
            server_default="queued",
        ),
        sa.Column("current_phase", sa.Text, nullable=True),
        sa.Column("progress_pct", sa.Integer, server_default="0", nullable=True),
        sa.Column("score", sa.Integer, nullable=True),
        sa.Column("score_details", sa.Text, nullable=True),  # JSONB in PG, TEXT in SQLite
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("progress", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("github_token", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    # Status index for worker queue — claim next queued job efficiently
    op.create_index(
        "idx_scans_status",
        "scans",
        ["status", "created_at"],
    )

    # Creation date index for listing scans newest-first
    op.create_index(
        "idx_scans_created_at",
        "scans",
        ["created_at"],
    )

    # --- findings table ---
    if _is_postgres():
        findings_pk = sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("uuid_generate_v4()"),
            nullable=False,
        )
        findings_scan_fk = sa.Column(
            "scan_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        )
    else:
        findings_pk = sa.Column("id", sa.String(36), primary_key=True, nullable=False)
        findings_scan_fk = sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        )

    op.create_table(
        "findings",
        findings_pk,
        findings_scan_fk,
        sa.Column("type", sa.Text, nullable=False, server_default="vulnerability"),
        sa.Column("severity", sa.Text, nullable=False, server_default="info"),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("line_number", sa.Integer, nullable=True),
        sa.Column("cve_id", sa.Text, nullable=True),
        sa.Column("ghsa_id", sa.Text, nullable=True),
        sa.Column("fix_version", sa.Text, nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.Text, nullable=True),
        sa.Column("rule_id", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    op.create_index("idx_findings_scan_id", "findings", ["scan_id"])
    op.create_index("idx_findings_severity", "findings", ["scan_id", "severity"])


def downgrade() -> None:
    """Drop findings and scans tables (in FK-safe order)."""
    op.drop_index("idx_findings_severity", table_name="findings")
    op.drop_index("idx_findings_scan_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("idx_scans_created_at", table_name="scans")
    op.drop_index("idx_scans_status", table_name="scans")
    op.drop_table("scans")
