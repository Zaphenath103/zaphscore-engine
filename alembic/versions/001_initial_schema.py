"""Initial schema migration — scans and findings tables.

Revision ID: 001_initial
Revises: None
Create Date: 2026-04-10

Safe baseline: uses CREATE IF NOT EXISTS so running on existing DB is a no-op.
"""
from __future__ import annotations
from alembic import op

revision: str = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        op.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                repo_url        TEXT        NOT NULL,
                branch          TEXT,
                status          TEXT        NOT NULL DEFAULT 'queued'
                                    CHECK (status IN ('queued', 'running', 'complete', 'failed')),
                current_phase   TEXT,
                progress_pct    INTEGER     DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
                score           INTEGER     CHECK (score IS NULL OR score BETWEEN 0 AND 100),
                score_details   JSONB,
                summary         JSONB,
                progress        JSONB,
                findings_encrypted TEXT,
                error           TEXT,
                github_token    TEXT,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                started_at      TIMESTAMPTZ,
                completed_at    TIMESTAMPTZ
            )
        """)
        op.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                scan_id         UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                type            TEXT        NOT NULL DEFAULT 'vulnerability'
                                    CHECK (type IN ('vulnerability', 'sast', 'secret', 'iac', 'license')),
                severity        TEXT        NOT NULL DEFAULT 'info'
                                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
                title           TEXT        NOT NULL,
                description     TEXT,
                file_path       TEXT,
                line_number     INTEGER,
                cve_id          TEXT,
                ghsa_id         TEXT,
                fix_version     TEXT,
                cvss_score      DOUBLE PRECISION,
                cvss_vector     TEXT,
                rule_id         TEXT,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
    else:
        # SQLite
        op.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, repo_url TEXT NOT NULL, branch TEXT,
                status TEXT NOT NULL DEFAULT 'queued', current_phase TEXT,
                progress_pct INTEGER DEFAULT 0, score INTEGER,
                score_details TEXT, summary TEXT, progress TEXT,
                findings_encrypted TEXT, error TEXT, github_token TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                started_at TEXT, completed_at TEXT
            )
        """)
        op.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                type TEXT NOT NULL DEFAULT 'vulnerability', severity TEXT NOT NULL DEFAULT 'info',
                title TEXT NOT NULL, description TEXT, file_path TEXT, line_number INTEGER,
                cve_id TEXT, ghsa_id TEXT, fix_version TEXT, cvss_score REAL,
                cvss_vector TEXT, rule_id TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            )
        """)

    op.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (scan_id, severity)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS findings")
    op.execute("DROP TABLE IF EXISTS scans")
