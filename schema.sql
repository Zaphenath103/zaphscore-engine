-- =============================================================================
-- ZSE — Zaphenath Security Engine — Database Schema
-- =============================================================================
-- Run this against your PostgreSQL database to initialise the tables.
-- In docker-compose it is mounted into /docker-entrypoint-initdb.d/ and runs
-- automatically on first container start.
-- =============================================================================

-- Enable uuid generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- Scans — one row per security scan job
-- ---------------------------------------------------------------------------
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
    error           TEXT,
    github_token    TEXT,          -- encrypted PAT for private repos (optional)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

-- Index for the worker queue — claim next queued job efficiently
CREATE INDEX IF NOT EXISTS idx_scans_status
    ON scans (status, created_at ASC)
    WHERE status = 'queued';

-- Index for listing scans by creation date
CREATE INDEX IF NOT EXISTS idx_scans_created_at
    ON scans (created_at DESC);

-- ---------------------------------------------------------------------------
-- Findings — individual security findings linked to a scan
-- ---------------------------------------------------------------------------
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
    line            INTEGER,
    cve_id          TEXT,
    ghsa_id         TEXT,
    fix_version     TEXT,
    cvss_score      DOUBLE PRECISION CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0.0 AND 10.0),
    cvss_vector     TEXT,
    rule_id         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup of all findings for a scan
CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings (scan_id);

-- Severity distribution queries
CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (scan_id, severity);
