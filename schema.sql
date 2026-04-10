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

-- ---------------------------------------------------------------------------
-- D-718: SOC2 Immutable Audit Log
-- INSERT-only table -- no UPDATE or DELETE should ever be issued.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          TEXT NOT NULL,
    actor_id        TEXT,
    actor_email     TEXT,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    client_ip       TEXT NOT NULL DEFAULT 'unknown',
    metadata        JSONB NOT NULL DEFAULT '{}',
    chain_hash      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_resource_id
    ON audit_log (resource_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id
    ON audit_log (actor_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- D-722: SOC2 Immutable Finding Suppression Log
-- INSERT-only table -- suppressions are never deleted, only expired.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppression_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      TEXT NOT NULL,
    scan_id         TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    actor_email     TEXT NOT NULL,
    reason          TEXT NOT NULL,
    justification   TEXT NOT NULL,
    client_ip       TEXT NOT NULL DEFAULT 'unknown',
    chain_hash      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_suppression_log_finding_id
    ON suppression_log (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_suppression_log_actor_id
    ON suppression_log (actor_id, created_at DESC);
