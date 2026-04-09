"""
ZSE Database layer — async operations with asyncpg.
No ORM. Raw SQL. Fast.

Uses FOR UPDATE SKIP LOCKED for the worker queue pattern so multiple
workers never double-process the same scan.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import asyncpg

from app.config import settings

logger = logging.getLogger("zse.database")

# ---------------------------------------------------------------------------
# Connection pool (singleton)
# ---------------------------------------------------------------------------

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Return (and lazily create) the asyncpg connection pool."""
    global _pool
    if _pool is None:
        logger.info("Creating asyncpg connection pool -> %s", settings.DATABASE_URL)
        _pool = await asyncpg.create_pool(
            dsn=settings.DATABASE_URL,
            min_size=2,
            max_size=settings.SCAN_CONCURRENCY + 5,
            command_timeout=60,
        )
    return _pool


async def close_pool() -> None:
    """Gracefully close the pool (call on shutdown)."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed.")


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_url        TEXT NOT NULL,
    branch          TEXT DEFAULT 'main',
    status          TEXT DEFAULT 'queued',
    score           INTEGER,
    score_details   JSONB,
    summary         JSONB,
    progress        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    file_path       TEXT,
    line_number     INTEGER,
    cve_id          TEXT,
    ghsa_id         TEXT,
    fix_version     TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    rule_id         TEXT,
    metadata        JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
"""


async def init_db() -> None:
    """Create tables and indexes if they do not exist."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(_INIT_SQL)
    logger.info("Database schema initialized.")


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------

async def create_scan(repo_url: str, branch: str = "main") -> uuid.UUID:
    """Insert a new scan row and return its UUID."""
    pool = await get_pool()
    scan_id = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scans (id, repo_url, branch, status, created_at)
            VALUES ($1, $2, $3, 'queued', now())
            """,
            scan_id,
            repo_url,
            branch,
        )
    logger.info("Created scan %s for %s@%s", scan_id, repo_url, branch)
    return scan_id


async def update_scan_status(
    scan_id: uuid.UUID,
    status: str,
    progress: Optional[dict] = None,
) -> None:
    """Update scan status and optional progress blob."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if progress is not None:
            await conn.execute(
                """
                UPDATE scans
                SET status = $2,
                    progress = $3::jsonb,
                    started_at = CASE
                        WHEN status = 'queued' AND $2 = 'running' THEN now()
                        ELSE started_at
                    END
                WHERE id = $1
                """,
                scan_id,
                status,
                json.dumps(progress),
            )
        else:
            await conn.execute(
                """
                UPDATE scans
                SET status = $2,
                    started_at = CASE
                        WHEN status = 'queued' AND $2 = 'running' THEN now()
                        ELSE started_at
                    END
                WHERE id = $1
                """,
                scan_id,
                status,
            )


async def store_findings(scan_id: uuid.UUID, findings: list[dict]) -> int:
    """Bulk-insert findings. Returns count inserted."""
    if not findings:
        return 0
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Use executemany for batch insert
        await conn.executemany(
            """
            INSERT INTO findings
                (id, scan_id, type, severity, title, description,
                 file_path, line_number, cve_id, ghsa_id, fix_version,
                 cvss_score, cvss_vector, rule_id, metadata)
            VALUES
                ($1, $2, $3, $4, $5, $6,
                 $7, $8, $9, $10, $11,
                 $12, $13, $14, $15::jsonb)
            """,
            [
                (
                    uuid.uuid4(),
                    scan_id,
                    f["type"],
                    f["severity"],
                    f["title"],
                    f.get("description"),
                    f.get("file_path"),
                    f.get("line"),
                    f.get("cve_id"),
                    f.get("ghsa_id"),
                    f.get("fix_version"),
                    f.get("cvss_score"),
                    f.get("cvss_vector"),
                    f.get("rule_id"),
                    json.dumps(f.get("metadata", {})),
                )
                for f in findings
            ],
        )
    logger.info("Stored %d findings for scan %s", len(findings), scan_id)
    return len(findings)


async def store_score(scan_id: uuid.UUID, score_summary: dict) -> None:
    """Persist the score breakdown."""
    pool = await get_pool()
    overall = score_summary.get("overall", 0)
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE scans
            SET score = $2,
                score_details = $3::jsonb
            WHERE id = $1
            """,
            scan_id,
            overall,
            json.dumps(score_summary),
        )


async def complete_scan(
    scan_id: uuid.UUID,
    score: int,
    summary: dict,
) -> None:
    """Mark a scan as complete with final score and summary."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE scans
            SET status = 'complete',
                score = $2,
                summary = $3::jsonb,
                completed_at = now()
            WHERE id = $1
            """,
            scan_id,
            score,
            json.dumps(summary),
        )
    logger.info("Scan %s completed with score %d", scan_id, score)


async def fail_scan(scan_id: uuid.UUID, error: str) -> None:
    """Mark a scan as failed with an error message."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE scans
            SET status = 'failed',
                error = $2,
                completed_at = now()
            WHERE id = $1
            """,
            scan_id,
            error,
        )
    logger.warning("Scan %s failed: %s", scan_id, error)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    """Convert an asyncpg Record to a plain dict, deserialising JSONB."""
    d = dict(row)
    for key in ("score_details", "summary", "progress", "metadata"):
        if key in d and isinstance(d[key], str):
            d[key] = json.loads(d[key])
    return d


async def get_scan(scan_id: uuid.UUID) -> Optional[dict[str, Any]]:
    """Fetch a single scan row by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
    if row is None:
        return None
    return _row_to_dict(row)


async def get_scan_findings(scan_id: uuid.UUID) -> list[dict[str, Any]]:
    """Fetch all findings for a given scan."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM findings WHERE scan_id = $1 ORDER BY severity, title",
            scan_id,
        )
    return [_row_to_dict(r) for r in rows]


async def list_scans(page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """Return paginated scans (newest first) and total count."""
    pool = await get_pool()
    offset = (page - 1) * per_page
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT count(*) FROM scans")
        rows = await conn.fetch(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            per_page,
            offset,
        )
    return [_row_to_dict(r) for r in rows], total


# ---------------------------------------------------------------------------
# Worker queue — FOR UPDATE SKIP LOCKED
# ---------------------------------------------------------------------------

async def claim_next_job() -> Optional[dict[str, Any]]:
    """Atomically claim the oldest queued scan for processing.

    Uses SELECT ... FOR UPDATE SKIP LOCKED inside a transaction so that
    concurrent workers never pick the same job.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT *
                FROM scans
                WHERE status = 'queued'
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """
            )
            if row is None:
                return None

            scan_id = row["id"]
            await conn.execute(
                """
                UPDATE scans
                SET status = 'running', started_at = now()
                WHERE id = $1
                """,
                scan_id,
            )
    logger.info("Worker claimed scan %s", scan_id)
    return _row_to_dict(row)
