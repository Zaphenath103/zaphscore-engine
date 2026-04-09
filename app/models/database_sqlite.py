"""ZSE Database — SQLite fallback for local development and demos.

Drop-in replacement for database.py (asyncpg/Postgres). Uses aiosqlite
so the server can run tonight without a Postgres instance. All public
functions match the exact same interface as the Postgres module.

Database file: ./zse_data.db
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from app.config import settings

logger = logging.getLogger("zse.database.sqlite")

# ---------------------------------------------------------------------------
# Connection (singleton)
# ---------------------------------------------------------------------------

# On Vercel, only /tmp is writable. Locally, use current directory.
_DB_PATH = Path("/tmp/zse_data.db") if os.environ.get("VERCEL") else Path("./zse_data.db")
_conn: Optional[aiosqlite.Connection] = None


async def get_pool() -> aiosqlite.Connection:
    """Return (and lazily create) the aiosqlite connection.

    Named ``get_pool`` for interface compatibility with the asyncpg module.
    """
    global _conn
    if _conn is None:
        logger.info("Opening SQLite database -> %s", _DB_PATH.resolve())
        _conn = await aiosqlite.connect(str(_DB_PATH))
        _conn.row_factory = aiosqlite.Row
        await _conn.execute("PRAGMA journal_mode=WAL")
        await _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


async def close_pool() -> None:
    """Gracefully close the connection (call on shutdown)."""
    global _conn
    if _conn is not None:
        await _conn.close()
        _conn = None
        logger.info("SQLite connection closed.")


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    repo_url        TEXT NOT NULL,
    branch          TEXT DEFAULT 'main',
    status          TEXT DEFAULT 'queued',
    score           INTEGER,
    score_details   TEXT DEFAULT '{}',
    summary         TEXT DEFAULT '{}',
    progress        TEXT DEFAULT '{}',
    created_at      TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
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
    metadata        TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
"""


async def init_db() -> None:
    """Create tables and indexes if they do not exist."""
    conn = await get_pool()
    await conn.executescript(_INIT_SQL)
    await conn.commit()
    logger.info("SQLite schema initialized at %s", _DB_PATH.resolve())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    """Convert an aiosqlite Row to a plain dict, deserialising JSON fields."""
    d = dict(row)
    for key in ("score_details", "summary", "progress", "metadata"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    # Convert UUID string ID to uuid.UUID for compatibility
    if "id" in d and isinstance(d["id"], str):
        try:
            d["id"] = uuid.UUID(d["id"])
        except ValueError:
            pass
    if "scan_id" in d and isinstance(d["scan_id"], str):
        try:
            d["scan_id"] = uuid.UUID(d["scan_id"])
        except ValueError:
            pass
    return d


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------

async def create_scan(repo_url: str, branch: str = "main") -> uuid.UUID:
    """Insert a new scan row and return its UUID."""
    conn = await get_pool()
    scan_id = uuid.uuid4()
    await conn.execute(
        """
        INSERT INTO scans (id, repo_url, branch, status, created_at)
        VALUES (?, ?, ?, 'queued', ?)
        """,
        (str(scan_id), repo_url, branch, _now_iso()),
    )
    await conn.commit()
    logger.info("Created scan %s for %s@%s", scan_id, repo_url, branch)
    return scan_id


async def update_scan_status(
    scan_id: uuid.UUID,
    status: str,
    progress: Optional[dict] = None,
) -> None:
    """Update scan status and optional progress blob."""
    conn = await get_pool()
    sid = str(scan_id)

    if progress is not None:
        # Fetch current status to decide whether to set started_at
        cursor = await conn.execute(
            "SELECT status FROM scans WHERE id = ?", (sid,)
        )
        row = await cursor.fetchone()
        started_update = ""
        if row and row["status"] == "queued" and status == "running":
            started_update = f", started_at = '{_now_iso()}'"

        await conn.execute(
            f"""
            UPDATE scans
            SET status = ?, progress = ?{started_update}
            WHERE id = ?
            """,
            (status, json.dumps(progress), sid),
        )
    else:
        cursor = await conn.execute(
            "SELECT status FROM scans WHERE id = ?", (sid,)
        )
        row = await cursor.fetchone()
        started_update = ""
        if row and row["status"] == "queued" and status == "running":
            started_update = f", started_at = '{_now_iso()}'"

        await conn.execute(
            f"""
            UPDATE scans
            SET status = ?{started_update}
            WHERE id = ?
            """,
            (status, sid),
        )
    await conn.commit()


async def store_findings(scan_id: uuid.UUID, findings: list[dict]) -> int:
    """Bulk-insert findings. Returns count inserted."""
    if not findings:
        return 0
    conn = await get_pool()
    sid = str(scan_id)
    rows = [
        (
            str(uuid.uuid4()),
            sid,
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
    ]
    await conn.executemany(
        """
        INSERT INTO findings
            (id, scan_id, type, severity, title, description,
             file_path, line_number, cve_id, ghsa_id, fix_version,
             cvss_score, cvss_vector, rule_id, metadata)
        VALUES
            (?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?,
             ?, ?, ?, ?)
        """,
        rows,
    )
    await conn.commit()
    logger.info("Stored %d findings for scan %s", len(findings), scan_id)
    return len(findings)


async def store_score(scan_id: uuid.UUID, score_summary: dict) -> None:
    """Persist the score breakdown."""
    conn = await get_pool()
    overall = score_summary.get("overall", 0)
    await conn.execute(
        """
        UPDATE scans
        SET score = ?, score_details = ?
        WHERE id = ?
        """,
        (overall, json.dumps(score_summary), str(scan_id)),
    )
    await conn.commit()


async def complete_scan(
    scan_id: uuid.UUID,
    score: int,
    summary: dict,
) -> None:
    """Mark a scan as complete with final score and summary."""
    conn = await get_pool()
    await conn.execute(
        """
        UPDATE scans
        SET status = 'complete',
            score = ?,
            summary = ?,
            completed_at = ?
        WHERE id = ?
        """,
        (score, json.dumps(summary), _now_iso(), str(scan_id)),
    )
    await conn.commit()
    logger.info("Scan %s completed with score %d", scan_id, score)


async def fail_scan(scan_id: uuid.UUID, error: str) -> None:
    """Mark a scan as failed with an error message."""
    conn = await get_pool()
    await conn.execute(
        """
        UPDATE scans
        SET status = 'failed',
            error = ?,
            completed_at = ?
        WHERE id = ?
        """,
        (error, _now_iso(), str(scan_id)),
    )
    await conn.commit()
    logger.warning("Scan %s failed: %s", scan_id, error)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

async def get_scan(scan_id: uuid.UUID) -> Optional[dict[str, Any]]:
    """Fetch a single scan row by ID."""
    conn = await get_pool()
    cursor = await conn.execute(
        "SELECT * FROM scans WHERE id = ?", (str(scan_id),)
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


async def get_scan_findings(scan_id: uuid.UUID) -> list[dict[str, Any]]:
    """Fetch all findings for a given scan."""
    conn = await get_pool()
    cursor = await conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, title",
        (str(scan_id),),
    )
    rows = await cursor.fetchall()
    return [_row_to_dict(r) for r in rows]


async def list_scans(page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """Return paginated scans (newest first) and total count."""
    conn = await get_pool()
    offset = (page - 1) * per_page

    cursor = await conn.execute("SELECT count(*) as cnt FROM scans")
    count_row = await cursor.fetchone()
    total = count_row["cnt"] if count_row else 0

    cursor = await conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    )
    rows = await cursor.fetchall()
    return [_row_to_dict(r) for r in rows], total


# ---------------------------------------------------------------------------
# Worker queue
# ---------------------------------------------------------------------------

async def claim_next_job() -> Optional[dict[str, Any]]:
    """Atomically claim the oldest queued scan for processing.

    SQLite does not support FOR UPDATE SKIP LOCKED, but since we only
    run a single worker in local/demo mode this simple UPDATE is safe.
    """
    conn = await get_pool()

    # Find the oldest queued scan
    cursor = await conn.execute(
        """
        SELECT * FROM scans
        WHERE status = 'queued'
        ORDER BY created_at ASC
        LIMIT 1
        """
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    scan_id = row["id"]

    # Claim it
    await conn.execute(
        """
        UPDATE scans
        SET status = 'running', started_at = ?
        WHERE id = ? AND status = 'queued'
        """,
        (_now_iso(), scan_id),
    )
    await conn.commit()

    logger.info("Worker claimed scan %s", scan_id)
    return _row_to_dict(row)
