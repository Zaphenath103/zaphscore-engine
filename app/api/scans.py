"""
ZSE Scan API — submit scans, query results, stream progress via SSE.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from starlette.responses import StreamingResponse

from app.api.deps import CurrentUser
from app.models import database as db
from app.models.schemas import (
    Finding,
    FindingType,
    PaginatedScans,
    ScanPhase,
    ScanProgress,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanStatus,
    ScanSummary,
    ScoreSummary,
    Severity,
)

logger = logging.getLogger("zse.api.scans")
router = APIRouter(prefix="/api/scans", tags=["scans"])

# ---------------------------------------------------------------------------
# Simple in-memory rate limiter: max 10 scans per IP per minute
# ---------------------------------------------------------------------------
_RATE_LIMIT_MAX = 10
_RATE_LIMIT_WINDOW = 60  # seconds
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str) -> None:
    """Raise 429 if the client has exceeded the scan submission rate limit."""
    now = time.time()
    timestamps = _rate_limit_store[client_ip]
    # Prune timestamps outside the window
    _rate_limit_store[client_ip] = [t for t in timestamps if now - t < _RATE_LIMIT_WINDOW]
    if len(_rate_limit_store[client_ip]) >= _RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {_RATE_LIMIT_MAX} scans per {_RATE_LIMIT_WINDOW}s. Try again later.",
        )
    _rate_limit_store[client_ip].append(now)


# ---------------------------------------------------------------------------
# POST /api/scans — submit a new scan
# ---------------------------------------------------------------------------

async def _run_scan_background(scan_id: uuid.UUID, repo_url: str, branch: str) -> None:
    """Execute scan immediately — used as FastAPI BackgroundTask so scans run
    even on Vercel serverless where the poll-loop worker may not be alive."""
    try:
        from app.workers.scan_worker import _execute_scan  # type: ignore[attr-defined]
        await _execute_scan(scan_id, repo_url, branch)
    except Exception as exc:
        logger.error("Background scan task failed: %s", exc, exc_info=True)
        try:
            await db.fail_scan(scan_id, error=str(exc))
        except Exception:
            pass


@router.post("", response_model=ScanResponse, status_code=201)
async def submit_scan(
    body: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser,  # D-003: auth gate — 401 if no valid JWT
) -> ScanResponse:
    """Queue a new security scan for a GitHub repository.

    Requires a valid Supabase JWT in the Authorization: Bearer header.
    Unauthenticated requests are rejected with HTTP 401 before any pipeline runs.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    branch = body.branch or "main"
    scan_id = await db.create_scan(repo_url=body.repo_url, branch=branch)

    logger.info("Scan queued: %s -> %s@%s", scan_id, body.repo_url, branch)

    # Trigger scan immediately via BackgroundTasks — critical for Vercel serverless
    # where the background worker poll loop may not be running between requests.
    background_tasks.add_task(_run_scan_background, scan_id, body.repo_url, branch)

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.queued,
        created_at=datetime.now(timezone.utc),
        stream_url=f"/api/scans/{scan_id}/stream",
    )


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id} — get scan status + results
# ---------------------------------------------------------------------------

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: uuid.UUID, current_user: CurrentUser) -> ScanResult:
    """Return the full scan record, including findings if the scan is complete.

    D-066: Requires authentication — scan results contain security findings
    that must not be exposed to unauthenticated callers.
    """
    row = await db.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = await db.get_scan_findings(scan_id)
    findings = [
        Finding(
            id=f["id"],
            type=FindingType(f["type"]),
            severity=Severity(f["severity"]),
            title=f["title"],
            description=f.get("description"),
            file_path=f.get("file_path"),
            line=f.get("line_number"),
            cve_id=f.get("cve_id"),
            ghsa_id=f.get("ghsa_id"),
            fix_version=f.get("fix_version"),
            cvss_score=f.get("cvss_score"),
            cvss_vector=f.get("cvss_vector"),
            rule_id=f.get("rule_id"),
        )
        for f in findings_rows
    ]

    score_details = None
    if row.get("score_details"):
        score_details = ScoreSummary(**row["score_details"])

    summary = None
    if row.get("summary"):
        summary = ScanSummary(**row["summary"])

    return ScanResult(
        scan_id=row["id"],
        status=ScanStatus(row["status"]),
        repo_url=row["repo_url"],
        branch=row.get("branch"),
        score=row.get("score"),
        score_details=score_details,
        findings=findings,
        summary=summary,
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        error=row.get("error"),
    )


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/stream — SSE progress stream
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/stream")
async def stream_scan_progress(scan_id: uuid.UUID, request: Request, current_user: CurrentUser):
    """Server-Sent Events endpoint that streams scan progress in real time.

    D-066: Requires authentication — progress stream reveals repo structure and
    vulnerability details during active scans.


    The client connects once and receives JSON events like:
        data: {"phase": "cloning", "progress_pct": 10, "message": "Cloning repo..."}

    The stream closes automatically when the scan reaches 'complete' or 'failed'.
    """

    async def event_generator():
        last_progress: dict = {}
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                logger.debug("SSE client disconnected for scan %s", scan_id)
                break

            row = await db.get_scan(scan_id)
            if row is None:
                yield f"event: error\ndata: {json.dumps({'error': 'Scan not found'})}\n\n"
                break

            status = row["status"]
            progress = row.get("progress") or {}

            # Only emit when progress actually changes
            if progress != last_progress:
                phase = progress.get("phase", "queued")
                pct = progress.get("progress_pct", 0)
                msg = progress.get("message", f"Status: {status}")

                event_data = ScanProgress(
                    phase=ScanPhase(phase) if phase in ScanPhase.__members__ else ScanPhase.cloning,
                    progress_pct=pct,
                    message=msg,
                )
                yield f"event: progress\ndata: {event_data.model_dump_json()}\n\n"
                last_progress = progress

            # Terminal states — send final event and close
            if status == "complete":
                final = {
                    "phase": "complete",
                    "progress_pct": 100,
                    "message": f"Scan complete. Score: {row.get('score', 'N/A')}/100",
                    "score": row.get("score"),
                }
                yield f"event: complete\ndata: {json.dumps(final)}\n\n"
                break

            if status == "failed":
                yield f"event: error\ndata: {json.dumps({'error': row.get('error', 'Unknown error')})}\n\n"
                break

            # Poll interval — 1 second is fast enough for UX, light on DB
            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------------------
# GET /api/scans — list recent scans (paginated)
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedScans)
async def list_scans(
    current_user: CurrentUser,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
) -> PaginatedScans:
    """Return a paginated list of scans, newest first.

    D-066: Requires authentication — scan list reveals repo URLs and security scores
    which must not be enumerable by unauthenticated callers.
    """
    items_raw, total = await db.list_scans(page=page, per_page=per_page)

    items = []
    for row in items_raw:
        score_details = None
        if row.get("score_details"):
            score_details = ScoreSummary(**row["score_details"])
        summary = None
        if row.get("summary"):
            summary = ScanSummary(**row["summary"])

        items.append(
            ScanResult(
                scan_id=row["id"],
                status=ScanStatus(row["status"]),
                repo_url=row["repo_url"],
                branch=row.get("branch"),
                score=row.get("score"),
                score_details=score_details,
                findings=[],  # List view omits findings for performance
                summary=summary,
                created_at=row["created_at"],
                started_at=row.get("started_at"),
                completed_at=row.get("completed_at"),
                error=row.get("error"),
            )
        )

    return PaginatedScans(items=items, total=total, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# GET /api/admin/queue — D-065: Scan queue depth metric (admin only)
# ---------------------------------------------------------------------------

admin_router = APIRouter(prefix="/api/admin", tags=["admin"])


def _is_admin(current_user: dict) -> bool:
    """Check if user has admin JWT claim."""
    app_meta = current_user.get("app_metadata", {}) or {}
    user_meta = current_user.get("user_metadata", {}) or {}
    role = (
        app_meta.get("role")
        or user_meta.get("role")
        or current_user.get("role")
        or ""
    ).lower()
    return role in ("admin", "superadmin", "service_role")


@admin_router.get("/queue")
async def get_queue_depth(current_user: CurrentUser):
    """D-065: Admin-only scan queue metrics.

    Returns pending/running counts, today's completions, average duration,
    and the age of the oldest pending scan — without reading the DB directly.

    Requires role=admin in JWT app_metadata.
    """
    if not _is_admin(current_user):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail="Admin role required. Set app_metadata.role=admin in Supabase.",
        )

    from datetime import datetime, timezone, timedelta
    import time

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        # Fetch all scans for today to compute metrics
        items_raw, total = await db.list_scans(page=1, per_page=500)

        pending = 0
        running = 0
        done_today = 0
        durations: list[float] = []
        oldest_pending_created: float | None = None

        for row in items_raw:
            status = row.get("status", "")
            created_raw = row.get("created_at")
            started_raw = row.get("started_at")
            completed_raw = row.get("completed_at")

            if status == "queued":
                pending += 1
                # Track oldest pending
                if created_raw:
                    try:
                        if isinstance(created_raw, str):
                            dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                        else:
                            dt = created_raw
                        age = (now - dt).total_seconds()
                        if oldest_pending_created is None or age > oldest_pending_created:
                            oldest_pending_created = age
                    except Exception:
                        pass

            elif status == "running":
                running += 1

            elif status == "complete" and completed_raw:
                try:
                    if isinstance(completed_raw, str):
                        completed_dt = datetime.fromisoformat(completed_raw.replace("Z", "+00:00"))
                    else:
                        completed_dt = completed_raw
                    if completed_dt >= today_start:
                        done_today += 1

                    # Compute duration if both started_at and completed_at available
                    if started_raw:
                        if isinstance(started_raw, str):
                            started_dt = datetime.fromisoformat(started_raw.replace("Z", "+00:00"))
                        else:
                            started_dt = started_raw
                        duration = (completed_dt - started_dt).total_seconds()
                        if duration > 0:
                            durations.append(duration)
                except Exception:
                    pass

        avg_duration = round(sum(durations) / len(durations), 1) if durations else 0.0

        return {
            "pending": pending,
            "running": running,
            "done_today": done_today,
            "avg_duration_s": avg_duration,
            "oldest_pending_age_s": round(oldest_pending_created, 0) if oldest_pending_created else 0,
            "total_scans": total,
            "computed_at": now.isoformat(),
        }

    except Exception as exc:
        logger.error("Queue depth metric error: %s", exc)
        return {
            "pending": -1,
            "running": -1,
            "done_today": -1,
            "avg_duration_s": 0,
            "oldest_pending_age_s": 0,
            "error": str(exc),
        }
