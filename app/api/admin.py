"""
D-065: Admin API endpoints — queue depth metrics and operational visibility.

Endpoints:
    GET /api/admin/queue — real-time queue depth metrics (admin JWT required)

The queue endpoint lets the factory know if the worker is backed up without
reading the DB directly. Returns pending/running counts, daily completions,
average duration, and oldest pending age.

Authentication: requires a valid JWT with admin=true claim (or role=admin).
Non-admin authenticated users receive HTTP 403.
Unauthenticated requests receive HTTP 401.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.api.deps import CurrentUser, get_current_user
from app.models import database as db

logger = logging.getLogger("zse.api.admin")

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Admin access guard
# ---------------------------------------------------------------------------

async def _require_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Dependency: ensure the authenticated user has admin privileges.

    Checks:
    1. JWT claim `admin=true` (top-level)
    2. JWT claim `role=admin` (top-level or in app_metadata)
    3. JWT claim `app_metadata.role=admin`

    Raises HTTP 403 if the user is authenticated but not an admin.
    HTTP 401 is raised by get_current_user if the token is missing/invalid.
    """
    is_admin = (
        user.get("admin") is True
        or user.get("role") == "admin"
        or user.get("app_metadata", {}).get("role") == "admin"
        or user.get("app_metadata", {}).get("admin") is True
    )
    if not is_admin:
        logger.warning(
            "Non-admin user attempted admin queue access: sub=%s",
            user.get("sub", "unknown"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return user


AdminUser = CurrentUser  # type alias — admin check is via Depends below


# ---------------------------------------------------------------------------
# GET /api/admin/queue
# ---------------------------------------------------------------------------

@router.get("/queue")
async def get_queue_metrics(
    _admin: dict = Depends(_require_admin),
) -> JSONResponse:
    """Return real-time queue depth and worker health metrics.

    Response schema:
    {
        "pending": int,          # scans in 'queued' status
        "running": int,          # scans in 'running' status
        "done_today": int,       # scans completed in the last 24h
        "failed_today": int,     # scans failed in the last 24h
        "avg_duration_s": float, # average scan duration (complete scans, last 24h)
        "oldest_pending_age_s": float | null,  # age of oldest queued scan in seconds
        "total_scans": int,      # all-time scan count
        "timestamp": str,        # ISO 8601 UTC timestamp of this response
    }

    Used by Railway/Vercel health probes and the ZaphLabs monitoring dashboard.
    """
    now_utc = datetime.now(timezone.utc)
    now_ts = now_utc.isoformat()

    metrics: dict[str, Any] = {
        "pending": 0,
        "running": 0,
        "done_today": 0,
        "failed_today": 0,
        "avg_duration_s": None,
        "oldest_pending_age_s": None,
        "total_scans": 0,
        "timestamp": now_ts,
    }

    try:
        # Fetch all scans (paginated internally — we get page 1, large per_page)
        # For a production queue with millions of scans this would need a dedicated
        # DB query; for now list_scans is sufficient (expected volume: < 10K/day).
        rows, total = await db.list_scans(page=1, per_page=1000)
        metrics["total_scans"] = total

        pending_rows = []
        durations: list[float] = []
        now_epoch = time.time()
        cutoff_24h = now_epoch - 86400

        for row in rows:
            s = row.get("status", "")

            if s == "queued":
                metrics["pending"] += 1
                pending_rows.append(row)

            elif s == "running":
                metrics["running"] += 1

            elif s == "complete":
                # Count completions in last 24h
                completed_at = row.get("completed_at")
                if completed_at:
                    try:
                        if isinstance(completed_at, str):
                            # Parse ISO string
                            dt = datetime.fromisoformat(
                                completed_at.replace("Z", "+00:00")
                            )
                            comp_epoch = dt.timestamp()
                        elif isinstance(completed_at, datetime):
                            comp_epoch = completed_at.timestamp()
                        else:
                            comp_epoch = 0

                        if comp_epoch >= cutoff_24h:
                            metrics["done_today"] += 1

                            # Compute duration
                            started_at = row.get("started_at")
                            if started_at:
                                try:
                                    if isinstance(started_at, str):
                                        dt_start = datetime.fromisoformat(
                                            started_at.replace("Z", "+00:00")
                                        )
                                        start_epoch = dt_start.timestamp()
                                    elif isinstance(started_at, datetime):
                                        start_epoch = started_at.timestamp()
                                    else:
                                        start_epoch = None

                                    if start_epoch:
                                        durations.append(comp_epoch - start_epoch)
                                except Exception:
                                    pass
                    except Exception:
                        pass

            elif s == "failed":
                completed_at = row.get("completed_at")
                if completed_at:
                    try:
                        if isinstance(completed_at, str):
                            dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
                            comp_epoch = dt.timestamp()
                        elif isinstance(completed_at, datetime):
                            comp_epoch = completed_at.timestamp()
                        else:
                            comp_epoch = 0
                        if comp_epoch >= cutoff_24h:
                            metrics["failed_today"] += 1
                    except Exception:
                        pass

        # Average duration
        if durations:
            metrics["avg_duration_s"] = round(sum(durations) / len(durations), 2)

        # Oldest pending scan age
        if pending_rows:
            oldest_age_s: float | None = None
            for row in pending_rows:
                created_at = row.get("created_at")
                if created_at:
                    try:
                        if isinstance(created_at, str):
                            dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                            created_epoch = dt.timestamp()
                        elif isinstance(created_at, datetime):
                            created_epoch = created_at.timestamp()
                        else:
                            continue
                        age = now_epoch - created_epoch
                        if oldest_age_s is None or age > oldest_age_s:
                            oldest_age_s = age
                    except Exception:
                        pass
            if oldest_age_s is not None:
                metrics["oldest_pending_age_s"] = round(oldest_age_s, 2)

    except Exception as exc:
        logger.error("Queue metrics query failed: %s", exc, exc_info=True)
        metrics["error"] = str(exc)

    return JSONResponse(content=metrics)
