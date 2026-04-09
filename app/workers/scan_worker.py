"""
ZSE Scan Worker — Background asyncio task that claims queued scans and runs the
security pipeline.  Designed for single-process deployment (Railway) with
configurable concurrency via asyncio.Semaphore.

Usage:
    from app.workers.scan_worker import start_worker, shutdown_worker, sse_channels
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

from app.config import settings
from app.models import database as db
from app.services.sse import create_channel, publish, cleanup

logger = logging.getLogger("zse.worker")

# ---------------------------------------------------------------------------
# Global SSE channel registry — the API layer imports this to subscribe
# ---------------------------------------------------------------------------
sse_channels: dict[str, asyncio.Queue] = {}

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------
_shutdown_event: asyncio.Event | None = None
_semaphore: asyncio.Semaphore | None = None

# Global flag indicating the worker is alive (used by health check)
worker_alive: bool = False


# ---------------------------------------------------------------------------
# Progress callback factory
# ---------------------------------------------------------------------------

def _make_progress_callback(
    scan_id: uuid.UUID,
) -> Callable[..., Coroutine]:
    """Return an async callback the pipeline calls to report progress.

    The pipeline calls this with a single dict: {"phase": ..., "pct": ..., "message": ...}.
    It writes to the database AND pushes to the SSE channel.
    """

    async def progress_callback(data: dict[str, Any]) -> None:
        phase = data.get("phase", "unknown")
        progress_pct = data.get("pct", 0)
        message = data.get("message", "")

        event = {
            "phase": phase,
            "progress_pct": progress_pct,
            "message": message,
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        }

        # Persist phase to DB (lightweight update)
        try:
            await db.update_scan_status(
                scan_id,
                "running",
                progress={"phase": phase, "progress_pct": progress_pct, "message": message},
            )
        except Exception:
            logger.warning("Failed to persist progress for scan %s", scan_id, exc_info=True)

        # Push to SSE channel
        await publish(str(scan_id), event)

    return progress_callback


# ---------------------------------------------------------------------------
# Single scan executor
# ---------------------------------------------------------------------------

async def _execute_scan(scan_id: uuid.UUID, repo_url: str, branch: str | None) -> None:
    """Run the full security pipeline for one scan."""
    sid = str(scan_id)
    create_channel(sid)

    try:
        progress_cb = _make_progress_callback(scan_id)

        # Late import to avoid circular deps — the pipeline module is heavy
        from app.engine.pipeline import run_scan  # type: ignore[import-untyped]

        result = await run_scan(
            scan_id=sid,
            repo_url=repo_url,
            branch=branch,
            progress_callback=progress_cb,
        )

        # C-5 fix: score is a Pydantic ScoreSummary model, use attribute access
        score_obj = result.get("score")
        if hasattr(score_obj, "overall"):
            score_val: int = score_obj.overall
            score_details: dict = score_obj.model_dump()
        elif isinstance(score_obj, dict):
            score_val = score_obj.get("overall", 0)
            score_details = score_obj
        else:
            score_val = int(score_obj) if score_obj else 0
            score_details = {}

        # Convert Finding models to dicts for storage
        raw_findings = result.get("findings", [])
        findings: list[dict] = [
            f.model_dump() if hasattr(f, "model_dump") else f
            for f in raw_findings
        ]

        summary_obj = result.get("summary")
        summary_dict: dict = (
            summary_obj.model_dump() if hasattr(summary_obj, "model_dump")
            else summary_obj if isinstance(summary_obj, dict)
            else {}
        )

        await db.store_findings(scan_id, findings)
        await db.complete_scan(scan_id, score=score_val, summary=summary_dict)

        await publish(sid, {
            "phase": "complete",
            "progress_pct": 100,
            "message": f"Scan complete — score {score_val}/100, {len(findings)} findings",
            "score": score_val,
            "total_findings": len(findings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        logger.info("Scan %s complete — score=%d findings=%d", sid, score_val, len(findings))

    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        logger.error("Scan %s failed: %s", sid, error_msg, exc_info=True)

        await db.fail_scan(scan_id, error=error_msg)
        await publish(sid, {
            "phase": "failed",
            "progress_pct": 0,
            "message": error_msg,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    finally:
        # Keep channel alive briefly so late subscribers can read the final event
        await asyncio.sleep(2)
        cleanup(sid)


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------

async def _poll_loop() -> None:
    """Main loop: poll for queued jobs every 2 seconds, dispatch with semaphore."""
    global _semaphore, _shutdown_event, worker_alive

    _semaphore = asyncio.Semaphore(settings.SCAN_CONCURRENCY)
    _shutdown_event = asyncio.Event()
    worker_alive = True

    logger.info(
        "Scan worker started — concurrency=%d, polling every 2s",
        settings.SCAN_CONCURRENCY,
    )

    while not _shutdown_event.is_set():
        try:
            row = await db.claim_next_job()
            if row is not None:
                scan_id = row["id"]
                repo_url = row["repo_url"]
                branch = row.get("branch")

                logger.info("Claimed scan %s for %s@%s", scan_id, repo_url, branch or "default")

                # Acquire semaphore slot, then launch in background
                await _semaphore.acquire()
                asyncio.create_task(_run_with_semaphore(scan_id, repo_url, branch))
            else:
                # Nothing queued — wait before polling again
                try:
                    await asyncio.wait_for(_shutdown_event.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

        except Exception as exc:
            logger.error("Error in poll loop: %s", exc, exc_info=True)
            await asyncio.sleep(5)

    worker_alive = False
    logger.info("Scan worker shut down cleanly.")


async def _run_with_semaphore(
    scan_id: uuid.UUID,
    repo_url: str,
    branch: str | None,
) -> None:
    """Wrapper that releases the semaphore when the scan finishes."""
    try:
        await _execute_scan(scan_id, repo_url, branch)
    finally:
        _semaphore.release()  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_worker_task: asyncio.Task | None = None


async def start_worker() -> None:
    """Start the background scan worker.  Call from FastAPI lifespan."""
    global _worker_task
    if _worker_task is not None and not _worker_task.done():
        logger.warning("Worker already running — skipping duplicate start.")
        return
    _worker_task = asyncio.create_task(_poll_loop())
    logger.info("Scan worker task created.")


async def shutdown_worker() -> None:
    """Signal the worker to stop and wait for it to finish."""
    global _shutdown_event, _worker_task
    if _shutdown_event is not None:
        _shutdown_event.set()
    if _worker_task is not None:
        try:
            await asyncio.wait_for(_worker_task, timeout=30)
        except asyncio.TimeoutError:
            logger.warning("Worker did not shut down within 30s — cancelling.")
            _worker_task.cancel()
        _worker_task = None


def _handle_signal(sig: signal.Signals) -> None:
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    logger.info("Received signal %s — initiating graceful shutdown.", sig.name)
    if _shutdown_event is not None:
        _shutdown_event.set()


def install_signal_handlers() -> None:
    """Install SIGTERM/SIGINT handlers on the running event loop."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            logger.debug("Signal handler for %s not supported on this platform.", sig.name)
