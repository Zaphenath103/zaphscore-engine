"""
ZSE Server-Sent Events (SSE) service — manages per-scan event channels.

The scan worker publishes progress events; the API SSE endpoint subscribes.
Uses simple in-memory asyncio.Queue instances keyed by scan_id.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncGenerator

logger = logging.getLogger("zse.sse")

# ---------------------------------------------------------------------------
# Channel registry — scan_id -> asyncio.Queue
# ---------------------------------------------------------------------------
_channels: dict[str, asyncio.Queue[dict[str, Any] | None]] = {}

KEEPALIVE_INTERVAL = 15  # seconds


def create_channel(scan_id: str) -> asyncio.Queue[dict[str, Any] | None]:
    """Create a new SSE channel for a scan.

    If one already exists it is replaced (previous subscribers will get None
    sentinel and exit cleanly).
    """
    if scan_id in _channels:
        # Signal any existing subscribers to stop
        try:
            _channels[scan_id].put_nowait(None)
        except asyncio.QueueFull:
            pass
        logger.debug("Replaced existing SSE channel for scan %s", scan_id)

    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=256)
    _channels[scan_id] = queue
    logger.debug("Created SSE channel for scan %s", scan_id)
    return queue


async def publish(scan_id: str, event_data: dict[str, Any]) -> None:
    """Push an event to the scan's SSE channel.

    Silently drops the event if no channel exists (scan already cleaned up)
    or if the queue is full.
    """
    queue = _channels.get(scan_id)
    if queue is None:
        logger.debug("No SSE channel for scan %s — event dropped.", scan_id)
        return
    try:
        queue.put_nowait(event_data)
    except asyncio.QueueFull:
        logger.warning("SSE channel for scan %s is full — event dropped.", scan_id)


async def subscribe(scan_id: str) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted strings for the given scan.

    Yields:
        SSE lines in the format ``data: {json}\\n\\n``
        Sends ``:keepalive\\n\\n`` every 15 seconds if idle.
        Terminates when the channel is cleaned up (receives None sentinel)
        or the channel doesn't exist.
    """
    queue = _channels.get(scan_id)
    if queue is None:
        # Channel doesn't exist yet or was already cleaned up.
        # Yield a terminal event so the client knows.
        yield _format_event({"phase": "unknown", "message": "Scan not found or already completed."})
        return

    while True:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_INTERVAL)

            if event is None:
                # Sentinel — channel is shutting down
                yield _format_event({"phase": "closed", "message": "Stream closed."})
                return

            yield _format_event(event)

            # If the scan is complete or failed, send one last event and stop
            phase = event.get("phase", "")
            if phase in ("complete", "failed"):
                return

        except asyncio.TimeoutError:
            # No events for KEEPALIVE_INTERVAL — send keepalive
            yield ":keepalive\n\n"


def cleanup(scan_id: str) -> None:
    """Remove the SSE channel for a scan.

    Sends a None sentinel to any active subscribers before removing.
    """
    queue = _channels.pop(scan_id, None)
    if queue is not None:
        try:
            queue.put_nowait(None)
        except asyncio.QueueFull:
            pass
        logger.debug("Cleaned up SSE channel for scan %s", scan_id)


def get_channel(scan_id: str) -> asyncio.Queue[dict[str, Any] | None] | None:
    """Get the queue for a scan, if it exists."""
    return _channels.get(scan_id)


def active_channels() -> list[str]:
    """List scan IDs with active SSE channels (for debugging)."""
    return list(_channels.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_event(data: dict[str, Any]) -> str:
    """Format a dict as an SSE data line."""
    return f"data: {json.dumps(data)}\n\n"
