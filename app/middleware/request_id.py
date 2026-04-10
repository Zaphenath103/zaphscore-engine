"""
D-063: Request ID Tracing Middleware.

Generates a UUID per request, attaches it as X-Request-ID header in both
request and response, and injects it into the logging context.

Every log line from this request includes request_id — making production
debugging tractable. Grep one ID across all logs to trace a full request.

Usage in main.py:
    from app.middleware.request_id import RequestIDMiddleware
    app.add_middleware(RequestIDMiddleware)

Log output format (with structlog or standard logging):
    2026-04-10 09:00:00 | zse.api.scans | INFO | [req-id=abc123] Scan queued
"""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("zse.middleware.request_id")

# Context variable — allows downstream code to access request_id without
# threading or passing it through every function call
_request_id_var: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    """Return the current request's ID (empty string outside of a request context)."""
    return _request_id_var.get("")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generate UUID per request; attach to headers and logging context."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Use existing ID from client if provided (tracing across services),
        # otherwise generate a new one
        incoming_id = request.headers.get("X-Request-ID", "")
        request_id = incoming_id if _is_valid_uuid(incoming_id) else str(uuid.uuid4())

        # Inject into context var (accessible via get_request_id())
        token = _request_id_var.set(request_id)

        # Add to request state for use in endpoint handlers
        request.state.request_id = request_id

        # Inject a logging filter so all log records from this context include request_id
        _log_filter = _RequestIDFilter(request_id)
        root_logger = logging.getLogger()
        root_logger.addFilter(_log_filter)

        try:
            response = await call_next(request)
        finally:
            root_logger.removeFilter(_log_filter)
            _request_id_var.reset(token)

        # Always return the request_id in the response header
        response.headers["X-Request-ID"] = request_id
        return response


def _is_valid_uuid(value: str) -> bool:
    """Check if value is a valid UUID string."""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


class _RequestIDFilter(logging.Filter):
    """Logging filter that injects request_id into every log record."""

    def __init__(self, request_id: str) -> None:
        super().__init__()
        self.request_id = request_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = self.request_id
        return True
