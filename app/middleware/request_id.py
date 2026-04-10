"""
D-063: Request ID Tracing Middleware.

Generates a UUID per request and:
1. Attaches it as X-Request-ID response header (visible to API clients for support)
2. Reads it from X-Request-ID request header (allows clients to supply their own)
3. Makes it available via contextvars for injection into log records

Every log line then includes the request_id, making it trivial to grep all logs
for a single failing request across distributed instances.

Usage in log filters:
    from app.middleware.request_id import get_request_id
    request_id = get_request_id()  # returns the ID or "no-request"

Mount in main.py BEFORE other middleware so all subsequent middleware/handlers
see the request_id:
    from app.middleware.request_id import RequestIDMiddleware
    app.add_middleware(RequestIDMiddleware)
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Context variable — survives async context switches within a single request
_request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def get_request_id() -> str:
    """Return the current request's ID, or 'no-request' if outside a request context."""
    return _request_id_var.get() or "no-request"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a UUID request ID to every request for distributed tracing.

    If the client supplies X-Request-ID, that value is used (max 64 chars,
    validated to contain only safe characters). Otherwise a new UUID4 is generated.

    The ID is:
    - Stored in a ContextVar (accessible anywhere in the async call stack)
    - Attached to the response as X-Request-ID
    """

    _SAFE_CHARS = frozenset(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-_."
    )

    def _sanitize_request_id(self, value: str) -> Optional[str]:
        """Return value if it is safe and short enough, else None."""
        if not value or len(value) > 64:
            return None
        if not all(c in self._SAFE_CHARS for c in value):
            return None
        return value

    async def dispatch(self, request: Request, call_next) -> Response:
        # Honour client-supplied ID (e.g. Stripe, load balancers) or generate fresh one
        client_id = self._sanitize_request_id(
            request.headers.get("X-Request-ID", "")
        )
        request_id = client_id or str(uuid.uuid4())

        # Set context so downstream code can call get_request_id()
        token = _request_id_var.set(request_id)

        try:
            response = await call_next(request)
        finally:
            _request_id_var.reset(token)

        response.headers["X-Request-ID"] = request_id
        return response


class RequestIDLogFilter:
    """logging.Filter that injects request_id into every log record.

    Add to any handler:
        handler.addFilter(RequestIDLogFilter())
    """

    def filter(self, record):
        record.request_id = get_request_id()
        return True
