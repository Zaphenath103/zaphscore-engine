"""
D-014 + D-069: Security Headers Middleware.

Adds browser-enforced security headers to every response:
  - Strict-Transport-Security          → enforces HTTPS, prevents downgrade attacks
  - X-Content-Type-Options: nosniff    → prevents MIME-type sniffing attacks
  - X-Frame-Options: DENY              → blocks clickjacking via iframes
  - Referrer-Policy: strict-origin     → no URL leakage across origins
  - Permissions-Policy                 → disables unneeded browser APIs
  - Content-Security-Policy            → restricts script/style/media origins
"""

from __future__ import annotations

import os

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# D-069: HSTS max-age of 1 year (31536000s) with includeSubDomains.
# Only set on production — avoids breaking local http:// development.
_IS_PRODUCTION = bool(os.environ.get("VERCEL") or os.environ.get("RAILWAY_ENVIRONMENT"))

_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), magnetometer=(), gyroscope=()"
    ),
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com https://*.supabase.co; "
        "frame-ancestors 'none';"
    ),
    "X-XSS-Protection": "1; mode=block",
}

# D-069: Add HSTS only in production — HSTS over plain HTTP breaks things in dev
if _IS_PRODUCTION:
    _SECURITY_HEADERS["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains; preload"
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers on every outgoing response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
