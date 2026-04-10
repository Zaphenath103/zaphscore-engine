"""
D-014: Security Headers Middleware.

Adds browser-enforced security headers to every response:
  - X-Content-Type-Options: nosniff      → prevents MIME-type sniffing attacks
  - X-Frame-Options: DENY               → blocks clickjacking via iframes
  - Referrer-Policy: strict-origin      → no URL leakage across origins
  - Permissions-Policy                  → disables unneeded browser APIs
  - Content-Security-Policy             → restricts script/style/media origins
"""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers on every outgoing response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
