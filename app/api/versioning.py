"""
D-057: API Versioning — /api/v1/ prefix with deprecation alias for /api/.

All routers are mounted at /api/v1/. The legacy /api/ prefix remains active
with a Deprecation header so existing clients don't break immediately.

Mount pattern in main.py:
    from app.api.versioning import include_versioned_routers
    include_versioned_routers(app)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    pass

logger = logging.getLogger("zse.api.versioning")

_DEPRECATION_MSG = (
    'The /api/ prefix is deprecated and will be removed in v2. '
    'Use /api/v1/ instead. See https://zaphscore.zaphenath.app/docs for migration guide.'
)


class DeprecationHeaderMiddleware(BaseHTTPMiddleware):
    """Adds a Deprecation header to responses for /api/ routes (non-v1)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        path = request.url.path

        # Add deprecation header only for legacy /api/ paths (not /api/v1/)
        if path.startswith("/api/") and not path.startswith("/api/v1/"):
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = "Sat, 01 Jan 2027 00:00:00 GMT"
            response.headers["Link"] = (
                '<https://zaphscore.zaphenath.app/docs>; rel="successor-version"'
            )

        return response


def include_versioned_routers(app: FastAPI) -> None:
    """Mount all API routers at both /api/v1/ (primary) and /api/ (deprecated alias).

    Call this from main.py instead of manually mounting each router.
    """
    _load_routers(app, version_prefix="/api/v1")
    _load_routers(app, version_prefix="/api")

    # Register deprecation middleware for legacy /api/ paths
    app.add_middleware(DeprecationHeaderMiddleware)
    logger.info("API versioning: /api/v1/ (primary) + /api/ (deprecated alias) registered")


def _load_routers(app: FastAPI, version_prefix: str) -> None:
    """Mount all routers with the given prefix (strips their existing /api prefix)."""

    router_defs = [
        ("app.api.scans",    "router", "/scans",   ["scans"]),
        ("app.api.repos",    "router", "/repos",    ["repos"]),
        ("app.api.waitlist", "router", "/waitlist", ["waitlist"]),
        ("app.api.user",     "router", "/user",     ["user"]),
        ("app.api.reports",  "router", "/scans",    ["reports"]),
        ("app.api.webhook",  "router", "/webhook",  ["webhook"]),
    ]

    for module_path, attr, path_suffix, tags in router_defs:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            original_router = getattr(mod, attr)

            # Build a copy of the router with the new prefix
            from fastapi import APIRouter
            versioned_router = APIRouter()
            versioned_router.include_router(
                original_router,
                prefix=f"{version_prefix}{path_suffix}".rstrip("/"),
            )
            app.include_router(versioned_router)
        except Exception as exc:
            logger.error(
                "Failed to mount %s at %s%s: %s",
                module_path, version_prefix, path_suffix, exc,
            )
