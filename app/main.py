"""
Zaphenath Security Engine (ZSE) — FastAPI entry point.

Run with:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from app.config import settings

# ---------------------------------------------------------------------------
# Logging (D-063: inject request_id into every log record)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(name)-24s | %(levelname)-7s | [%(request_id)s] %(message)s",
)
logger = logging.getLogger("zse")

# Attach the request_id filter to the root logger so all loggers inherit it
try:
    from app.middleware.request_id import RequestIDLogFilter
    logging.getLogger().addFilter(RequestIDLogFilter())
except Exception as _e:
    logging.getLogger("zse").warning("RequestIDLogFilter not loaded: %s", _e)

# ---------------------------------------------------------------------------
# D-060: Sentry — initialise before the lifespan so startup errors are captured
# ---------------------------------------------------------------------------
if settings.SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            traces_sample_rate=0.1,        # 10% of requests traced for performance
            profiles_sample_rate=0.05,     # 5% profiled — low overhead
            environment=os.environ.get("RAILWAY_ENVIRONMENT", "development"),
            integrations=[
                StarletteIntegration(transaction_style="endpoint"),
                FastApiIntegration(transaction_style="endpoint"),
            ],
            # Never send user PII — scan results may contain sensitive repo data
            send_default_pii=False,
        )
        logger.info("Sentry initialised (DSN configured)")
    except ImportError:
        logger.warning(
            "sentry-sdk not installed — add 'sentry-sdk[fastapi]' to requirements.txt "
            "to enable error tracking."
        )
    except Exception as _sentry_err:
        logger.warning("Sentry init failed: %s", _sentry_err)

# ---------------------------------------------------------------------------
# Global state — set during lifespan, read by endpoints
# ---------------------------------------------------------------------------
_db_backend: str = "none"
_db_ok: bool = False
_worker_ok: bool = False


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown (CRASH-PROOF)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown. NEVER crashes — app must always start for healthcheck."""
    global _db_backend, _db_ok, _worker_ok

    logger.info("ZSE starting up... PORT=%s", os.environ.get("PORT", "not set"))

    # D-060: Sentry error tracking
    try:
        if settings.SENTRY_DSN:
            import sentry_sdk
            from sentry_sdk.integrations.fastapi import FastApiIntegration
            from sentry_sdk.integrations.starlette import StarletteIntegration
            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                traces_sample_rate=0.1,
                environment="production" if (os.environ.get("VERCEL") or os.environ.get("RAILWAY_ENVIRONMENT")) else "development",
                integrations=[StarletteIntegration(), FastApiIntegration()],
                send_default_pii=False,
            )
            logger.info("Sentry error tracking initialized")
    except Exception as e:
        logger.warning("Sentry init failed (non-fatal): %s", e)

    # D-033: Validate required env vars — log warnings, fail-fast in production
    try:
        from app.config import validate_required_env_vars
        is_prod = os.environ.get("VERCEL") or os.environ.get("RAILWAY_ENVIRONMENT")
        warnings = validate_required_env_vars(strict=bool(is_prod))
        if warnings:
            logger.warning("Env var check: %d warning(s) found", len(warnings))
    except RuntimeError as e:
        logger.critical("Startup aborted: %s", e)
        raise

    # --- Database (best-effort, non-fatal) ---
    _db_url = settings.DATABASE_URL
    _skip_postgres = "localhost" in _db_url or "127.0.0.1" in _db_url

    if not _skip_postgres and _db_url.startswith("postgresql"):
        try:
            from app.models import database as db
            await asyncio.wait_for(db.init_db(), timeout=10)
            _db_backend = "PostgreSQL"
            _db_ok = True
            logger.info("PostgreSQL connected")
        except Exception as e:
            logger.warning("PostgreSQL failed: %s — trying SQLite", e)

    if not _db_ok:
        try:
            from app.models import database_sqlite as db  # type: ignore[no-redef]
            await db.init_db()
            _db_backend = "SQLite"
            _db_ok = True
            # Monkey-patch so other modules use SQLite
            import app.models.database as db_module
            for attr in dir(db):
                if not attr.startswith("_"):
                    setattr(db_module, attr, getattr(db, attr))
            logger.info("SQLite connected")
        except Exception as e:
            logger.error("SQLite also failed: %s — running without database", e)
            _db_backend = "none"

    # --- Worker (best-effort, non-fatal) ---
    if _db_ok:
        try:
            from app.workers.scan_worker import start_worker
            await start_worker()
            _worker_ok = True
            logger.info("Scan worker started")
        except Exception as e:
            logger.error("Worker failed to start: %s", e)

    logger.info("ZSE ready — db=%s worker=%s", _db_backend, _worker_ok)

    yield  # ---- app is running ----

    # --- Shutdown (best-effort) ---
    logger.info("ZSE shutting down...")
    try:
        from app.workers.scan_worker import shutdown_worker
        await shutdown_worker()
    except Exception:
        pass
    try:
        from app.models.database import close_pool
        await close_pool()
    except Exception:
        pass
    logger.info("ZSE shutdown complete.")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Zaphenath Security Engine",
    description="Production-grade security scanning backend.",
    version="0.2.0",
    lifespan=lifespan,
)

# D-004: CORS — never send credentials=True with wildcard origin.
# Per CORS spec: allow_credentials=True with allow_origins=["*"] is rejected by browsers
# AND enables CSRF from any domain. Credentials only flow to explicit origins.
_cors_origins = (
    ["*"] if settings.CORS_ORIGINS == "*"
    else [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
)
_cors_credentials = _cors_origins != ["*"]  # False when wildcard — safe default

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# D-063: Request ID tracing — attach UUID to every request/response/log line
try:
    from app.middleware.request_id import RequestIDMiddleware
    app.add_middleware(RequestIDMiddleware)
    logger.info("Request ID middleware loaded")
except Exception as e:
    logger.error("Request ID middleware failed to load: %s", e)

# D-014: Security headers — X-Content-Type-Options, X-Frame-Options, CSP, HSTS, etc.
try:
    from app.middleware.security_headers import SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)
    logger.info("Security headers middleware loaded")
except Exception as e:
    logger.error("Security headers middleware failed to load: %s", e)

# D-005: Rate limiting middleware — protects scan endpoints from DoS
try:
    from app.middleware.rate_limit import RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware)
    logger.info("Rate limiting middleware loaded")
except Exception as e:
    logger.error("Rate limiting middleware failed to load: %s", e)

# ---------------------------------------------------------------------------
# D-057: API versioning — mount all routers under BOTH /api/v1/ AND /api/
#
# Strategy:
#   - /api/v1/ is the canonical versioned path (new clients use this)
#   - /api/ is preserved as a backward-compat alias with X-API-Deprecated header
#
# Each router already has its own prefix (e.g. /api/scans, /api/repos).
# We re-mount the same router objects without a prefix change, then add a
# /api/v1/ sub-application that re-declares the versioned routes.
#
# Implementation: Use APIRouter with include_router + prefix override.
# FastAPI does not support prefix stripping for existing routers in-place,
# so we use a v1 sub-router that re-mounts everything.
# ---------------------------------------------------------------------------

from fastapi import APIRouter as _APIRouter

_v1 = _APIRouter(prefix="/api/v1")  # versioned prefix


def _mount_router(router, *, label: str) -> None:
    """Mount a router at both /api/ (legacy) and /api/v1/ (canonical)."""
    # Legacy /api/ mount (unchanged path — backward compat)
    try:
        app.include_router(router)
    except Exception as e:
        logger.error("Failed to load %s router (legacy): %s", label, e)

    # Canonical /api/v1/ mount — strips the router's own /api prefix, adds /v1
    try:
        # Build a v1-prefixed version: router.prefix is e.g. "/api/scans"
        # We want to mount at "/api/v1/scans" — i.e. strip "/api" from router.prefix
        stripped_prefix = router.prefix.removeprefix("/api")
        app.include_router(router, prefix=f"/api/v1{stripped_prefix}", tags=[f"{label}-v1"])
    except Exception as e:
        logger.error("Failed to load %s router (v1): %s", label, e)


# Mount routers — wrapped so a broken router never kills startup
try:
    from app.api.scans import router as scans_router
    _mount_router(scans_router, label="scans")
except Exception as e:
    logger.error("Failed to load scans router: %s", e)

try:
    from app.api.repos import router as repos_router
    _mount_router(repos_router, label="repos")
except Exception as e:
    logger.error("Failed to load repos router: %s", e)

try:
    from app.api.waitlist import router as waitlist_router
    _mount_router(waitlist_router, label="waitlist")
except Exception as e:
    logger.error("Failed to load waitlist router: %s", e)

try:
    from app.api.user import router as user_router  # D-012: GDPR delete
    _mount_router(user_router, label="user")
except Exception as e:
    logger.error("Failed to load user router: %s", e)

try:
    from app.api.reports import router as reports_router  # D-043: PDF export
    _mount_router(reports_router, label="reports")
except Exception as e:
    logger.error("Failed to load reports router: %s", e)

try:
    from app.api.webhook import router as webhook_router
    _mount_router(webhook_router, label="webhook")
    logger.info("Stripe webhook router loaded (legacy + v1)")
except Exception as e:
    logger.error("Failed to load webhook router: %s", e)


# ---------------------------------------------------------------------------
# 404 handler
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "not found", "path": str(request.url.path)},
    )


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------

@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    """Serve robots.txt — prevent API crawling."""
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /api/\n"
        "Disallow: /admin/\n"
        "Disallow: /docs\n"
        "Disallow: /redoc\n"
        "Disallow: /openapi.json\n"
        "\n"
        f"Sitemap: https://zaphscore.zaphenath.app/sitemap.xml\n"
    )


@app.get("/ping")
async def ping():
    """Instant liveness probe — Railway healthcheck. Always returns 200."""
    return {"ok": True}


@app.get("/health")
async def health():
    """D-064: Enhanced health check with subsystem and resource status.

    Returns:
        status: 'healthy' (all systems go), 'degraded' (partial), 'unhealthy' (critical failure)
        db: database backend status and connectivity
        worker: scan worker status
        disk_free_mb: free space in /tmp (scan workspace) — low = scans will fail
        checks: ordered list of check results for monitoring dashboards
    """
    import shutil as _shutil
    import time as _time

    checks: list[dict] = []
    overall_healthy = True

    # --- DB check ---
    db_status = "ok" if _db_ok else "error"
    if not _db_ok:
        overall_healthy = False
    checks.append({"name": "database", "status": db_status, "backend": _db_backend})

    # --- Worker check ---
    worker_status = "ok" if _worker_ok else "degraded"
    checks.append({"name": "worker", "status": worker_status})

    # --- Disk check (scan workspace) ---
    try:
        disk = _shutil.disk_usage("/tmp")
        disk_free_mb = disk.free // (1024 * 1024)
        disk_status = "ok" if disk_free_mb > 500 else ("degraded" if disk_free_mb > 100 else "critical")
        if disk_status == "critical":
            overall_healthy = False
        checks.append({"name": "disk_tmp", "status": disk_status, "free_mb": disk_free_mb})
    except Exception as _e:
        disk_free_mb = -1
        checks.append({"name": "disk_tmp", "status": "unknown", "error": str(_e)})

    # --- Memory check ---
    try:
        import resource as _resource
        mem_usage_mb = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss // 1024
        checks.append({"name": "memory_rss_mb", "status": "ok", "rss_mb": mem_usage_mb})
    except Exception:
        # resource module not available on all platforms — non-fatal
        checks.append({"name": "memory_rss_mb", "status": "unknown"})

    overall = "healthy" if (overall_healthy and _db_ok) else ("degraded" if _db_ok else "unhealthy")

    return {
        "service": "zaphenath-security-engine",
        "status": overall,
        "version": app.version,
        "database": _db_backend,
        "worker": "alive" if _worker_ok else "down",
        "disk_free_mb": disk_free_mb,
        "port": os.environ.get("PORT", "default"),
        "checks": checks,
    }


@app.get("/og-image.png")
async def og_image():
    """Serve the ZaphScore OG image for Twitter/X and social previews."""
    import base64
    try:
        from app.og_image_b64 import OG_IMAGE_PNG_B64
        png_bytes = base64.b64decode(OG_IMAGE_PNG_B64)
        return Response(
            content=png_bytes,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    except Exception as e:
        logger.error("OG image load failed: %s", e)
        return Response(content=b"", media_type="image/png", status_code=404)


@app.get("/", response_class=HTMLResponse)
async def frontend():
    """Serve the ZaphScore scan frontend."""
    try:
        from app.frontend import SCAN_PAGE_HTML
        return SCAN_PAGE_HTML
    except Exception as e:
        logger.error("Frontend load failed: %s", e)
        return HTMLResponse(
            content=f"<html><body><h1>ZaphScore</h1><p>Frontend loading error: {e}</p>"
            f"<p><a href='/health'>Health</a> | <a href='/docs'>API Docs</a></p></body></html>",
            status_code=200,
        )
