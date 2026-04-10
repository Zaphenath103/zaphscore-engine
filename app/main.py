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
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(name)-24s | %(levelname)-7s | %(message)s",
)
logger = logging.getLogger("zse")

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

# D-014: Security headers — X-Content-Type-Options, X-Frame-Options, CSP, etc.
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

# Mount routers — wrapped so a broken router never kills startup
try:
    from app.api.scans import router as scans_router
    app.include_router(scans_router)
except Exception as e:
    logger.error("Failed to load scans router: %s", e)

try:
    from app.api.repos import router as repos_router
    app.include_router(repos_router)
except Exception as e:
    logger.error("Failed to load repos router: %s", e)

try:
    from app.api.waitlist import router as waitlist_router
    app.include_router(waitlist_router)
except Exception as e:
    logger.error("Failed to load waitlist router: %s", e)

try:
    from app.api.user import router as user_router  # D-012: GDPR delete
    app.include_router(user_router)
except Exception as e:
    logger.error("Failed to load user router: %s", e)

try:
    from app.api.reports import router as reports_router  # D-043: PDF export
    app.include_router(reports_router)
except Exception as e:
    logger.error("Failed to load reports router: %s", e)

try:
    from app.api.webhook import router as webhook_router
    app.include_router(webhook_router)
    logger.info("Stripe webhook router loaded")
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
    """Full health with subsystem status."""
    return {
        "service": "zaphenath-security-engine",
        "status": "ok" if (_db_ok and _worker_ok) else "degraded",
        "version": app.version,
        "database": _db_backend,
        "worker": "alive" if _worker_ok else "down",
        "port": os.environ.get("PORT", "default"),
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
