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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

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
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
_cors_origins = (
    ["*"] if settings.CORS_ORIGINS == "*"
    else [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------

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
