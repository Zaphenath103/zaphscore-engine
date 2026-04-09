"""
Zaphenath Security Engine (ZSE) — FastAPI entry point.

Run with:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router
from app.api.repos import router as repos_router
from app.config import settings
from app.workers.scan_worker import start_worker, shutdown_worker

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(name)-24s | %(levelname)-7s | %(message)s",
)
logger = logging.getLogger("zse")


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown events.

    Auto-detects database backend: tries PostgreSQL first, falls back
    to SQLite so the server can run locally without Postgres.
    """
    # --- Startup ---
    logger.info("ZSE starting up...")

    # Database auto-detection: Postgres -> SQLite fallback
    db_backend = "unknown"
    try:
        from app.models import database as db
        await db.init_db()
        db_backend = "PostgreSQL"
        logger.info("Using PostgreSQL database backend")
    except Exception as pg_err:
        logger.warning(
            "PostgreSQL unavailable (%s), falling back to SQLite", pg_err
        )
        try:
            from app.models import database_sqlite as db  # type: ignore[no-redef]
            await db.init_db()
            db_backend = "SQLite"
            # Monkey-patch the database module so all existing imports use SQLite
            import app.models.database as db_module
            for attr in dir(db):
                if not attr.startswith("_"):
                    setattr(db_module, attr, getattr(db, attr))
            logger.info("Using SQLite database backend (local/demo mode)")
        except Exception as sqlite_err:
            logger.critical(
                "No database backend available! PostgreSQL: %s | SQLite: %s",
                pg_err, sqlite_err,
            )
            raise RuntimeError("Cannot start ZSE without a database") from sqlite_err

    await start_worker()
    logger.info("Background scan worker started. DB backend: %s", db_backend)

    yield  # ---- app is running ----

    # --- Shutdown ---
    logger.info("ZSE shutting down...")
    await shutdown_worker()
    # Use the potentially monkey-patched close_pool
    from app.models.database import close_pool
    await close_pool()
    logger.info("ZSE shutdown complete.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Zaphenath Security Engine",
    description=(
        "Production-grade security scanning backend. "
        "Submit a GitHub repo URL and get a comprehensive security report "
        "covering vulnerabilities, SAST, secrets, IaC misconfigurations, "
        "and license compliance."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — configurable via CORS_ORIGINS env var; defaults to "*" for dev
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

# Mount routers
app.include_router(scans_router)
app.include_router(repos_router)


# ---------------------------------------------------------------------------
# Health / root
# ---------------------------------------------------------------------------

@app.get("/", tags=["health"])
async def health():
    """Health check — confirms the API is running with subsystem status."""
    import shutil
    from app.workers.scan_worker import worker_alive

    # Check database connectivity
    db_ok = False
    try:
        from app.models import database as db
        scan_list, _ = await db.list_scans(page=1, per_page=1)
        db_ok = True
    except Exception:
        pass

    # Check tool availability
    tools = {
        "semgrep": shutil.which("semgrep") is not None,
        "trufflehog": shutil.which("trufflehog") is not None,
        "trivy": shutil.which("trivy") is not None,
        "checkov": shutil.which("checkov") is not None,
    }

    overall = "ok" if (db_ok and worker_alive) else "degraded"

    return {
        "service": "zaphenath-security-engine",
        "status": overall,
        "version": app.version,
        "database": "connected" if db_ok else "disconnected",
        "worker": "alive" if worker_alive else "down",
        "tools": tools,
    }
