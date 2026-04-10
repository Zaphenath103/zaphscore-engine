"""
ZSE Configuration — All settings from environment variables via pydantic-settings.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Zaphenath Security Engine configuration.

    Every value comes from an environment variable of the same name (case-insensitive).
    Provide a .env file or export the variables in your shell / Railway dashboard.
    """

    # --- Supabase / Postgres ---
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""  # service-role key
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/zse"

    # --- GitHub App (authenticated: 5 000 req/hr) ---
    GITHUB_APP_ID: str = ""
    GITHUB_PRIVATE_KEY: str = ""  # PEM contents or path

    # --- GitHub PAT fallback (unauthenticated: 60 req/hr) ---
    GITHUB_TOKEN: str = ""

    # --- Redis (future: caching, pub/sub) ---
    REDIS_URL: Optional[str] = None

    # --- Stripe (D-001: webhook) ---
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""          # whsec_... from Stripe dashboard
    STRIPE_PAYMENT_LINK_PRO_MONTHLY: str = ""
    STRIPE_PAYMENT_LINK_PRO_ANNUAL: str = ""
    STRIPE_PAYMENT_LINK_ENT_MONTHLY: str = ""
    STRIPE_PAYMENT_LINK_ENT_ANNUAL: str = ""

    # --- Rate limiting (D-005/D-006) ---
    RATE_LIMIT_FREE: str = "10/hour"          # scans per IP for unauthenticated
    RATE_LIMIT_PRO: str = "100/hour"          # scans per authenticated Pro user
    UPSTASH_REDIS_URL: Optional[str] = None   # if set, use Redis for distributed RL

    # --- Sentry (D-060: error tracking) ---
    SENTRY_DSN: Optional[str] = None  # Set to enable automatic error reporting

    # --- Scan tunables ---
    SCAN_CONCURRENCY: int = Field(default=3, ge=1, le=20)
    MAX_REPO_SIZE_MB: int = Field(default=500, ge=1)
    CLONE_TIMEOUT_SECONDS: int = Field(default=120, ge=10)

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "info"

    # --- CORS (D-004) ---
    # Production: set to comma-separated explicit origins.
    # Default "*" is development-only; credentials are disabled when wildcard is active.
    CORS_ORIGINS: str = "https://zaphscore.zaphenath.app,https://zaphenath.app"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton — import this everywhere
settings = Settings()


# ---------------------------------------------------------------------------
# D-033: Startup env var validation — fail fast with clear error messages
# ---------------------------------------------------------------------------

def validate_required_env_vars(strict: bool = False) -> list[str]:
    """Check that critical env vars are set. Returns list of warnings.

    Args:
        strict: If True, raises RuntimeError on missing P0 vars (use in production).
                If False, only logs warnings (development-safe default).

    P0 (revenue-critical — must be set in production):
        STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, SUPABASE_URL, SUPABASE_KEY

    P1 (security-critical — strongly recommended):
        SUPABASE_JWT_SECRET
    """
    import logging
    import os
    logger = logging.getLogger("zse.config")

    warnings: list[str] = []

    # P0: Revenue gates — app must not start in production without these
    p0_vars = [
        ("STRIPE_SECRET_KEY",    settings.STRIPE_SECRET_KEY,    "Stripe payments will fail"),
        ("STRIPE_WEBHOOK_SECRET", settings.STRIPE_WEBHOOK_SECRET, "Stripe webhooks will fail — no revenue events"),
        ("SUPABASE_URL",         settings.SUPABASE_URL,         "Database unavailable in Postgres mode"),
        ("SUPABASE_KEY",         settings.SUPABASE_KEY,         "Database auth will fail"),
    ]

    # P1: Security-critical — auth and JWT verification
    p1_vars = [
        ("SUPABASE_JWT_SECRET", os.environ.get("SUPABASE_JWT_SECRET", ""),
         "JWT signatures NOT verified — auth gate is permissive"),
    ]

    missing_p0 = []
    for name, value, consequence in p0_vars:
        if not value:
            msg = f"[P0] Missing env var: {name} — {consequence}"
            logger.warning(msg)
            warnings.append(msg)
            missing_p0.append(name)

    for name, value, consequence in p1_vars:
        if not value:
            msg = f"[P1] Missing env var: {name} — {consequence}"
            logger.warning(msg)
            warnings.append(msg)

    if strict and missing_p0:
        raise RuntimeError(
            f"FATAL: Missing required environment variables: {', '.join(missing_p0)}. "
            "Set these in Vercel/Railway dashboard before starting in production."
        )

    return warnings
