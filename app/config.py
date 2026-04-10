"""
ZSE Configuration — All settings from environment variables via pydantic-settings.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Zaphenath Security Engine configuration."""

    # --- Supabase / Postgres ---
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/zse"

    # --- GitHub App ---
    GITHUB_APP_ID: str = ""
    GITHUB_PRIVATE_KEY: str = ""
    GITHUB_TOKEN: str = ""

    # --- Redis ---
    REDIS_URL: Optional[str] = None

    # --- Stripe ---
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PAYMENT_LINK_PRO_MONTHLY: str = ""
    STRIPE_PAYMENT_LINK_PRO_ANNUAL: str = ""
    STRIPE_PAYMENT_LINK_ENT_MONTHLY: str = ""
    STRIPE_PAYMENT_LINK_ENT_ANNUAL: str = ""

    # --- Rate limiting (D-005/D-006) ---
    RATE_LIMIT_FREE: str = "10/hour"
    RATE_LIMIT_PRO: str = "100/hour"
    UPSTASH_REDIS_URL: Optional[str] = None

    # --- D-060: Sentry error tracking ---
    SENTRY_DSN: Optional[str] = None

    # --- D-061: Per-user daily rate limits by JWT tier ---
    RATE_LIMIT_FREE_DAILY: int = Field(default=3, ge=1)
    RATE_LIMIT_PRO_DAILY: int = Field(default=100, ge=1)

    # --- Scan tunables ---
    SCAN_CONCURRENCY: int = Field(default=3, ge=1, le=20)
    MAX_REPO_SIZE_MB: int = Field(default=500, ge=1)
    CLONE_TIMEOUT_SECONDS: int = Field(default=120, ge=10)

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "info"

    # --- CORS (D-004) ---
    CORS_ORIGINS: str = "https://zaphscore.zaphenath.app,https://zaphenath.app"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


settings = Settings()


def validate_required_env_vars(strict: bool = False) -> list[str]:
    """Check that critical env vars are set. Returns list of warnings."""
    import logging
    import os
    logger = logging.getLogger("zse.config")
    warnings: list[str] = []

    p0_vars = [
        ("STRIPE_SECRET_KEY", settings.STRIPE_SECRET_KEY, "Stripe payments will fail"),
        ("STRIPE_WEBHOOK_SECRET", settings.STRIPE_WEBHOOK_SECRET, "Stripe webhooks will fail"),
        ("SUPABASE_URL", settings.SUPABASE_URL, "Database unavailable in Postgres mode"),
        ("SUPABASE_KEY", settings.SUPABASE_KEY, "Database auth will fail"),
    ]
    p1_vars = [
        ("SUPABASE_JWT_SECRET", os.environ.get("SUPABASE_JWT_SECRET", ""),
         "JWT signatures NOT verified"),
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
