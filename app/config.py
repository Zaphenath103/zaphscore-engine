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

    # --- Scan tunables ---
    SCAN_CONCURRENCY: int = Field(default=3, ge=1, le=20)
    MAX_REPO_SIZE_MB: int = Field(default=500, ge=1)
    CLONE_TIMEOUT_SECONDS: int = Field(default=120, ge=10)

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "info"

    # --- CORS ---
    CORS_ORIGINS: str = "*"  # Comma-separated origins, or "*" for dev

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton — import this everywhere
settings = Settings()
