"""
D-003 + D-068: Auth Gate — FastAPI dependency for verifying Supabase JWT tokens.

Usage:
    from app.api.deps import get_current_user, CurrentUser

    @router.post("/api/scans")
    async def submit_scan(body: ScanRequest, user: CurrentUser):
        ...

The dependency reads the Authorization: Bearer <token> header, verifies the
JWT signature against the Supabase JWT secret, and returns the decoded payload.
Raises HTTP 401 if the token is missing, expired, or invalid.

Environment variables required:
    SUPABASE_JWT_SECRET — JWT secret from Supabase Project → Settings → API
                          (the "JWT Secret" field, NOT the anon/service key)
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("zse.api.deps")

_bearer = HTTPBearer(auto_error=False)

# JWT secret from environment — Supabase Project Settings → API → JWT Secret
_JWT_SECRET: str = os.environ.get("SUPABASE_JWT_SECRET", "")

# D-068: Detect production environment — used to enforce hard fail when JWT secret missing
_IS_PRODUCTION: bool = bool(
    os.environ.get("VERCEL") or os.environ.get("RAILWAY_ENVIRONMENT")
)

if not _JWT_SECRET and _IS_PRODUCTION:
    # Log at startup — this is a critical misconfiguration
    logger.critical(
        "SUPABASE_JWT_SECRET is not set in production. "
        "All authenticated endpoints will reject requests with HTTP 503. "
        "Set SUPABASE_JWT_SECRET immediately in Vercel/Railway environment variables."
    )


def _decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a Supabase JWT. Raises ValueError on any failure."""
    try:
        import jwt  # PyJWT
    except ImportError:
        if _IS_PRODUCTION:
            # D-068: PyJWT is in requirements.txt — if missing in production, fail hard
            raise ValueError(
                "PyJWT not installed in production. Cannot verify JWT signatures. "
                "Ensure PyJWT is in requirements.txt and the image was built correctly."
            )
        # Development fallback: manual base64 decode (no signature verification)
        import base64 as _base64, json as _json
        logger.warning(
            "DEV MODE: PyJWT not installed — JWT signature NOT verified. "
            "Add PyJWT to requirements.txt for production."
        )
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 parts")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = _json.loads(_base64.urlsafe_b64decode(padded))
        import time
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return payload

    if not _JWT_SECRET:
        if _IS_PRODUCTION:
            # D-068: Hard fail in production — forged tokens must never be accepted
            raise ValueError(
                "SUPABASE_JWT_SECRET is not configured. "
                "Cannot verify JWT in production. Set this env var immediately."
            )
        # Development only: decode without verification — warn loudly
        logger.warning(
            "DEV MODE: SUPABASE_JWT_SECRET not set — JWT signature NOT verified. "
            "NEVER deploy without this secret configured."
        )
        import json as _json, base64 as _base64
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 parts")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        import time
        payload = _json.loads(_base64.urlsafe_b64decode(padded))
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return payload

    return jwt.decode(
        token,
        _JWT_SECRET,
        algorithms=["HS256"],
        audience="authenticated",
        options={"verify_exp": True},
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> dict[str, Any]:
    """FastAPI dependency — returns decoded JWT payload or raises 401.

    Inject with:
        user: Annotated[dict, Depends(get_current_user)]
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = _decode_token(credentials.credentials)
    except ValueError as exc:
        msg = str(exc)
        if "SUPABASE_JWT_SECRET" in msg or "PyJWT not installed" in msg:
            # D-068: Config error in production — return 503 so ops team notices
            logger.critical("Auth misconfiguration: %s", msg)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service misconfigured. Contact the platform administrator.",
            )
        logger.warning("JWT verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as exc:
        logger.warning("JWT verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# Convenience type alias for use in endpoint signatures
CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]
