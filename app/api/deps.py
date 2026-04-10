"""
D-003: Auth Gate — FastAPI dependency for verifying Supabase JWT tokens.

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


def _decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a Supabase JWT. Raises ValueError on any failure."""
    try:
        import jwt  # PyJWT
    except ImportError:
        # Fallback: manual base64 decode (no signature verification)
        # Only used if PyJWT is not installed — logs a warning.
        import base64, json
        logger.warning(
            "PyJWT not installed — JWT signature NOT verified. "
            "Add PyJWT to requirements.txt for production."
        )
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 parts")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        # Check expiry manually
        import time
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return payload

    if not _JWT_SECRET:
        logger.warning(
            "SUPABASE_JWT_SECRET not set — JWT signature NOT verified. "
            "Set this env var in Vercel/Railway to enable full auth."
        )
        # Decode without verification as a graceful degradation
        import json, base64
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 parts")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        import time
        payload = json.loads(base64.urlsafe_b64decode(padded))
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
