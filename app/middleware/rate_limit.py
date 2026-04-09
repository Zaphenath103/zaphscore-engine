"""
D-005 + D-006: Rate Limiting Middleware — sliding window, Redis-ready.

Prevents DoS via unlimited scan queue. Without this, any IP can queue thousands
of scans — each clones a full repository and runs 5 subprocess tools.

Architecture:
- Primary: Upstash Redis (if UPSTASH_REDIS_URL set) — distributed, survives restarts
- Fallback: In-memory dict — fast, but resets on cold starts / different instances

Limits:
- Free (unauthenticated): 10 scans/hour per IP (RATE_LIMIT_FREE env var)
- Pro (authenticated): 100 scans/hour per user (RATE_LIMIT_PRO env var)
- Non-scan routes: no limit

D-006 note: In-memory fallback is intentionally limited. On Vercel (multiple instances),
each instance has its own dict = rate limit is per-instance, not global. Set
UPSTASH_REDIS_URL to get true global rate limiting.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from typing import Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("zse.ratelimit")

# Routes that are rate-limited (POST only for scans — heavy operations)
_RATE_LIMITED_PATHS = {"/api/scans"}


def _parse_limit(spec: str) -> tuple[int, int]:
    """Parse '10/hour', '100/minute', '1000/day' → (count, window_seconds)."""
    try:
        count_str, unit = spec.strip().split("/")
        count = int(count_str.strip())
        unit = unit.strip().lower()
        windows = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
        return count, windows.get(unit, 3600)
    except Exception:
        return 10, 3600  # safe default: 10/hour


# ---------------------------------------------------------------------------
# Config (after _parse_limit is defined)
# ---------------------------------------------------------------------------
_FREE_LIMIT, _FREE_WINDOW = _parse_limit(os.environ.get("RATE_LIMIT_FREE", "10/hour"))
_PRO_LIMIT, _PRO_WINDOW   = _parse_limit(os.environ.get("RATE_LIMIT_PRO", "100/hour"))


# ---------------------------------------------------------------------------
# In-memory store (fallback)
# ---------------------------------------------------------------------------
# {key → [(timestamp, count)]}  — sliding log per (ip, window)
_store: dict[str, list[float]] = defaultdict(list)
_store_lock_import_done = False


def _in_memory_check(key: str, limit: int, window_secs: int) -> tuple[bool, int]:
    """Sliding window rate check using in-memory log.

    Returns: (allowed: bool, remaining: int)
    """
    now = time.monotonic()
    cutoff = now - window_secs

    # Evict expired timestamps
    log = _store[key]
    log[:] = [t for t in log if t > cutoff]

    if len(log) >= limit:
        return False, 0

    log.append(now)
    return True, limit - len(log)


async def _redis_check(key: str, limit: int, window_secs: int) -> Optional[tuple[bool, int]]:
    """Sliding window check via Upstash Redis (INCR + EXPIRE pattern).

    Returns None if Redis is unavailable (falls back to in-memory).
    """
    redis_url = os.environ.get("UPSTASH_REDIS_URL", "")
    if not redis_url:
        return None

    try:
        import aiohttp  # already a dependency

        headers = {}
        # Upstash REST API uses Bearer token from URL
        # URL format: https://<host>/incr/<key>?EX=<window>
        async with aiohttp.ClientSession() as sess:
            # Use Upstash REST API (no redis-py needed)
            token = redis_url.split("@")[0].replace("redis://:", "").replace("rediss://:", "")
            host = redis_url.split("@")[-1]

            incr_url = f"https://{host}/incr/{key}"
            expire_url = f"https://{host}/expire/{key}/{window_secs}"

            async with sess.post(
                incr_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=aiohttp.ClientTimeout(total=0.5),
            ) as resp:
                data = await resp.json()
                count = data.get("result", 0)

            if count == 1:
                # First request in this window — set TTL
                await sess.post(
                    expire_url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=aiohttp.ClientTimeout(total=0.5),
                )

            allowed = count <= limit
            remaining = max(0, limit - count)
            return allowed, remaining

    except Exception as exc:
        logger.debug("Redis rate limit check failed, falling back to memory: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limiter applied to scan-creation endpoints."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only rate-limit POST to scan endpoints
        if request.method != "POST" or request.url.path not in _RATE_LIMITED_PATHS:
            return await call_next(request)

        # Determine limit tier from Authorization header
        auth = request.headers.get("Authorization", "")
        is_authenticated = bool(auth and auth.startswith("Bearer "))
        limit = _PRO_LIMIT if is_authenticated else _FREE_LIMIT
        window = _PRO_WINDOW if is_authenticated else _FREE_WINDOW

        # Build rate limit key
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP", "")
            or (request.client.host if request.client else "unknown")
        )
        key = f"rl:{client_ip}:{window}"

        # Check rate limit (Redis preferred, in-memory fallback)
        result = await _redis_check(key, limit, window)
        if result is None:
            allowed, remaining = _in_memory_check(key, limit, window)
        else:
            allowed, remaining = result

        if not allowed:
            tier = "pro" if is_authenticated else "free"
            logger.warning("Rate limit exceeded: ip=%s tier=%s limit=%d/%ds", client_ip, tier, limit, window)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "limit": limit,
                    "window_seconds": window,
                    "tier": tier,
                    "retry_after": window,
                },
                headers={
                    "Retry-After": str(window),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Window": str(window),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Window"] = str(window)
        return response
