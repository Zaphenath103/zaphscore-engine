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

# D-061: Per-user daily limits (separate from global IP rate limits)
# free = 3 scans/day, pro = 100 scans/day, enterprise = unlimited
_USER_FREE_LIMIT, _USER_FREE_WINDOW   = _parse_limit(os.environ.get("USER_RATE_FREE", "3/day"))
_USER_PRO_LIMIT, _USER_PRO_WINDOW     = _parse_limit(os.environ.get("USER_RATE_PRO", "100/day"))
_USER_ENT_LIMIT, _USER_ENT_WINDOW     = _parse_limit(os.environ.get("USER_RATE_ENT", "10000/day"))


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


def _extract_user_tier(token: str) -> tuple[str, str]:
    """D-061: Decode JWT to extract user_id and tier (plan).

    Returns (user_id, tier) where tier is 'free' | 'pro' | 'enterprise'.
    Falls back to ('ip_fallback', 'free') on any error.
    """
    try:
        import base64, json, time
        parts = token.split(".")
        if len(parts) != 3:
            return ("unknown", "free")
        # Decode payload (no signature verification needed � rate limiting only)
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))

        # Check expiry
        if payload.get("exp", 0) < time.time():
            return ("expired", "free")

        user_id = payload.get("sub", "unknown")
        # Plan can be in app_metadata.plan or user_metadata.plan or top-level
        app_meta = payload.get("app_metadata", {}) or {}
        user_meta = payload.get("user_metadata", {}) or {}
        tier = (
            app_meta.get("plan")
            or user_meta.get("plan")
            or payload.get("plan")
            or "free"
        ).lower()

        # Normalize enterprise variants
        if tier in ("enterprise", "ent", "team"):
            tier = "enterprise"
        elif tier in ("pro", "professional", "paid"):
            tier = "pro"
        else:
            tier = "free"

        return (user_id, tier)
    except Exception:
        return ("unknown", "free")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limiter applied to scan-creation endpoints."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only rate-limit POST to scan endpoints
        if request.method != "POST" or request.url.path not in _RATE_LIMITED_PATHS:
            return await call_next(request)

        # D-061: Per-user rate limiting based on JWT tier claims
        auth = request.headers.get("Authorization", "")
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP", "")
            or (request.client.host if request.client else "unknown")
        )

        if auth and auth.startswith("Bearer "):
            token = auth[len("Bearer "):].strip()
            user_id, tier = _extract_user_tier(token)

            # Enterprise: unlimited (skip rate limit entirely)
            if tier == "enterprise":
                response = await call_next(request)
                response.headers["X-RateLimit-Tier"] = "enterprise"
                response.headers["X-RateLimit-Remaining"] = "unlimited"
                return response

            # Pro: 100/day per user
            if tier == "pro":
                limit, window = _USER_PRO_LIMIT, _USER_PRO_WINDOW
            else:
                # Free authenticated: 3/day per user
                limit, window = _USER_FREE_LIMIT, _USER_FREE_WINDOW

            key = f"rl:user:{user_id}:{window}"
        else:
            # Unauthenticated: IP-based global limit (10/hr)
            tier = "free"
            limit, window = _FREE_LIMIT, _FREE_WINDOW
            key = f"rl:{client_ip}:{window}"

        # Check rate limit (Redis preferred, in-memory fallback)
        result = await _redis_check(key, limit, window)
        if result is None:
            allowed, remaining = _in_memory_check(key, limit, window)
        else:
            allowed, remaining = result

        if not allowed:
            logger.warning("Rate limit exceeded: ip=%s tier=%s limit=%d/%ds", client_ip, tier, limit, window)
            upgrade_msg = (
                "Upgrade to Pro for 100 scans/day: https://zaphscore.zaphenath.app/pricing"
                if tier == "free" else
                "Contact us for Enterprise: https://zaphscore.zaphenath.app/pricing"
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "limit": limit,
                    "window_seconds": window,
                    "tier": tier,
                    "retry_after": window,
                    "upgrade": upgrade_msg,
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
