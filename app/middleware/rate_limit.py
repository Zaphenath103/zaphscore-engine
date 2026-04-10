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

def _resolve_client_ip(request: Request) -> str:
    """D-072: Resolve client IP using the rightmost (proxy-appended) hop.

    Rightmost = added by our infrastructure (Railway/Vercel), not spoofable by clients.
    Falls back to direct TCP address if no proxy headers present.
    """
    x_forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    x_real_ip = request.headers.get("X-Real-IP", "").strip()
    direct_ip = request.client.host if request.client else "unknown"

    if x_forwarded_for:
        hops = [h.strip() for h in x_forwarded_for.split(",") if h.strip()]
        return hops[-1] if hops else direct_ip
    if x_real_ip:
        return x_real_ip
    return direct_ip


def _decode_jwt_claims(token: str) -> dict:
    """Decode JWT payload without full verification (rate limit context only).

    We do a best-effort decode here — we're only reading the 'plan' claim
    to determine tier. Full verification happens in the auth dependency.
    Returns empty dict if decode fails.
    """
    try:
        import base64 as _b64, json as _json
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return _json.loads(_b64.urlsafe_b64decode(padded))
    except Exception:
        return {}


# D-061: Per-user daily limits by plan tier
# Free users: 3 scans/day (encourages upgrade)
# Pro users: 100 scans/day (generous for power users)
# Enterprise users: effectively unlimited (10 000/day)
_TIER_LIMITS: dict[str, tuple[int, int]] = {
    "enterprise": (10_000, 86_400),
    "pro": (100, 86_400),
    "free": (3, 86_400),
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limiter applied to scan-creation endpoints.

    D-061: Per-user tier limits (free=3/day, pro=100/day, enterprise=unlimited).
    D-072: Hardened IP resolution using rightmost X-Forwarded-For hop.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only rate-limit POST to scan endpoints
        if request.method != "POST" or request.url.path not in _RATE_LIMITED_PATHS:
            return await call_next(request)

        # --- D-061: Determine rate limit tier from JWT claims ---
        auth = request.headers.get("Authorization", "")
        user_id: Optional[str] = None
        tier_name = "free"

        if auth and auth.startswith("Bearer "):
            token = auth[len("Bearer "):].strip()
            claims = _decode_jwt_claims(token)
            user_id = claims.get("sub") or claims.get("user_id")
            # Read plan from JWT app_metadata (Supabase convention)
            app_meta = claims.get("app_metadata", {}) or {}
            user_meta = claims.get("user_metadata", {}) or {}
            plan = (
                app_meta.get("plan")
                or user_meta.get("plan")
                or claims.get("plan")
                or "free"
            )
            tier_name = plan if plan in _TIER_LIMITS else "free"

        limit, window = _TIER_LIMITS.get(tier_name, _TIER_LIMITS["free"])

        # --- Build rate limit key (per-user when authenticated, per-IP otherwise) ---
        client_ip = _resolve_client_ip(request)
        if user_id:
            # Per-user key: user ID + daily window — avoids IP rotation bypasses
            key = f"rl:user:{user_id}:{window}"
        else:
            # Anonymous: IP-based
            key = f"rl:ip:{client_ip}:{window}"

        # --- Check rate limit (Redis preferred, in-memory fallback) ---
        result = await _redis_check(key, limit, window)
        if result is None:
            allowed, remaining = _in_memory_check(key, limit, window)
        else:
            allowed, remaining = result

        if not allowed:
            logger.warning(
                "Rate limit exceeded: ip=%s user_id=%s tier=%s limit=%d/%ds",
                client_ip, user_id or "anon", tier_name, limit, window,
            )
            upgrade_msg = (
                " Upgrade to Pro for 100 scans/day at zaphscore.zaphenath.app."
                if tier_name == "free" else ""
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded.{upgrade_msg}",
                    "limit": limit,
                    "window_seconds": window,
                    "tier": tier_name,
                    "retry_after": window,
                },
                headers={
                    "Retry-After": str(window),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Window": str(window),
                    "X-RateLimit-Tier": tier_name,
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Window"] = str(window)
        response.headers["X-RateLimit-Tier"] = tier_name
        return response
