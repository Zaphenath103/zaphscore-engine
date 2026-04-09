"""
ZSE GitHub API Client — Async client for GitHub REST API v3.

Supports three auth modes (checked in order):
  1. GitHub App JWT (GITHUB_APP_ID + GITHUB_PRIVATE_KEY)
  2. Personal Access Token (GITHUB_TOKEN)
  3. Unauthenticated (60 req/hr)
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any

import aiohttp

from app.config import settings

logger = logging.getLogger("zse.github")

API_BASE = "https://api.github.com"
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds


class GitHubClient:
    """Async GitHub REST API client with rate-limit awareness and retry logic."""

    def __init__(self, token_override: str | None = None) -> None:
        self._session: aiohttp.ClientSession | None = None
        self._token_override = token_override

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = self._build_headers()
            self._session = aiohttp.ClientSession(
                base_url=API_BASE,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ZSE/1.0 (Zaphenath Security Engine)",
        }

        token = self._resolve_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        return headers

    def _resolve_token(self) -> str | None:
        """Determine which authentication token to use."""
        if self._token_override:
            return self._token_override

        # GitHub App JWT auth
        if settings.GITHUB_APP_ID and settings.GITHUB_PRIVATE_KEY:
            return self._generate_app_jwt()

        # PAT fallback
        if settings.GITHUB_TOKEN:
            return settings.GITHUB_TOKEN

        logger.warning("No GitHub token configured — using unauthenticated access (60 req/hr).")
        return None

    def _generate_app_jwt(self) -> str:
        """Generate a JWT for GitHub App authentication.

        Requires PyJWT and cryptography packages.  Falls back to PAT if not
        installed.
        """
        try:
            import jwt  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("PyJWT not installed — falling back to PAT auth.")
            return settings.GITHUB_TOKEN or ""

        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": settings.GITHUB_APP_ID,
        }

        private_key = settings.GITHUB_PRIVATE_KEY
        # If it looks like a file path, read it
        if not private_key.startswith("-----") and len(private_key) < 500:
            try:
                with open(private_key, "r") as f:
                    private_key = f.read()
            except FileNotFoundError:
                logger.error("GitHub App private key file not found: %s", private_key)
                return settings.GITHUB_TOKEN or ""

        return jwt.encode(payload, private_key, algorithm="RS256")

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # Core request method with retry + rate-limit handling
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Execute an API request with retries and rate-limit handling."""
        session = await self._get_session()

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.request(method, path, params=params) as resp:
                    # Log rate limit status
                    remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                    limit = resp.headers.get("X-RateLimit-Limit", "?")
                    reset_ts = resp.headers.get("X-RateLimit-Reset", "")
                    logger.debug(
                        "GitHub %s %s — %d — rate-limit: %s/%s",
                        method, path, resp.status, remaining, limit,
                    )

                    # Rate limited
                    if resp.status == 403 and remaining == "0":
                        reset_at = int(reset_ts) if reset_ts else int(time.time()) + 60
                        wait = max(reset_at - int(time.time()), 1)
                        logger.warning(
                            "GitHub rate limit hit — waiting %ds until reset.", wait
                        )
                        await asyncio.sleep(min(wait, 120))  # cap at 2 min
                        continue

                    # Server error — retry
                    if resp.status >= 500:
                        if attempt < MAX_RETRIES:
                            delay = BACKOFF_BASE * (2 ** (attempt - 1))
                            logger.warning(
                                "GitHub %d on %s %s — retry %d/%d in %.1fs",
                                resp.status, method, path, attempt, MAX_RETRIES, delay,
                            )
                            await asyncio.sleep(delay)
                            continue
                        resp.raise_for_status()

                    # Client error (4xx)
                    if resp.status >= 400:
                        body = await resp.text()
                        logger.error(
                            "GitHub %d on %s %s — %s",
                            resp.status, method, path, body[:500],
                        )
                        resp.raise_for_status()

                    return await resp.json()

            except aiohttp.ClientError as exc:
                if attempt < MAX_RETRIES:
                    delay = BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning(
                        "GitHub request error on %s %s: %s — retry %d/%d in %.1fs",
                        method, path, exc, attempt, MAX_RETRIES, delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    raise

        # Should not reach here, but satisfy type checker
        raise RuntimeError(f"GitHub request failed after {MAX_RETRIES} retries: {method} {path}")

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def get_repo_info(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch key repository metadata."""
        data = await self._request("GET", f"/repos/{owner}/{repo}")
        assert isinstance(data, dict)
        return {
            "stars": data.get("stargazers_count", 0),
            "language": data.get("language"),
            "size": data.get("size", 0),  # in KB
            "default_branch": data.get("default_branch", "main"),
            "topics": data.get("topics", []),
            "has_wiki": data.get("has_wiki", False),
            "open_issues": data.get("open_issues_count", 0),
        }

    async def get_repo_tree(
        self, owner: str, repo: str, branch: str = "main"
    ) -> list[str]:
        """Get the full file tree of a repo (for manifest discovery before clone).

        Uses the Git Tree API with recursive=1.
        """
        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        assert isinstance(data, dict)
        tree = data.get("tree", [])
        return [
            item["path"]
            for item in tree
            if item.get("type") == "blob"
        ]

    async def get_file_content(
        self, owner: str, repo: str, path: str, branch: str = "main"
    ) -> str:
        """Fetch a single file's content (base64 decoded)."""
        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": branch},
        )
        assert isinstance(data, dict)
        content_b64 = data.get("content", "")
        # GitHub returns base64-encoded content with newlines
        return base64.b64decode(content_b64).decode("utf-8")


# ---------------------------------------------------------------------------
# Module-level convenience instance
# ---------------------------------------------------------------------------
_default_client: GitHubClient | None = None


async def get_client(token_override: str | None = None) -> GitHubClient:
    """Get or create the default GitHub client singleton."""
    global _default_client
    if token_override:
        return GitHubClient(token_override=token_override)
    if _default_client is None:
        _default_client = GitHubClient()
    return _default_client


async def close_client() -> None:
    """Close the default client session."""
    global _default_client
    if _default_client:
        await _default_client.close()
        _default_client = None
