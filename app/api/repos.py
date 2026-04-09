"""
ZSE Repo API — lightweight proxy to the GitHub REST API for repo metadata.
"""

from __future__ import annotations

import logging

import aiohttp
from fastapi import APIRouter, HTTPException

from app.config import settings
from app.models.schemas import RepoInfo

logger = logging.getLogger("zse.api.repos")
router = APIRouter(prefix="/api/repos", tags=["repos"])

GITHUB_API = "https://api.github.com"


def _github_headers() -> dict[str, str]:
    """Build request headers — include auth token when available."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = settings.GITHUB_TOKEN
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@router.get("/{owner}/{repo}", response_model=RepoInfo)
async def get_repo_info(owner: str, repo: str) -> RepoInfo:
    """Fetch repository metadata from the GitHub API.

    Uses the configured GITHUB_TOKEN for higher rate limits (5 000 req/hr
    with auth vs 60 req/hr anonymous).
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}"

    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers=_github_headers()) as resp:
            status = resp.status
            if status == 404:
                raise HTTPException(status_code=404, detail="Repository not found on GitHub")
            if status == 403:
                raise HTTPException(
                    status_code=429,
                    detail="GitHub API rate limit exceeded. Configure GITHUB_TOKEN for higher limits.",
                )
            if status != 200:
                text = await resp.text()
                logger.error("GitHub API returned %d: %s", status, text[:200])
                raise HTTPException(
                    status_code=502,
                    detail=f"GitHub API error: {status}",
                )
            data = await resp.json()

    return RepoInfo(
        owner=data.get("owner", {}).get("login", owner),
        repo=data.get("name", repo),
        stars=data.get("stargazers_count", 0),
        language=data.get("language"),
        size_kb=data.get("size", 0),
        default_branch=data.get("default_branch", "main"),
    )
