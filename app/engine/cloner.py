"""
ZSE Git Clone Handler — async repo cloning with validation and size checks.

Supports two strategies:
  1. Git subprocess (preferred — full history support, works on Docker/Railway)
  2. GitHub API tarball download (fallback — works on Vercel serverless where git
     is not installed)

The strategy is auto-detected at runtime based on whether the `git` binary exists.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import re
import shutil
import tarfile
from pathlib import Path
from typing import Optional

import aiohttp

from app.config import settings

logger = logging.getLogger(__name__)

# Regex for validating GitHub URLs
_GITHUB_URL_RE = re.compile(
    r"^https?://(www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$"
)

# Cache the git availability check
_GIT_AVAILABLE: Optional[bool] = None


def _has_git() -> bool:
    """Check if git is actually executable (not just on PATH).

    Uses shutil.which first for speed, then verifies by running `git --version`.
    This catches environments where git exists on the filesystem but subprocess
    execution is blocked (e.g., Vercel serverless sandbox).
    Cached after first call.
    """
    global _GIT_AVAILABLE
    if _GIT_AVAILABLE is None:
        if shutil.which("git") is None:
            _GIT_AVAILABLE = False
            logger.warning("git not found on PATH — using GitHub API tarball download")
        else:
            # Actually try to run git — some sandboxes block subprocess even if git exists
            try:
                import subprocess
                result = subprocess.run(
                    ["git", "--version"],
                    capture_output=True,
                    timeout=5,
                )
                _GIT_AVAILABLE = result.returncode == 0
            except Exception as exc:
                _GIT_AVAILABLE = False
                logger.warning("git found on PATH but not executable (%s) — using tarball", exc)
        if _GIT_AVAILABLE:
            logger.info("git is available — using native git clone")
        else:
            logger.info("git unavailable — using GitHub API tarball download")
    return _GIT_AVAILABLE


def parse_github_url(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL. Raises ValueError if invalid."""
    m = _GITHUB_URL_RE.match(repo_url.strip().rstrip("/"))
    if not m:
        raise ValueError(f"Invalid GitHub URL: {repo_url}")
    return m.group("owner"), m.group("repo")


def normalise_url(repo_url: str) -> str:
    """Ensure the URL is https:// prefixed."""
    url = repo_url.strip().rstrip("/")
    if not url.startswith("http"):
        url = f"https://{url}"
    if not url.endswith(".git"):
        url = f"{url}.git"
    return url


# ---------------------------------------------------------------------------
# Strategy 1: Native git subprocess
# ---------------------------------------------------------------------------

async def _run_git(
    args: list[str],
    cwd: Optional[str] = None,
    timeout: int = 120,
) -> tuple[int, str, str]:
    """Run a git subprocess and return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"Git operation timed out after {timeout}s: git {' '.join(args)}")

    stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
    stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
    return proc.returncode, stdout, stderr


async def _get_default_branch(repo_url: str, timeout: int = 30) -> str:
    """Query the remote for its default branch via ls-remote."""
    try:
        rc, stdout, stderr = await _run_git(
            ["ls-remote", "--symref", repo_url, "HEAD"],
            timeout=timeout,
        )
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                if line.startswith("ref:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ref = parts[1]
                        return ref.replace("refs/heads/", "")
    except Exception as exc:
        logger.warning("Failed to detect default branch for %s: %s", repo_url, exc)
    return "main"


async def _clone_via_git(
    repo_url: str,
    owner: str,
    repo_name: str,
    branch: Optional[str],
    dest_dir: str,
    timeout: int,
    github_token: Optional[str],
) -> str:
    """Clone using native git subprocess."""
    clone_url = normalise_url(repo_url)

    if github_token:
        clone_url = clone_url.replace(
            "https://", f"https://x-access-token:{github_token}@"
        )

    clone_dest = os.path.join(dest_dir, repo_name)

    async def _attempt_clone(target_branch: Optional[str]) -> tuple[int, str, str]:
        if os.path.exists(clone_dest):
            shutil.rmtree(clone_dest, ignore_errors=True)
        args = ["clone", "--depth", "1"]
        if target_branch:
            args.extend(["--branch", target_branch])
        args.extend(["--", clone_url, clone_dest])
        return await _run_git(args, timeout=timeout)

    rc, stdout, stderr = await _attempt_clone(branch)

    if rc != 0 and branch:
        logger.warning(
            "Branch '%s' failed for %s/%s, falling back to default branch. stderr=%s",
            branch, owner, repo_name, stderr[:200],
        )
        default_branch = await _get_default_branch(clone_url)
        rc, stdout, stderr = await _attempt_clone(default_branch)
        if rc != 0:
            rc, stdout, stderr = await _attempt_clone(None)

    if rc != 0:
        raise RuntimeError(
            f"Git clone failed for {owner}/{repo_name}: {stderr[:500]}"
        )

    return clone_dest


# ---------------------------------------------------------------------------
# Strategy 2: GitHub API tarball download (serverless-friendly)
# ---------------------------------------------------------------------------

async def _get_default_branch_api(
    owner: str, repo_name: str, github_token: Optional[str] = None
) -> str:
    """Get default branch from GitHub API."""
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    url = f"https://api.github.com/repos/{owner}/{repo_name}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("default_branch", "main")
                else:
                    logger.warning("GitHub API repo info returned %d for %s/%s", resp.status, owner, repo_name)
    except Exception as exc:
        logger.warning("Failed to get default branch via API for %s/%s: %s", owner, repo_name, exc)
    return "main"


async def _clone_via_tarball(
    repo_url: str,
    owner: str,
    repo_name: str,
    branch: Optional[str],
    dest_dir: str,
    timeout: int,
    github_token: Optional[str],
) -> str:
    """Download and extract repo via GitHub tarball API.

    Uses https://api.github.com/repos/{owner}/{repo}/tarball/{ref}
    which returns a tar.gz archive of the repo contents.
    Works without git installed — perfect for Vercel serverless.
    """
    if not branch:
        branch = await _get_default_branch_api(owner, repo_name, github_token)

    tarball_url = f"https://api.github.com/repos/{owner}/{repo_name}/tarball/{branch}"
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    logger.info("Downloading tarball for %s/%s@%s", owner, repo_name, branch)

    clone_dest = os.path.join(dest_dir, repo_name)
    os.makedirs(clone_dest, exist_ok=True)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                tarball_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
            ) as resp:
                if resp.status == 404:
                    # Try without branch (default)
                    fallback_url = f"https://api.github.com/repos/{owner}/{repo_name}/tarball"
                    async with session.get(
                        fallback_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=True,
                    ) as resp2:
                        if resp2.status != 200:
                            raise RuntimeError(
                                f"GitHub tarball download failed for {owner}/{repo_name}: "
                                f"HTTP {resp2.status}"
                            )
                        tar_bytes = await resp2.read()
                elif resp.status != 200:
                    raise RuntimeError(
                        f"GitHub tarball download failed for {owner}/{repo_name}@{branch}: "
                        f"HTTP {resp.status}"
                    )
                else:
                    tar_bytes = await resp.read()

    except aiohttp.ClientError as exc:
        raise RuntimeError(
            f"Network error downloading {owner}/{repo_name}: {exc}"
        ) from exc

    # Extract tarball
    # GitHub tarballs have a top-level directory like "owner-repo-sha/"
    # We extract contents into clone_dest directly
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _extract_tarball, tar_bytes, clone_dest)

    logger.info("Tarball extracted for %s/%s to %s", owner, repo_name, clone_dest)
    return clone_dest


def _extract_tarball(tar_bytes: bytes, dest: str) -> None:
    """Extract a GitHub tarball, stripping the top-level directory."""
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        # Find the common prefix (GitHub adds "owner-repo-sha/" as root)
        members = tf.getmembers()
        if not members:
            raise RuntimeError("Empty tarball — repository may be empty or private")

        # The first entry is usually the top-level directory
        prefix = members[0].name.split("/")[0] + "/"

        for member in members:
            # Strip the top-level directory prefix
            if member.name.startswith(prefix):
                member.name = member.name[len(prefix):]
            elif "/" in member.name:
                # Some tarballs don't have a consistent prefix
                parts = member.name.split("/", 1)
                member.name = parts[1] if len(parts) > 1 else parts[0]

            if not member.name or member.name == ".":
                continue

            # Security: prevent path traversal
            target = os.path.join(dest, member.name)
            if not os.path.abspath(target).startswith(os.path.abspath(dest)):
                continue

            if member.isdir():
                os.makedirs(target, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with tf.extractfile(member) as src:
                    if src:
                        with open(target, "wb") as dst:
                            dst.write(src.read())


# ---------------------------------------------------------------------------
# Size check helper
# ---------------------------------------------------------------------------

async def _dir_size_mb(path: str) -> float:
    """Calculate directory size in MB (runs in executor to avoid blocking)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _calc_dir_size, path)


def _calc_dir_size(path: str) -> float:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total / (1024 * 1024)


# ---------------------------------------------------------------------------
# Public API — auto-detects strategy
# ---------------------------------------------------------------------------

async def clone_repo(
    repo_url: str,
    branch: Optional[str],
    dest_dir: str,
    timeout: int = 0,
    github_token: Optional[str] = None,
) -> str:
    """Clone a GitHub repo into dest_dir.

    Auto-detects whether to use native git or GitHub API tarball:
      - If git is on PATH → git clone --depth 1
      - If git is missing → GitHub API tarball download + extract

    Args:
        repo_url: Full GitHub HTTPS URL.
        branch: Branch to clone; falls back to default branch if it fails.
        dest_dir: Parent directory — the repo is cloned into a subdirectory.
        timeout: Clone timeout in seconds. 0 = use settings.CLONE_TIMEOUT_SECONDS.
        github_token: Optional PAT for private repos.

    Returns:
        Absolute path to the cloned repo directory.

    Raises:
        ValueError: If the URL is invalid.
        RuntimeError: If cloning fails.
        TimeoutError: If the clone exceeds the timeout.
    """
    owner, repo_name = parse_github_url(repo_url)

    if timeout <= 0:
        timeout = settings.CLONE_TIMEOUT_SECONDS

    # Use env-level token if not provided
    if not github_token and settings.GITHUB_TOKEN:
        github_token = settings.GITHUB_TOKEN

    # Auto-select strategy — tarball is the fallback when git is unavailable or broken
    if _has_git():
        try:
            clone_dest = await _clone_via_git(
                repo_url, owner, repo_name, branch, dest_dir, timeout, github_token,
            )
        except (FileNotFoundError, OSError, PermissionError) as exc:
            # Git found on PATH but execution failed (sandbox restriction, broken binary, etc.)
            # Reset cache so future calls also use tarball in this process
            global _GIT_AVAILABLE
            _GIT_AVAILABLE = False
            logger.warning(
                "git clone raised %s (%s) — falling back to tarball download", type(exc).__name__, exc
            )
            clone_dest = await _clone_via_tarball(
                repo_url, owner, repo_name, branch, dest_dir, timeout, github_token,
            )
    else:
        clone_dest = await _clone_via_tarball(
            repo_url, owner, repo_name, branch, dest_dir, timeout, github_token,
        )

    # Size check
    size_mb = await _dir_size_mb(clone_dest)
    max_size = settings.MAX_REPO_SIZE_MB
    if size_mb > max_size:
        shutil.rmtree(clone_dest, ignore_errors=True)
        raise RuntimeError(
            f"Repository {owner}/{repo_name} is {size_mb:.1f} MB, exceeding the "
            f"{max_size} MB limit. Clone aborted."
        )

    logger.info(
        "Cloned %s/%s (%.1f MB) to %s [strategy=%s]",
        owner, repo_name, size_mb, clone_dest,
        "git" if _has_git() else "tarball",
    )
    return clone_dest
