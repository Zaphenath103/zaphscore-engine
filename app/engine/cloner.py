"""
ZSE Git Clone Handler — async repo cloning with validation and size checks.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Regex for validating GitHub URLs
_GITHUB_URL_RE = re.compile(
    r"^https?://(www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$"
)


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
            # Parse: ref: refs/heads/main	HEAD
            for line in stdout.splitlines():
                if line.startswith("ref:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ref = parts[1]
                        return ref.replace("refs/heads/", "")
    except Exception as exc:
        logger.warning("Failed to detect default branch for %s: %s", repo_url, exc)
    return "main"


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


async def clone_repo(
    repo_url: str,
    branch: Optional[str],
    dest_dir: str,
    timeout: int = 0,
    github_token: Optional[str] = None,
) -> str:
    """Clone a GitHub repo with --depth 1 into dest_dir.

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
        RuntimeError: If cloning fails on both specified and default branch.
        TimeoutError: If the clone exceeds the timeout.
    """
    owner, repo_name = parse_github_url(repo_url)
    clone_url = normalise_url(repo_url)

    # Inject token for private repos
    if github_token:
        clone_url = clone_url.replace(
            "https://", f"https://x-access-token:{github_token}@"
        )

    if timeout <= 0:
        timeout = settings.CLONE_TIMEOUT_SECONDS

    clone_dest = os.path.join(dest_dir, repo_name)

    async def _attempt_clone(target_branch: Optional[str]) -> tuple[int, str, str]:
        # Clean up any previous attempt
        if os.path.exists(clone_dest):
            shutil.rmtree(clone_dest, ignore_errors=True)

        args = ["clone", "--depth", "1"]
        if target_branch:
            args.extend(["--branch", target_branch])
        args.extend(["--", clone_url, clone_dest])

        return await _run_git(args, timeout=timeout)

    # First attempt: user-specified branch
    rc, stdout, stderr = await _attempt_clone(branch)

    if rc != 0 and branch:
        logger.warning(
            "Branch '%s' failed for %s/%s, falling back to default branch. stderr=%s",
            branch, owner, repo_name, stderr[:200],
        )
        default_branch = await _get_default_branch(clone_url)
        rc, stdout, stderr = await _attempt_clone(default_branch)
        if rc != 0:
            # Last resort: clone without specifying branch
            rc, stdout, stderr = await _attempt_clone(None)

    if rc != 0:
        raise RuntimeError(
            f"Git clone failed for {owner}/{repo_name}: {stderr[:500]}"
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
        "Cloned %s/%s (%.1f MB) to %s", owner, repo_name, size_mb, clone_dest
    )
    return clone_dest
