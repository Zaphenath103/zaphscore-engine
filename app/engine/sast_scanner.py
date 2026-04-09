"""
ZSE SAST Scanner — Semgrep integration for static analysis security testing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Optional

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

SEMGREP_TIMEOUT = 300  # seconds

# Semgrep severity → ZSE severity
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.high,
    "WARNING": Severity.medium,
    "INFO": Severity.low,
}


def _clean_check_id(check_id: str) -> str:
    """Clean semgrep check_id into a readable title.

    e.g. 'python.lang.security.audit.exec-detected' → 'Exec Detected'
    """
    # Take the last segment after the last dot
    parts = check_id.rsplit(".", 1)
    last = parts[-1] if parts else check_id
    # Convert kebab-case / snake_case to title case
    return last.replace("-", " ").replace("_", " ").title()


async def scan_sast(repo_dir: str) -> list[Finding]:
    """Run Semgrep SAST scan on the repository.

    Args:
        repo_dir: Absolute path to the cloned repository.

    Returns:
        List of Finding objects from static analysis.
        Returns empty list if semgrep is not installed.
    """
    # Check if semgrep is available
    if not shutil.which("semgrep"):
        logger.warning(
            "Semgrep is not installed — SAST scan skipped. "
            "Install with: pip install semgrep"
        )
        return []

    findings: list[Finding] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=SEMGREP_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error("Semgrep timed out after %ds for %s", SEMGREP_TIMEOUT, repo_dir)
            return []

        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        if proc.returncode not in (0, 1):
            # returncode 1 can mean "findings found" in some semgrep versions
            logger.warning("Semgrep exited with code %d: %s", proc.returncode, stderr_text[:300])

        # Parse JSON output
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        if not stdout_text.strip():
            logger.info("Semgrep produced no output for %s", repo_dir)
            return []

        try:
            data = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse semgrep JSON output: %s", exc)
            return []

        results = data.get("results", [])
        logger.info("Semgrep found %d results in %s", len(results), repo_dir)

        for result in results:
            check_id = result.get("check_id", "unknown")
            message = result.get("extra", {}).get("message", "")
            severity_str = result.get("extra", {}).get("severity", "WARNING")
            path = result.get("path", "")
            start_line = result.get("start", {}).get("line")

            # Map severity
            severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.medium)

            # Make path relative to repo_dir
            if path.startswith(repo_dir):
                path = path[len(repo_dir):].lstrip("/\\")

            findings.append(Finding(
                type=FindingType.sast,
                severity=severity,
                title=_clean_check_id(check_id),
                description=message[:1000] if message else f"Semgrep rule: {check_id}",
                file_path=path or None,
                line=start_line,
                rule_id=check_id,
            ))

    except FileNotFoundError:
        logger.warning("Semgrep binary not found — SAST scan skipped")
    except Exception as exc:
        logger.error("SAST scan failed: %s", exc, exc_info=True)

    return findings
