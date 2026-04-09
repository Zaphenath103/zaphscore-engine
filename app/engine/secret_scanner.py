"""
ZSE Secret Scanner — TruffleHog integration for detecting leaked secrets.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

TRUFFLEHOG_TIMEOUT = 180  # seconds


def _redact_secret(raw: str) -> str:
    """D-009: Fully redact the secret — show ZERO characters of the actual value.

    Showing even 4 chars (e.g. "ghp_", "AKIA") reveals the secret type and
    confirms to an attacker exactly what was found. Detector name already
    communicates the type without leaking credential data.
    """
    if not raw:
        return "[REDACTED]"
    return "[REDACTED]"


def _extract_detector_name(result: dict) -> str:
    """Extract a human-readable detector name from trufflehog output."""
    # TruffleHog v3 format
    detector_name = result.get("DetectorName", "")
    if detector_name:
        return detector_name

    # Fallback: detectorType field
    detector_type = result.get("DetectorType", 0)
    detector_map = {
        0: "Unknown Secret",
        1: "AWS Access Key",
        2: "GitHub Token",
        3: "Slack Token",
        4: "Google API Key",
        5: "Stripe Key",
    }
    return detector_map.get(detector_type, f"Secret (type {detector_type})")


async def scan_secrets(repo_dir: str) -> list[Finding]:
    """Run TruffleHog filesystem scan for leaked secrets.

    Args:
        repo_dir: Absolute path to the cloned repository.

    Returns:
        List of Finding objects, all with severity=critical.
        Returns empty list if trufflehog is not installed.
    """
    # Check if trufflehog is available
    if not shutil.which("trufflehog"):
        logger.warning(
            "TruffleHog is not installed — secret scan skipped. "
            "Install from: https://github.com/trufflesecurity/trufflehog"
        )
        return []

    findings: list[Finding] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "trufflehog", "filesystem",
            "--json",
            "--no-update",
            repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=TRUFFLEHOG_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error("TruffleHog timed out after %ds for %s", TRUFFLEHOG_TIMEOUT, repo_dir)
            return []

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode not in (0, 1):
            logger.warning(
                "TruffleHog exited with code %d: %s",
                proc.returncode, stderr_text[:300],
            )

        # TruffleHog outputs one JSON object per line
        if not stdout_text.strip():
            logger.info("TruffleHog found no secrets in %s", repo_dir)
            return []

        for line in stdout_text.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector_name = _extract_detector_name(result)

            # Extract the raw secret for redaction
            raw_secret = result.get("Raw", "")
            redacted = _redact_secret(raw_secret)

            # Source metadata
            source_meta = result.get("SourceMetadata", {})
            source_data = source_meta.get("Data", {})
            # TruffleHog filesystem source
            filesystem_data = source_data.get("Filesystem", {})
            file_path = filesystem_data.get("file", "")
            line_num = filesystem_data.get("line")

            # Make path relative
            if file_path.startswith(repo_dir):
                file_path = file_path[len(repo_dir):].lstrip("/\\")

            # Verified status
            verified = result.get("Verified", False)
            verification_note = " (verified active)" if verified else " (unverified)"

            findings.append(Finding(
                type=FindingType.secret,
                severity=Severity.critical,
                title=f"{detector_name}{verification_note}",
                description=(
                    f"Detected secret: {redacted}\n"
                    f"Detector: {detector_name}\n"
                    f"Verified: {'Yes — this secret is confirmed active' if verified else 'No — may be inactive or rotated'}"
                ),
                file_path=file_path or None,
                line=line_num if isinstance(line_num, int) else None,
            ))

        logger.info("TruffleHog found %d secrets in %s", len(findings), repo_dir)

    except FileNotFoundError:
        logger.warning("TruffleHog binary not found — secret scan skipped")
    except Exception as exc:
        logger.error("Secret scan failed: %s", exc, exc_info=True)

    return findings
