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


# ---------------------------------------------------------------------------
# D-687: Secret validity checking
# ---------------------------------------------------------------------------

import aiohttp as _aiohttp

# Lightweight liveness probes per detector type
_VALIDITY_ENDPOINTS: dict = {
    "GitHub": {
        "url": "https://api.github.com/user",
        "header": "Authorization",
        "prefix": "token ",
        "valid_codes": {200},
        "invalid_codes": {401},
    },
    "GitHubOauth2": {
        "url": "https://api.github.com/user",
        "header": "Authorization",
        "prefix": "Bearer ",
        "valid_codes": {200},
        "invalid_codes": {401},
    },
    "Stripe": {
        "url": "https://api.stripe.com/v1/account",
        "header": "Authorization",
        "prefix": "Bearer ",
        "valid_codes": {200},
        "invalid_codes": {401, 403},
    },
}


async def check_secret_validity(
    detector_name: str,
    raw_secret: str,
    already_verified: bool,
) -> tuple:
    """D-687: Probe liveness of a detected secret.

    Args:
        detector_name: Service name returned by TruffleHog (e.g. 'GitHub').
        raw_secret: The raw credential value.
        already_verified: True if TruffleHog already confirmed via its own probe.

    Returns:
        (is_live, note) where is_live=True if credential is confirmed active.
    """
    if already_verified:
        return True, "Verified active by TruffleHog probe"

    if not raw_secret:
        return False, "Cannot probe -- secret value unavailable"

    endpoint = _VALIDITY_ENDPOINTS.get(detector_name)
    if not endpoint:
        return False, f"Validity probe not implemented for '{detector_name}'"

    try:
        headers = {
            endpoint["header"]: endpoint["prefix"] + raw_secret,
            "User-Agent": "ZaphScore-Engine/0.1 (security-scan)",
        }
        timeout = _aiohttp.ClientTimeout(total=8)
        async with _aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(endpoint["url"], headers=headers) as resp:
                if resp.status in endpoint.get("valid_codes", set()):
                    return True, f"Confirmed live via {endpoint['url']} (HTTP {resp.status})"
                elif resp.status in endpoint.get("invalid_codes", set()):
                    return False, f"Appears rotated/invalid (HTTP {resp.status})"
                else:
                    return False, f"Inconclusive probe (HTTP {resp.status})"
    except Exception as exc:
        return False, f"Probe error: {type(exc).__name__} -- treat as potentially live"


# ---------------------------------------------------------------------------
# D-755: Multi-rule secret correlation
# ---------------------------------------------------------------------------

from collections import defaultdict as _defaultdict


def correlate_secrets(raw_findings: list) -> list:
    """D-755: Group multi-detector hits on the same file into correlated findings.

    When multiple secret detectors fire on the same file, that strongly indicates
    a credentials dump. Correlated findings are surfaced with elevated severity
    context listing all detectors found -- mirrors Snyk multi-rule correlation.

    Args:
        raw_findings: List of raw TruffleHog result dicts.

    Returns:
        Modified list where same-file multi-detector hits are correlated.
    """
    by_file: dict = _defaultdict(list)
    no_file: list = []

    for result in raw_findings:
        source_meta = result.get("SourceMetadata", {})
        source_data = source_meta.get("Data", {})
        filesystem_data = source_data.get("Filesystem", {})
        file_path = filesystem_data.get("file", "")
        if file_path:
            by_file[file_path].append(result)
        else:
            no_file.append(result)

    correlated: list = list(no_file)

    for file_path, results in by_file.items():
        if len(results) == 1:
            correlated.extend(results)
        else:
            detectors = [_extract_detector_name(r) for r in results]
            unique_detectors = list(dict.fromkeys(detectors))

            base = dict(results[0])
            base["_correlated"] = True
            base["_correlated_detectors"] = unique_detectors
            base["_correlated_count"] = len(results)
            correlated.append(base)

            logger.debug(
                "Correlated %d secret detectors on %s: %s",
                len(results), file_path, ", ".join(unique_detectors),
            )

    return correlated
