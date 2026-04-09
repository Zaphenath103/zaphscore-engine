"""ZSE Container Scanner — Trivy integration for container image and filesystem scanning."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger("zse.engine.container_scanner")

TRIVY_TIMEOUT = 300  # seconds

# Container-related filenames to detect
_CONTAINER_FILES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "containerfile",
}

# Trivy severity → ZSE severity
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "UNKNOWN": Severity.info,
}


def _has_container_files(repo_dir: str) -> bool:
    """Check if the repo contains any container-related files."""
    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", "venv", ".venv"}

    for dirpath, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        for fname in filenames:
            fname_lower = fname.lower()

            # Exact container file names
            if fname_lower in _CONTAINER_FILES:
                return True

            # *.dockerfile pattern
            if fname_lower.endswith(".dockerfile"):
                return True

    return False


def _map_severity(trivy_severity: str) -> Severity:
    """Map a Trivy severity string to ZSE Severity enum."""
    if isinstance(trivy_severity, str):
        return _SEVERITY_MAP.get(trivy_severity.upper(), Severity.medium)
    return Severity.medium


def _parse_vulnerabilities(data: dict, repo_dir: str) -> list[Finding]:
    """Parse Trivy filesystem scan JSON output for vulnerabilities."""
    findings: list[Finding] = []

    results = data.get("Results", [])
    for result in results:
        target = result.get("Target", "")
        vulnerabilities = result.get("Vulnerabilities") or []

        for vuln in vulnerabilities:
            vuln_id = vuln.get("VulnerabilityID", "")
            title = vuln.get("Title", vuln_id)
            description_parts = []
            if title:
                description_parts.append(title)
            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            if pkg_name and installed_version:
                description_parts.append(f"Package: {pkg_name}@{installed_version}")
            vuln_desc = vuln.get("Description", "")
            if vuln_desc:
                description_parts.append(vuln_desc[:500])

            # Extract CVSS v3 score
            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for source_data in cvss_data.values():
                if isinstance(source_data, dict) and "V3Score" in source_data:
                    cvss_score = source_data["V3Score"]
                    break

            # Make target path relative
            file_path = target
            if file_path.startswith(repo_dir):
                file_path = file_path[len(repo_dir):].lstrip("/\\")

            findings.append(Finding(
                type=FindingType.vulnerability,
                severity=_map_severity(vuln.get("Severity", "MEDIUM")),
                title=f"{vuln_id}: {title}"[:200] if title != vuln_id else vuln_id[:200],
                description="\n".join(description_parts)[:1000],
                file_path=file_path or None,
                cve_id=vuln_id or None,
                fix_version=vuln.get("FixedVersion") or None,
                cvss_score=cvss_score,
            ))

    return findings


def _parse_misconfigurations(data: dict, repo_dir: str) -> list[Finding]:
    """Parse Trivy config scan JSON output for misconfigurations."""
    findings: list[Finding] = []

    results = data.get("Results", [])
    for result in results:
        target = result.get("Target", "")
        misconfigs = result.get("Misconfigurations") or []

        for misconf in misconfigs:
            misconf_id = misconf.get("ID", "")
            misconf_title = misconf.get("Title", "")
            message = misconf.get("Message", "")
            resolution = misconf.get("Resolution", "")

            description_parts = []
            if message:
                description_parts.append(message)
            if resolution:
                description_parts.append(f"Resolution: {resolution}")

            # Make target path relative
            file_path = target
            if file_path.startswith(repo_dir):
                file_path = file_path[len(repo_dir):].lstrip("/\\")

            findings.append(Finding(
                type=FindingType.iac,
                severity=_map_severity(misconf.get("Severity", "MEDIUM")),
                title=f"{misconf_id}: {misconf_title}"[:200] if misconf_title else misconf_id[:200],
                description="\n".join(description_parts)[:1000],
                file_path=file_path or None,
                rule_id=misconf_id or None,
            ))

    return findings


async def scan_containers(repo_dir: str) -> list[Finding]:
    """Run Trivy container/filesystem scan for vulnerabilities and misconfigurations.

    Args:
        repo_dir: Absolute path to the cloned repository.

    Returns:
        List of Finding objects for container vulnerabilities and Dockerfile misconfigs.
        Returns empty list if no container files detected or trivy not installed.
    """
    # Quick check: are there any container files?
    loop = asyncio.get_event_loop()
    has_containers = await loop.run_in_executor(None, _has_container_files, repo_dir)
    if not has_containers:
        logger.info("No container files detected in %s — skipping Trivy scan", repo_dir)
        return []

    # Check if trivy is available
    if not shutil.which("trivy"):
        logger.warning(
            "Trivy is not installed — container scan skipped. "
            "Install from: https://github.com/aquasecurity/trivy"
        )
        return []

    findings: list[Finding] = []

    # -----------------------------------------------------------------------
    # Scan 1: Filesystem vulnerability scan
    # -----------------------------------------------------------------------
    try:
        proc = await asyncio.create_subprocess_exec(
            "trivy", "filesystem",
            "--scanners", "vuln,misconfig",
            "--format", "json",
            "--quiet",
            repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=TRIVY_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error("Trivy filesystem scan timed out after %ds for %s", TRIVY_TIMEOUT, repo_dir)
            return []

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode not in (0, 1):
            logger.warning(
                "Trivy filesystem exited with code %d: %s",
                proc.returncode, stderr_text[:300],
            )

        if stdout_text.strip():
            try:
                data = json.loads(stdout_text)
            except json.JSONDecodeError as exc:
                logger.error("Failed to parse Trivy filesystem JSON output: %s", exc)
                data = {}

            findings.extend(_parse_vulnerabilities(data, repo_dir))
            findings.extend(_parse_misconfigurations(data, repo_dir))

    except FileNotFoundError:
        logger.warning("Trivy binary not found — container filesystem scan skipped")
    except Exception as exc:
        logger.error("Trivy filesystem scan failed: %s", exc, exc_info=True)

    # -----------------------------------------------------------------------
    # Scan 2: Config-only scan for Dockerfile misconfigurations
    # -----------------------------------------------------------------------
    try:
        proc = await asyncio.create_subprocess_exec(
            "trivy", "config",
            "--format", "json",
            "--quiet",
            repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=TRIVY_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error("Trivy config scan timed out after %ds for %s", TRIVY_TIMEOUT, repo_dir)
            return findings  # return what we have so far

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode not in (0, 1):
            logger.warning(
                "Trivy config exited with code %d: %s",
                proc.returncode, stderr_text[:300],
            )

        if stdout_text.strip():
            try:
                data = json.loads(stdout_text)
            except json.JSONDecodeError as exc:
                logger.error("Failed to parse Trivy config JSON output: %s", exc)
                data = {}

            config_findings = _parse_misconfigurations(data, repo_dir)
            # Deduplicate against findings we already have from the filesystem scan
            existing_ids = {(f.rule_id, f.file_path) for f in findings if f.rule_id}
            for cf in config_findings:
                if (cf.rule_id, cf.file_path) not in existing_ids:
                    findings.append(cf)

    except FileNotFoundError:
        logger.warning("Trivy binary not found — container config scan skipped")
    except Exception as exc:
        logger.error("Trivy config scan failed: %s", exc, exc_info=True)

    logger.info("Trivy found %d container findings in %s", len(findings), repo_dir)
    return findings
