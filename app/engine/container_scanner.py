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


# ---------------------------------------------------------------------------
# D-678: Dockerfile base image recommendation engine
# Closes the gap vs Snyk Container base-image upgrade suggestions.
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dataclass

BASE_IMAGE_RECOMMENDATIONS: dict[str, tuple[str, str]] = {
    "ubuntu:16.04":  ("ubuntu:22.04", "high"),
    "ubuntu:18.04":  ("ubuntu:22.04", "high"),
    "ubuntu:20.04":  ("ubuntu:24.04", "medium"),
    "ubuntu:22.04":  ("ubuntu:24.04", "low"),
    "debian:8":      ("debian:12-slim", "critical"),
    "debian:9":      ("debian:12-slim", "high"),
    "debian:10":     ("debian:12-slim", "medium"),
    "debian:11":     ("debian:12-slim", "low"),
    "debian:buster": ("debian:bookworm-slim", "medium"),
    "debian:stretch": ("debian:bookworm-slim", "high"),
    "python:3.6":    ("python:3.12-slim", "critical"),
    "python:3.7":    ("python:3.12-slim", "critical"),
    "python:3.8":    ("python:3.12-slim", "high"),
    "python:3.9":    ("python:3.12-slim", "medium"),
    "python:3.10":   ("python:3.12-slim", "low"),
    "python:3.11":   ("python:3.12-slim", "low"),
    "node:10":       ("node:20-slim", "critical"),
    "node:12":       ("node:20-slim", "critical"),
    "node:14":       ("node:20-slim", "high"),
    "node:16":       ("node:20-slim", "medium"),
    "node:18":       ("node:20-slim", "low"),
    "alpine:3.10":   ("alpine:3.20", "high"),
    "alpine:3.11":   ("alpine:3.20", "high"),
    "alpine:3.12":   ("alpine:3.20", "medium"),
    "alpine:3.14":   ("alpine:3.20", "low"),
    "openjdk:8":     ("eclipse-temurin:21-jre-jammy", "critical"),
    "openjdk:11":    ("eclipse-temurin:21-jre-jammy", "medium"),
    "openjdk:17":    ("eclipse-temurin:21-jre-jammy", "low"),
    "java:8":        ("eclipse-temurin:21-jre-jammy", "critical"),
    "nginx:1.18":    ("nginx:stable-alpine", "medium"),
    "nginx:1.20":    ("nginx:stable-alpine", "low"),
    "redis:5":       ("redis:7-alpine", "medium"),
    "redis:6":       ("redis:7-alpine", "low"),
    "postgres:10":   ("postgres:16-alpine", "high"),
    "postgres:12":   ("postgres:16-alpine", "medium"),
    "postgres:14":   ("postgres:16-alpine", "low"),
    "php:7.2":       ("php:8.3-fpm-alpine", "critical"),
    "php:7.4":       ("php:8.3-fpm-alpine", "medium"),
    "php:8.0":       ("php:8.3-fpm-alpine", "low"),
    "ruby:2.6":      ("ruby:3.3-alpine", "critical"),
    "ruby:2.7":      ("ruby:3.3-alpine", "medium"),
    "golang:1.18":   ("golang:1.22-alpine", "medium"),
    "golang:1.20":   ("golang:1.22-alpine", "low"),
    "gcr.io/distroless/static:nonroot": ("gcr.io/distroless/static-debian12:nonroot", "low"),
    "gcr.io/distroless/base:latest": ("gcr.io/distroless/base-debian12:nonroot", "low"),
}


@_dataclass
class ContainerFinding:
    """Result of a base-image recommendation check.

    Attributes:
        dockerfile_path: Relative path to the Dockerfile.
        current_image: The FROM image string in the Dockerfile.
        recommended_image: Suggested replacement image.
        severity: "critical" | "high" | "medium" | "low".
        reason: Human-readable explanation.
    """
    dockerfile_path: str
    current_image: str
    recommended_image: str
    severity: str
    reason: str


def _extract_from_statements(dockerfile_content: str) -> list[str]:
    """Extract all base images from a Dockerfile (multi-stage aware)."""
    images: list[str] = []
    for line in dockerfile_content.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            parts = stripped.split()
            if len(parts) >= 2:
                image_ref = parts[1]
                if not image_ref.startswith("$"):
                    images.append(image_ref)
    return images


def _normalise_image_ref(image_ref: str) -> str:
    """Normalise an image ref for lookup (lowercase, strip digest)."""
    if "@" in image_ref:
        image_ref = image_ref.split("@")[0]
    return image_ref.lower().strip()


def scan_dockerfile(path: str) -> list[ContainerFinding]:
    """Scan a single Dockerfile for outdated base images.

    Args:
        path: Absolute or relative path to the Dockerfile.

    Returns:
        List of ContainerFinding objects for each outdated base image.
        Empty list if all images are current or not in the database.
    """
    findings: list[ContainerFinding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            dockerfile_content = fh.read()
    except OSError as exc:
        logger.warning("scan_dockerfile: cannot read %s: %s", path, exc)
        return []
    from_images = _extract_from_statements(dockerfile_content)
    for image_ref in from_images:
        normalised = _normalise_image_ref(image_ref)
        rec = BASE_IMAGE_RECOMMENDATIONS.get(normalised)
        if rec is None and ":" in normalised:
            name, tag = normalised.split(":", 1)
            for variant in ("-slim", "-alpine", "-buster", "-bullseye",
                            "-bookworm", "-jammy", "-focal", "-bionic",
                            "-fpm", "-jre", "-jdk"):
                if tag.endswith(variant):
                    tag = tag[: -len(variant)]
                    break
            rec = BASE_IMAGE_RECOMMENDATIONS.get(f"{name}:{tag}")
        if rec is not None:
            recommended_image, severity = rec
            findings.append(ContainerFinding(
                dockerfile_path=path,
                current_image=image_ref,
                recommended_image=recommended_image,
                severity=severity,
                reason=(
                    f"Base image '{image_ref}' is outdated. "
                    f"Upgrade to '{recommended_image}' for latest security patches."
                ),
            ))
    return findings


def scan_dockerfiles_in_repo(repo_dir: str) -> list[ContainerFinding]:
    """Scan all Dockerfiles in a repository for outdated base images."""
    import os as _os
    all_findings: list[ContainerFinding] = []
    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", "venv", ".venv"}
    for dirpath, dirnames, filenames in _os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if (fname.lower() in ("dockerfile", "containerfile")
                    or fname.lower().endswith(".dockerfile")):
                full_path = _os.path.join(dirpath, fname)
                rel_path = _os.path.relpath(full_path, repo_dir)
                item_findings = scan_dockerfile(full_path)
                for f in item_findings:
                    f.dockerfile_path = rel_path
                all_findings.extend(item_findings)
    logger.info("Dockerfile base-image scan: %d findings in %s", len(all_findings), repo_dir)
    return all_findings


def container_findings_to_zse(findings: list[ContainerFinding]) -> list[Finding]:
    """Convert ContainerFinding objects to ZSE Finding objects."""
    sev_map = {
        "critical": Severity.critical,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
        "info": Severity.info,
    }
    results: list[Finding] = []
    for cf in findings:
        results.append(Finding(
            type=FindingType.vulnerability,
            severity=sev_map.get(cf.severity, Severity.low),
            title=f"Outdated base image: {cf.current_image}",
            description=(
                f"{cf.reason}"
                f"\nCurrent: `{cf.current_image}`"
                f"\nRecommended: `{cf.recommended_image}`"
            ),
            file_path=cf.dockerfile_path or None,
        ))
    return results