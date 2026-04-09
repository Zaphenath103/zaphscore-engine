"""
ZSE IaC Scanner — Checkov integration for Infrastructure-as-Code security checks
(Terraform, Docker, Kubernetes, CloudFormation).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

CHECKOV_TIMEOUT = 300  # seconds

# Patterns that indicate IaC files are present
_IAC_PATTERNS = {
    "terraform": ["*.tf", "*.tf.json"],
    "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "kubernetes": ["*.yaml", "*.yml"],  # only in k8s-like directories
}

# Checkov severity → ZSE severity
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "INFO": Severity.info,
}

# Directories that suggest kubernetes manifests
_K8S_DIR_HINTS = {"k8s", "kubernetes", "manifests", "deploy", "deployments", "helm", "charts"}


def _has_iac_files(repo_dir: str) -> bool:
    """Check if the repo contains any IaC files worth scanning."""
    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", "venv", ".venv"}

    for dirpath, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        rel_dir = os.path.relpath(dirpath, repo_dir).lower()

        for fname in filenames:
            fname_lower = fname.lower()

            # Terraform files
            if fname_lower.endswith(".tf") or fname_lower.endswith(".tf.json"):
                return True

            # Docker files
            if fname_lower in ("dockerfile", "docker-compose.yml", "docker-compose.yaml"):
                return True

            # Kubernetes yamls in k8s-like directories
            if fname_lower.endswith((".yaml", ".yml")):
                dir_parts = set(rel_dir.replace("\\", "/").split("/"))
                if dir_parts & _K8S_DIR_HINTS:
                    return True
                # Also check if the YAML contains k8s-like content
                # (we do a quick first-line check)
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        head = f.read(500)
                        if "apiVersion:" in head and "kind:" in head:
                            return True
                except OSError:
                    pass

    return False


async def scan_iac(repo_dir: str) -> list[Finding]:
    """Run Checkov IaC scan on the repository.

    Args:
        repo_dir: Absolute path to the cloned repository.

    Returns:
        List of Finding objects for failed IaC checks.
        Returns empty list if no IaC files detected or checkov not installed.
    """
    # Quick check: are there any IaC files?
    loop = asyncio.get_event_loop()
    has_iac = await loop.run_in_executor(None, _has_iac_files, repo_dir)
    if not has_iac:
        logger.info("No IaC files detected in %s — skipping Checkov scan", repo_dir)
        return []

    # Check if checkov is available
    if not shutil.which("checkov"):
        logger.warning(
            "Checkov is not installed — IaC scan skipped. "
            "Install with: pip install checkov"
        )
        return []

    findings: list[Finding] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "checkov",
            "-d", repo_dir,
            "--output", "json",
            "--quiet",
            "--compact",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=CHECKOV_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error("Checkov timed out after %ds for %s", CHECKOV_TIMEOUT, repo_dir)
            return []

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode not in (0, 1):
            # 1 = checks failed (findings found), which is expected
            logger.warning(
                "Checkov exited with code %d: %s",
                proc.returncode, stderr_text[:300],
            )

        if not stdout_text.strip():
            logger.info("Checkov produced no output for %s", repo_dir)
            return []

        # Checkov can output a list of results (one per framework) or a single dict
        try:
            data = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Checkov JSON output: %s", exc)
            return []

        # Normalise: if data is a list, process each; if dict, wrap in list
        result_blocks: list[dict] = []
        if isinstance(data, list):
            result_blocks = data
        elif isinstance(data, dict):
            result_blocks = [data]

        for block in result_blocks:
            failed_checks = block.get("results", {}).get("failed_checks", [])

            for check in failed_checks:
                check_id = check.get("check_id", "")
                check_name = check.get("name", check.get("check_id", "Unknown check"))
                guideline = check.get("guideline", "")
                file_path = check.get("file_path", "")
                severity_str = check.get("severity", check.get("check_result", {}).get("severity", "MEDIUM"))

                # Map severity
                if isinstance(severity_str, str):
                    severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.medium)
                else:
                    severity = Severity.medium

                # Make path relative
                if file_path.startswith(repo_dir):
                    file_path = file_path[len(repo_dir):].lstrip("/\\")
                elif file_path.startswith("/"):
                    file_path = file_path.lstrip("/")

                # Build description
                desc_parts = [check_name]
                if guideline:
                    desc_parts.append(f"Guideline: {guideline}")
                resource = check.get("resource", "")
                if resource:
                    desc_parts.append(f"Resource: {resource}")

                findings.append(Finding(
                    type=FindingType.iac,
                    severity=severity,
                    title=check_name[:200],
                    description="\n".join(desc_parts)[:1000],
                    file_path=file_path or None,
                    line=check.get("file_line_range", [None])[0],
                    rule_id=check_id or None,
                ))

        logger.info("Checkov found %d failed checks in %s", len(findings), repo_dir)

    except FileNotFoundError:
        logger.warning("Checkov binary not found — IaC scan skipped")
    except Exception as exc:
        logger.error("IaC scan failed: %s", exc, exc_info=True)

    return findings
