"""
ZSE IaC Helm Scanner -- D-681: Security analysis for Helm charts.

Scans Helm chart directories for security misconfigurations by:
1. Parsing Chart.yaml for chart metadata
2. Iterating templates/ and crds/ directories
3. Delegating each YAML template to the Kubernetes manifest scanner
4. Aggregating findings with chart context
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Optional

from app.scanner.iac_kubernetes import scan_k8s_manifest

logger = logging.getLogger(__name__)


def _parse_chart_yaml(chart_yaml_path: Path) -> dict[str, Any]:
    """Parse Chart.yaml into a simple dict (name, version, apiVersion, description)."""
    result: dict[str, Any] = {}
    if not chart_yaml_path.exists():
        return result
    try:
        content = chart_yaml_path.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                result[key.strip()] = val.strip().strip('"\'')
    except OSError as exc:
        logger.error("Cannot read Chart.yaml %s: %s", chart_yaml_path, exc)
    return result


def _is_helm_chart(directory: Path) -> bool:
    """Check if a directory is a Helm chart (has Chart.yaml)."""
    return (directory / "Chart.yaml").exists() or (directory / "Chart.yml").exists()


def _find_template_files(chart_dir: Path) -> list[Path]:
    """Find all YAML template files in a Helm chart directory."""
    template_files: list[Path] = []
    # templates/ directory
    templates_dir = chart_dir / "templates"
    if templates_dir.is_dir():
        for f in sorted(templates_dir.rglob("*.yaml")) + sorted(templates_dir.rglob("*.yml")):
            template_files.append(f)
    # crds/ directory
    crds_dir = chart_dir / "crds"
    if crds_dir.is_dir():
        for f in sorted(crds_dir.rglob("*.yaml")) + sorted(crds_dir.rglob("*.yml")):
            template_files.append(f)
    return template_files


def _strip_helm_template_syntax(content: str) -> str:
    """Remove Helm Go template directives to make YAML parseable.

    Replaces {{ ... }} blocks with safe placeholder values so the
    Kubernetes scanner can parse the structural YAML.
    """
    # Replace {{ ... }} with placeholder values based on context
    def replacer(m: re.Match) -> str:
        inner = m.group(1).strip()
        # Common patterns
        if inner.startswith("-"):
            inner = inner[1:].strip()
        if inner.startswith("if ") or inner.startswith("else") or inner.startswith("end") or inner.startswith("range") or inner.startswith("with"):
            return ""
        if "toJson" in inner or "toYaml" in inner:
            return "{}"
        if inner.startswith(".Values.") or inner.startswith(".Chart.") or inner.startswith(".Release."):
            return "HELM_VALUE"
        return "HELM_VALUE"

    result = re.sub(r'\{\{(.*?)\}\}', replacer, content, flags=re.DOTALL)
    # Remove lines that became empty due to template-only content
    lines = []
    for line in result.splitlines():
        stripped = line.strip()
        # Skip lines that are only whitespace or HELM_VALUE with no key
        if stripped == "HELM_VALUE":
            continue
        lines.append(line)
    return "\n".join(lines)


def scan_helm_chart(chart_dir: str) -> list[dict[str, Any]]:
    """Scan a Helm chart directory for security misconfigurations.

    Parses Chart.yaml for metadata, iterates templates/ and crds/,
    strips Helm template syntax, and delegates to the Kubernetes scanner.

    Args:
        chart_dir: Absolute path to the Helm chart directory (contains Chart.yaml).

    Returns:
        List of finding dicts with keys: rule_id, resource, kind, message, severity,
        file, chart_name, chart_version.
    """
    chart_path = Path(chart_dir)

    if not chart_path.is_dir():
        logger.warning("Helm chart directory not found: %s", chart_dir)
        return []

    if not _is_helm_chart(chart_path):
        logger.warning("No Chart.yaml found in %s -- not a Helm chart", chart_dir)
        return []

    chart_yaml = chart_path / "Chart.yaml"
    if not chart_yaml.exists():
        chart_yaml = chart_path / "Chart.yml"
    chart_meta = _parse_chart_yaml(chart_yaml)
    chart_name = chart_meta.get("name", chart_path.name)
    chart_version = chart_meta.get("version", "unknown")

    template_files = _find_template_files(chart_path)
    if not template_files:
        logger.info("No template files found in Helm chart %s", chart_dir)
        return []

    all_findings: list[dict[str, Any]] = []

    for template_file in template_files:
        try:
            content = template_file.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.error("Cannot read template %s: %s", template_file, exc)
            continue

        # Write cleaned content to a temp location for scanning
        cleaned = _strip_helm_template_syntax(content)
        if not cleaned.strip():
            continue

        # Write to temp file for the k8s scanner
        import tempfile, os
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yaml",
            prefix="helm_scan_",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(cleaned)
            tmp_path = tmp.name

        try:
            findings = scan_k8s_manifest(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        # Annotate findings with Helm chart context and real file path
        rel = template_file.relative_to(chart_path)
        for finding in findings:
            finding["file"] = str(template_file)
            finding["chart_name"] = chart_name
            finding["chart_version"] = chart_version
            finding["template"] = str(rel)
        all_findings.extend(findings)

    logger.info(
        "Helm chart scan %s (%s@%s): %d findings across %d templates",
        chart_dir, chart_name, chart_version, len(all_findings), len(template_files)
    )
    return all_findings


def scan_helm_charts_directory(base_dir: str) -> list[dict[str, Any]]:
    """Scan all Helm charts found recursively under a base directory.

    A directory is treated as a Helm chart if it contains Chart.yaml.

    Args:
        base_dir: Root directory to search for Helm charts.

    Returns:
        Aggregated findings across all discovered charts.
    """
    base_path = Path(base_dir)
    if not base_path.is_dir():
        logger.warning("Base directory not found: %s", base_dir)
        return []

    _SKIP = {".git", "node_modules", "__pycache__", "vendor", ".tox"}
    all_findings: list[dict[str, Any]] = []

    for chart_yaml in base_path.rglob("Chart.yaml"):
        chart_dir = chart_yaml.parent
        if any(p in chart_dir.parts for p in _SKIP):
            continue
        all_findings.extend(scan_helm_chart(str(chart_dir)))

    logger.info("Helm charts dir scan %s: %d total findings", base_dir, len(all_findings))
    return all_findings
