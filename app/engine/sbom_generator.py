"""ZSE SBOM Generator — produces CycloneDX and SPDX Software Bill of Materials."""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger("zse.engine.sbom_generator")

# Ecosystem → PURL prefix mapping
_PURL_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "pkg:npm/",
    "pypi": "pkg:pypi/",
    "go": "pkg:golang/",
    "golang": "pkg:golang/",
    "cargo": "pkg:cargo/",
    "crates.io": "pkg:cargo/",
    "maven": "pkg:maven/",
    "nuget": "pkg:nuget/",
    "rubygems": "pkg:gem/",
    "gem": "pkg:gem/",
    "packagist": "pkg:composer/",
    "composer": "pkg:composer/",
}

# Known deprecated packages (common examples — extend as needed)
_KNOWN_DEPRECATED: set[str] = {
    "request",
    "tslint",
    "istanbul",
    "nomnom",
    "wrench",
    "graceful-fs",
    "node-uuid",
    "minimatch",
    "mkdirp",
}


def _build_purl(name: str, version: str, ecosystem: str) -> str:
    """Build a Package URL (purl) from dependency metadata."""
    eco_lower = ecosystem.lower() if ecosystem else ""
    prefix = _PURL_ECOSYSTEM_MAP.get(eco_lower, f"pkg:{eco_lower}/" if eco_lower else "pkg:generic/")

    # Sanitise the name for purl format
    safe_name = name.strip().lower()
    if version:
        return f"{prefix}{safe_name}@{version}"
    return f"{prefix}{safe_name}"


def _get_repo_name(repo_dir: str) -> str:
    """Extract a sensible repo name from the directory path."""
    basename = os.path.basename(os.path.normpath(repo_dir))
    # Strip common temp dir prefixes
    cleaned = re.sub(r"^zse-[a-f0-9-]+-", "", basename)
    return cleaned or "unknown-project"


def _iso_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_cyclonedx(repo_name: str, dependencies: list[dict]) -> dict:
    """Generate a CycloneDX 1.5 JSON SBOM."""
    components = []
    dep_refs = []

    for dep in dependencies:
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        ecosystem = dep.get("ecosystem", dep.get("source", ""))
        license_id = dep.get("license", "")
        optional = dep.get("optional", False)

        purl = _build_purl(name, version, ecosystem)

        component: dict = {
            "type": "library",
            "name": name,
            "version": version or "0.0.0",
            "purl": purl,
            "scope": "optional" if optional else "required",
        }

        if license_id:
            component["licenses"] = [{"license": {"id": license_id}}]

        components.append(component)
        dep_refs.append({"ref": purl, "dependsOn": []})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": _iso_now(),
            "tools": [
                {
                    "vendor": "Zaphenath",
                    "name": "ZSE",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": repo_name,
                "version": "0.0.0",
            },
        },
        "components": components,
        "dependencies": dep_refs,
    }


def _generate_spdx(repo_name: str, dependencies: list[dict]) -> dict:
    """Generate an SPDX 2.3 JSON SBOM."""
    packages = []

    for dep in dependencies:
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        ecosystem = dep.get("ecosystem", dep.get("source", ""))

        purl = _build_purl(name, version, ecosystem)

        # SPDX IDs must be alphanumeric + hyphens
        safe_id = re.sub(r"[^a-zA-Z0-9\-.]", "-", f"{name}-{version}" if version else name)

        package: dict = {
            "SPDXID": f"SPDXRef-Package-{safe_id}",
            "name": name,
            "versionInfo": version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ],
        }

        packages.append(package)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": repo_name,
        "documentNamespace": f"https://zaphenath.app/sbom/{repo_name}",
        "creationInfo": {
            "created": _iso_now(),
            "creators": ["Tool: ZSE-0.1.0"],
            "licenseListVersion": "3.19",
        },
        "packages": packages,
    }


async def generate_sbom(
    repo_dir: str,
    dependencies: list[dict],
    format: str = "cyclonedx",
) -> dict:
    """Generate a Software Bill of Materials in CycloneDX or SPDX format.

    Args:
        repo_dir: Absolute path to the cloned repository.
        dependencies: List of dependency dicts from the dependency resolver.
            Each dict should have at minimum: name, version, ecosystem.
            Optional fields: license, optional.
        format: SBOM format — "cyclonedx" (CycloneDX 1.5) or "spdx" (SPDX 2.3).

    Returns:
        SBOM document as a dict (JSON-serialisable).
    """
    repo_name = _get_repo_name(repo_dir)
    format_lower = format.lower().strip()

    logger.info(
        "Generating %s SBOM for %s (%d dependencies)",
        format_lower, repo_name, len(dependencies),
    )

    try:
        if format_lower == "spdx":
            sbom = _generate_spdx(repo_name, dependencies)
        else:
            # Default to CycloneDX
            if format_lower != "cyclonedx":
                logger.warning(
                    "Unknown SBOM format '%s' — defaulting to CycloneDX", format
                )
            sbom = _generate_cyclonedx(repo_name, dependencies)

        logger.info(
            "Generated %s SBOM for %s with %d components",
            format_lower, repo_name, len(dependencies),
        )
        return sbom

    except Exception as exc:
        logger.error("SBOM generation failed: %s", exc, exc_info=True)
        # Return a minimal valid SBOM rather than crashing
        if format_lower == "spdx":
            return {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": repo_name,
                "documentNamespace": f"https://zaphenath.app/sbom/{repo_name}",
                "creationInfo": {
                    "created": _iso_now(),
                    "creators": ["Tool: ZSE-0.1.0"],
                    "licenseListVersion": "3.19",
                },
                "packages": [],
            }
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": _iso_now(),
                "tools": [{"vendor": "Zaphenath", "name": "ZSE", "version": "0.1.0"}],
                "component": {"type": "application", "name": repo_name, "version": "0.0.0"},
            },
            "components": [],
            "dependencies": [],
        }


async def scan_sbom_compliance(sbom: dict) -> list[Finding]:
    """Check an SBOM for compliance issues.

    Inspects the SBOM for common problems:
    - Components/packages with missing version information
    - Components/packages with missing license information
    - Known deprecated packages

    Args:
        sbom: An SBOM dict (CycloneDX or SPDX format).

    Returns:
        List of Finding objects for compliance issues.
    """
    findings: list[Finding] = []

    try:
        # Determine format and extract components
        if sbom.get("bomFormat") == "CycloneDX":
            components = sbom.get("components", [])
            for comp in components:
                name = comp.get("name", "unknown")
                version = comp.get("version", "")
                licenses = comp.get("licenses", [])

                # Check for missing version
                if not version or version == "0.0.0":
                    findings.append(Finding(
                        type=FindingType.license,
                        severity=Severity.medium,
                        title=f"Missing version for {name}",
                        description=(
                            f"Component '{name}' has no version specified in the SBOM. "
                            "This makes vulnerability tracking and reproducible builds difficult."
                        ),
                    ))

                # Check for missing license
                if not licenses:
                    findings.append(Finding(
                        type=FindingType.license,
                        severity=Severity.medium,
                        title=f"Missing license for {name}",
                        description=(
                            f"Component '{name}' (version: {version or 'unknown'}) has no license "
                            "information. This may indicate a compliance risk."
                        ),
                    ))

                # Check for deprecated packages
                if name.lower() in _KNOWN_DEPRECATED:
                    findings.append(Finding(
                        type=FindingType.license,
                        severity=Severity.low,
                        title=f"Deprecated package: {name}",
                        description=(
                            f"Package '{name}' (version: {version or 'unknown'}) is known to be "
                            "deprecated. Consider migrating to a maintained alternative."
                        ),
                    ))

        elif sbom.get("spdxVersion", "").startswith("SPDX"):
            packages = sbom.get("packages", [])
            for pkg in packages:
                name = pkg.get("name", "unknown")
                version = pkg.get("versionInfo", "")

                # Check for missing version
                if not version or version == "NOASSERTION":
                    findings.append(Finding(
                        type=FindingType.license,
                        severity=Severity.medium,
                        title=f"Missing version for {name}",
                        description=(
                            f"Package '{name}' has no version specified in the SBOM. "
                            "This makes vulnerability tracking and reproducible builds difficult."
                        ),
                    ))

                # Check for missing license (SPDX packages may have licenseDeclared)
                license_declared = pkg.get("licenseDeclared", "")
                license_concluded = pkg.get("licenseConcluded", "")
                if (not license_declared or license_declared == "NOASSERTION") and \
                   (not license_concluded or license_concluded == "NOASSERTION"):
                    findings.append(Finding(
                        type=FindingType.license,
                        severity=Severity.medium,
                        title=f"Missing license for {name}",
                        description=(
                            f"Package '{name}' (version: {version or 'unknown'}) has no license "
                            "information declared. This may indicate a compliance risk."
                        ),
                    ))

                # Check for deprecated packages
                if name.lower() in _KNOWN_DEPRECATED:
                    findings.append(Finding(
                        type=FindingType.license,
                        severity=Severity.low,
                        title=f"Deprecated package: {name}",
                        description=(
                            f"Package '{name}' (version: {version or 'unknown'}) is known to be "
                            "deprecated. Consider migrating to a maintained alternative."
                        ),
                    ))

        else:
            logger.warning("Unknown SBOM format — cannot run compliance checks")

        logger.info("SBOM compliance check found %d issues", len(findings))

    except Exception as exc:
        logger.error("SBOM compliance scan failed: %s", exc, exc_info=True)

    return findings
