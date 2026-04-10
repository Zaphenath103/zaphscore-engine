"""
ZSE License Compliance Scanner — checks license declarations in package
manifests and LICENSE files for compliance risks.

Includes per-dependency license scanning for npm, Python, and Cargo
ecosystems, with license inventory generation and risk classification.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Optional

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# Known permissive licenses (SPDX identifiers)
PERMISSIVE_LICENSES: set[str] = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "0BSD",
    "CC0-1.0",
    "Zlib",
    "BSL-1.0",
    "PSF-2.0",
    "Python-2.0",
    "BlueOak-1.0.0",
}

# Known copyleft licenses
COPYLEFT_LICENSES: set[str] = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EUPL-1.2",
    "CPAL-1.0",
    "OSL-3.0",
}

# Patterns to detect license type from LICENSE file content
_LICENSE_CONTENT_PATTERNS: list[tuple[str, str]] = [
    (r"MIT License", "MIT"),
    (r"Apache License.*Version 2\.0", "Apache-2.0"),
    (r"BSD 2-Clause", "BSD-2-Clause"),
    (r"BSD 3-Clause", "BSD-3-Clause"),
    (r"ISC License", "ISC"),
    (r"GNU GENERAL PUBLIC LICENSE.*Version 3", "GPL-3.0"),
    (r"GNU GENERAL PUBLIC LICENSE.*Version 2", "GPL-2.0"),
    (r"GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
    (r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 3", "LGPL-3.0"),
    (r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1", "LGPL-2.1"),
    (r"Mozilla Public License.*2\.0", "MPL-2.0"),
    (r"The Unlicense", "Unlicense"),
]


def _normalise_spdx(raw: str) -> str:
    """Normalise a license identifier to a clean SPDX-like form."""
    s = raw.strip()
    # Handle SPDX expressions: "MIT OR Apache-2.0" → take the first
    if " OR " in s.upper():
        s = s.split(" OR ")[0].strip()
    if " AND " in s.upper():
        s = s.split(" AND ")[0].strip()
    # Handle parenthesised expressions
    s = s.strip("()")
    return s


def _classify_license(spdx: str) -> Optional[str]:
    """Classify a license as 'permissive', 'copyleft', or None (unknown)."""
    normalised = _normalise_spdx(spdx)
    if normalised in PERMISSIVE_LICENSES:
        return "permissive"
    if normalised in COPYLEFT_LICENSES:
        return "copyleft"
    # Try case-insensitive match
    upper = normalised.upper()
    for lic in PERMISSIVE_LICENSES:
        if lic.upper() == upper:
            return "permissive"
    for lic in COPYLEFT_LICENSES:
        if lic.upper() == upper:
            return "copyleft"
    return None


def _detect_license_from_file(content: str) -> Optional[str]:
    """Try to identify a license SPDX ID from LICENSE file content."""
    for pattern, spdx in _LICENSE_CONTENT_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return spdx
    return None


def _read_json_field(file_path: str, *keys: str) -> Optional[str]:
    """Read a nested field from a JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                return None
        return str(data) if data else None
    except Exception:
        return None


def _read_toml_field(file_path: str, *keys: str) -> Optional[str]:
    """Read a nested field from a TOML file."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                return None
        return str(data) if data else None
    except Exception:
        return None


async def scan_licenses(
    repo_dir: str,
    dependencies: list[dict],
) -> list[Finding]:
    """Scan the repository for license compliance issues.

    Args:
        repo_dir: Absolute path to the cloned repository.
        dependencies: Resolved dependency list (used for context, not scanned individually).

    Returns:
        List of Finding objects for license compliance issues.
    """
    findings: list[Finding] = []

    # -----------------------------------------------------------------------
    # 1. Check root LICENSE / COPYING files
    # -----------------------------------------------------------------------
    root_license_spdx: Optional[str] = None
    license_file_names = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE",
                          "LICENCE.md", "LICENCE.txt", "COPYING", "COPYING.md"]

    for lf_name in license_file_names:
        lf_path = os.path.join(repo_dir, lf_name)
        if os.path.isfile(lf_path):
            try:
                with open(lf_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(10000)
                detected = _detect_license_from_file(content)
                if detected:
                    root_license_spdx = detected
                    logger.info("Detected root license: %s (from %s)", detected, lf_name)
                    break
            except OSError:
                pass

    # -----------------------------------------------------------------------
    # 2. Check package.json license field
    # -----------------------------------------------------------------------
    pkg_json_path = os.path.join(repo_dir, "package.json")
    if os.path.isfile(pkg_json_path):
        pkg_license = _read_json_field(pkg_json_path, "license")
        if pkg_license:
            normalised = _normalise_spdx(pkg_license)
            classification = _classify_license(normalised)
            if classification is None and normalised not in ("UNLICENSED", "SEE LICENSE IN LICENSE"):
                findings.append(Finding(
                    type=FindingType.license,
                    severity=Severity.low,
                    title=f"Unknown license in package.json: {normalised}",
                    description=(
                        f"The license '{normalised}' declared in package.json is not a recognised "
                        f"SPDX identifier. Review for compliance."
                    ),
                    file_path="package.json",
                ))
            elif not root_license_spdx:
                root_license_spdx = normalised
        else:
            findings.append(Finding(
                type=FindingType.license,
                severity=Severity.medium,
                title="No license field in package.json",
                description=(
                    "package.json does not declare a license. This creates license compliance "
                    "risk for consumers of this package."
                ),
                file_path="package.json",
            ))

    # -----------------------------------------------------------------------
    # 3. Check Cargo.toml license field
    # -----------------------------------------------------------------------
    cargo_toml_path = os.path.join(repo_dir, "Cargo.toml")
    if os.path.isfile(cargo_toml_path):
        cargo_license = _read_toml_field(cargo_toml_path, "package", "license")
        if cargo_license:
            normalised = _normalise_spdx(cargo_license)
            classification = _classify_license(normalised)
            if classification is None:
                findings.append(Finding(
                    type=FindingType.license,
                    severity=Severity.low,
                    title=f"Unknown license in Cargo.toml: {normalised}",
                    description=(
                        f"The license '{normalised}' in Cargo.toml is not a recognised "
                        f"SPDX identifier. Review for compliance."
                    ),
                    file_path="Cargo.toml",
                ))
            elif not root_license_spdx:
                root_license_spdx = normalised
        else:
            # Check for license-file alternative
            cargo_license_file = _read_toml_field(cargo_toml_path, "package", "license-file")
            if not cargo_license_file:
                findings.append(Finding(
                    type=FindingType.license,
                    severity=Severity.medium,
                    title="No license field in Cargo.toml",
                    description=(
                        "Cargo.toml does not declare a license or license-file. "
                        "This is required for publishing to crates.io."
                    ),
                    file_path="Cargo.toml",
                ))

    # -----------------------------------------------------------------------
    # 4. Check pyproject.toml license field
    # -----------------------------------------------------------------------
    pyproject_path = os.path.join(repo_dir, "pyproject.toml")
    if os.path.isfile(pyproject_path):
        py_license = _read_toml_field(pyproject_path, "project", "license")
        # license can be a string or a table with {text = "..."} or {file = "..."}
        if not py_license or py_license == "None":
            # Try nested form
            py_license = _read_toml_field(pyproject_path, "project", "license", "text")
        if py_license and py_license != "None":
            normalised = _normalise_spdx(py_license)
            if not root_license_spdx:
                root_license_spdx = normalised

    # -----------------------------------------------------------------------
    # 5. No license file at all
    # -----------------------------------------------------------------------
    if root_license_spdx is None:
        # Check if there is ANY license file
        has_any = any(
            os.path.isfile(os.path.join(repo_dir, name))
            for name in license_file_names
        )
        if not has_any:
            findings.append(Finding(
                type=FindingType.license,
                severity=Severity.medium,
                title="No LICENSE file found",
                description=(
                    "The repository does not contain a LICENSE or COPYING file. "
                    "Without an explicit license, the code is under exclusive copyright "
                    "by default, which restricts use by others."
                ),
            ))

    # -----------------------------------------------------------------------
    # 6. Copyleft check — flag if root project uses copyleft
    # -----------------------------------------------------------------------
    if root_license_spdx:
        classification = _classify_license(root_license_spdx)
        if classification == "copyleft":
            findings.append(Finding(
                type=FindingType.license,
                severity=Severity.high,
                title=f"Copyleft license detected: {root_license_spdx}",
                description=(
                    f"This project uses the copyleft license '{root_license_spdx}'. "
                    f"Copyleft licenses require derivative works to be distributed under "
                    f"the same license terms. Ensure this is intentional and compatible "
                    f"with your distribution model."
                ),
            ))

    # -----------------------------------------------------------------------
    # 7. Per-dependency license scan
    # -----------------------------------------------------------------------
    dep_inventory, dep_findings = await scan_dependency_licenses(
        repo_dir, dependencies, root_license_spdx,
    )
    findings.extend(dep_findings)

    logger.info(
        "License scan complete: %d findings, root license=%s, dep inventory=%d",
        len(findings), root_license_spdx or "unknown", len(dep_inventory),
    )
    return findings


# ---------------------------------------------------------------------------
# License risk classification for per-dependency scanning
# ---------------------------------------------------------------------------

# Clear: no obligations beyond attribution
CLEAR_LICENSES: set[str] = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "Unlicense", "0BSD", "CC0-1.0", "Zlib", "BSL-1.0", "PSF-2.0",
    "Python-2.0", "BlueOak-1.0.0", "CC-BY-4.0", "CC-BY-3.0",
    "WTFPL",
}

# Caution: weak copyleft — may require source sharing of modifications
CAUTION_LICENSES: set[str] = {
    "MPL-2.0", "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "EUPL-1.2",
    "CPAL-1.0", "EPL-1.0", "EPL-2.0", "OSL-3.0",
}

# Restricted: strong copyleft — derivative works must use same license
RESTRICTED_LICENSES: set[str] = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "CC-BY-SA-4.0",
}

# Non-GPL-compatible project licenses (if a project uses one of these,
# GPL deps are incompatible)
_NON_GPL_COMPATIBLE: set[str] = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
}


def _classify_dep_license_risk(spdx: str) -> str:
    """Classify a dependency license into a risk level.

    Returns one of: ``"clear"``, ``"caution"``, ``"restricted"``,
    ``"unknown"``.
    """
    normalised = _normalise_spdx(spdx)
    upper = normalised.upper()

    # Check exact match first, then case-insensitive
    if normalised in CLEAR_LICENSES:
        return "clear"
    for lic in CLEAR_LICENSES:
        if lic.upper() == upper:
            return "clear"

    if normalised in CAUTION_LICENSES:
        return "caution"
    for lic in CAUTION_LICENSES:
        if lic.upper() == upper:
            return "caution"

    if normalised in RESTRICTED_LICENSES:
        return "restricted"
    for lic in RESTRICTED_LICENSES:
        if lic.upper() == upper:
            return "restricted"

    return "unknown"


# ---------------------------------------------------------------------------
# Per-dependency license extraction
# ---------------------------------------------------------------------------

def _scan_npm_dep_license(
    repo_dir: str,
    pkg_name: str,
    pkg_version: str,
) -> Optional[str]:
    """Extract the license for an npm dependency.

    Checks (in order):
      1. ``node_modules/{pkg}/package.json`` → ``license`` field
      2. ``package-lock.json`` → packages → node_modules/{pkg} → license
    """
    # 1. Direct node_modules check
    # Handle scoped packages: @scope/name → @scope/name
    nm_pkg_json = os.path.join(repo_dir, "node_modules", pkg_name, "package.json")
    if os.path.isfile(nm_pkg_json):
        lic = _read_json_field(nm_pkg_json, "license")
        if lic:
            return lic
        # Some packages use "licenses" (array of {type, url})
        try:
            with open(nm_pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            licenses = data.get("licenses")
            if isinstance(licenses, list) and licenses:
                first = licenses[0]
                if isinstance(first, dict) and "type" in first:
                    return first["type"]
        except Exception:
            pass

    # 2. package-lock.json
    lock_path = os.path.join(repo_dir, "package-lock.json")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                lock_data = json.load(f)
            # v2/v3 lockfile: packages → "node_modules/{name}" → license
            packages = lock_data.get("packages", {})
            key = f"node_modules/{pkg_name}"
            pkg_entry = packages.get(key, {})
            lic = pkg_entry.get("license")
            if lic:
                return lic
            # v1 lockfile: dependencies → name → resolved (no license field)
        except Exception:
            pass

    return None


def _scan_python_dep_license(
    repo_dir: str,
    pkg_name: str,
) -> Optional[str]:
    """Extract the license for a Python dependency from site-packages METADATA.

    Searches common virtualenv/venv layouts for the installed metadata.
    """
    # Normalise name: underscores and hyphens are interchangeable in Python
    normalised = re.sub(r"[-_.]+", "_", pkg_name).lower()

    # Possible locations for site-packages
    candidates: list[str] = []
    for venv_dir in ("venv", ".venv", "env", ".env"):
        sp = os.path.join(repo_dir, venv_dir, "lib")
        if os.path.isdir(sp):
            # Walk into python3.x/site-packages
            try:
                for entry in os.listdir(sp):
                    if entry.startswith("python"):
                        candidates.append(
                            os.path.join(sp, entry, "site-packages"),
                        )
            except OSError:
                pass
    # Also check global-ish paths that may exist in CI containers
    candidates.append(os.path.join(repo_dir, ".tox"))

    for sp_dir in candidates:
        if not os.path.isdir(sp_dir):
            continue
        # Look for {normalised}-{version}.dist-info/METADATA
        try:
            for entry in os.listdir(sp_dir):
                entry_lower = entry.lower().replace("-", "_")
                if entry_lower.startswith(normalised) and entry.endswith(".dist-info"):
                    metadata_path = os.path.join(sp_dir, entry, "METADATA")
                    if os.path.isfile(metadata_path):
                        lic = _parse_python_metadata_license(metadata_path)
                        if lic:
                            return lic
        except OSError:
            pass

    return None


def _parse_python_metadata_license(metadata_path: str) -> Optional[str]:
    """Parse a Python METADATA file for the License classifier or header."""
    try:
        with open(metadata_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(8000)
    except OSError:
        return None

    # Check for License header first (PEP 566)
    for line in content.splitlines():
        if line.startswith("License:"):
            value = line[len("License:"):].strip()
            if value and value.lower() not in ("unknown", "none", ""):
                return value

    # Check classifiers: "License :: OSI Approved :: MIT License"
    for line in content.splitlines():
        if line.startswith("Classifier: License"):
            parts = line.split("::")
            if len(parts) >= 3:
                lic_name = parts[-1].strip()
                # Map common classifier names to SPDX
                spdx = _classifier_to_spdx(lic_name)
                if spdx:
                    return spdx

    return None


def _classifier_to_spdx(classifier_name: str) -> Optional[str]:
    """Map a Python license classifier name to an SPDX identifier."""
    _map: dict[str, str] = {
        "MIT License": "MIT",
        "Apache Software License": "Apache-2.0",
        "BSD License": "BSD-3-Clause",
        "ISC License (ISCL)": "ISC",
        "GNU General Public License v3 (GPLv3)": "GPL-3.0",
        "GNU General Public License v2 (GPLv2)": "GPL-2.0",
        "GNU Affero General Public License v3": "AGPL-3.0",
        "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
        "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "The Unlicense (Unlicense)": "Unlicense",
        "Python Software Foundation License": "PSF-2.0",
        "European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
    }
    return _map.get(classifier_name)


def _scan_cargo_dep_license(
    repo_dir: str,
    pkg_name: str,
) -> Optional[str]:
    """Extract license for a Cargo dependency.

    Cargo.lock does not store licenses, but the local cargo registry
    cache might.  We attempt to read the cached crate's Cargo.toml.
    """
    # Check if there's a local cargo registry cache
    cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
    registry_src = os.path.join(cargo_home, "registry", "src")

    if os.path.isdir(registry_src):
        try:
            for registry in os.listdir(registry_src):
                registry_path = os.path.join(registry_src, registry)
                if not os.path.isdir(registry_path):
                    continue
                for entry in os.listdir(registry_path):
                    if entry.startswith(pkg_name + "-"):
                        crate_toml = os.path.join(registry_path, entry, "Cargo.toml")
                        if os.path.isfile(crate_toml):
                            lic = _read_toml_field(crate_toml, "package", "license")
                            if lic:
                                return lic
        except OSError:
            pass

    return None


# ---------------------------------------------------------------------------
# Main per-dependency scanning function
# ---------------------------------------------------------------------------

async def scan_dependency_licenses(
    repo_dir: str,
    dependencies: list[dict],
    root_license_spdx: Optional[str] = None,
) -> tuple[list[dict], list[Finding]]:
    """Scan individual dependencies for their license declarations.

    For each dependency, attempts to find the license via ecosystem-specific
    methods (node_modules, site-packages METADATA, cargo registry cache).

    Args:
        repo_dir: Absolute path to the cloned repository.
        dependencies: Resolved dependency list with ``name``, ``version``,
            ``ecosystem`` keys.
        root_license_spdx: The project's own SPDX license (used for
            compatibility checks).

    Returns:
        A 2-tuple of ``(inventory, findings)`` where *inventory* is a list
        of ``{package, version, license, risk_level}`` dicts and *findings*
        is a list of :class:`Finding` objects for any issues detected.
    """
    inventory: list[dict] = []
    findings: list[Finding] = []

    for dep in dependencies:
        name = dep.get("name", "")
        version = dep.get("version", "")
        ecosystem = dep.get("ecosystem", "")

        if not name:
            continue

        # Resolve license based on ecosystem
        detected_license: Optional[str] = None

        if ecosystem == "npm":
            detected_license = _scan_npm_dep_license(repo_dir, name, version)
        elif ecosystem == "PyPI":
            detected_license = _scan_python_dep_license(repo_dir, name)
        elif ecosystem == "crates.io":
            detected_license = _scan_cargo_dep_license(repo_dir, name)

        # Normalise and classify
        if detected_license:
            normalised = _normalise_spdx(detected_license)
            risk_level = _classify_dep_license_risk(normalised)
        else:
            normalised = "UNKNOWN"
            risk_level = "unknown"

        inventory.append({
            "package": name,
            "version": version,
            "license": normalised,
            "risk_level": risk_level,
        })

        # Generate findings for problematic licenses
        if risk_level == "restricted":
            # Check if the root project license is non-GPL
            is_incompatible = (
                root_license_spdx
                and _normalise_spdx(root_license_spdx) in _NON_GPL_COMPATIBLE
            )
            severity = Severity.high if is_incompatible else Severity.medium
            title_suffix = ""
            if is_incompatible:
                title_suffix = f" (incompatible with {root_license_spdx} project)"

            findings.append(Finding(
                type=FindingType.license,
                severity=severity,
                title=f"Restricted license {normalised} in dependency {name}{title_suffix}",
                description=(
                    f"The dependency {name}@{version} uses the restricted "
                    f"license '{normalised}'. Strong copyleft licenses require "
                    f"derivative works to be distributed under the same terms. "
                    f"Evaluate whether this dependency is acceptable for your "
                    f"project's distribution model."
                ),
                file_path=None,
            ))

        elif risk_level == "unknown" and normalised == "UNKNOWN":
            findings.append(Finding(
                type=FindingType.license,
                severity=Severity.medium,
                title=f"Unknown license for dependency {name}",
                description=(
                    f"Could not determine the license for {name}@{version} "
                    f"({ecosystem}). Manual review is recommended to ensure "
                    f"license compliance."
                ),
                file_path=None,
            ))

    logger.info(
        "Per-dependency license scan: %d deps scanned, %d issues found",
        len(inventory), len(findings),
    )
    return inventory, findings


# ---------------------------------------------------------------------------
# License report generation
# ---------------------------------------------------------------------------

def generate_license_report(inventory: list[dict]) -> dict:
    """Generate a summary report from a license inventory.

    Args:
        inventory: List of ``{package, version, license, risk_level}`` dicts
            as returned by :func:`scan_dependency_licenses`.

    Returns:
        A report dict with ``summary``, ``distribution``, and
        ``risk_items`` keys.
    """
    total = len(inventory)
    clear_count = sum(1 for i in inventory if i["risk_level"] == "clear")
    caution_count = sum(1 for i in inventory if i["risk_level"] == "caution")
    restricted_count = sum(1 for i in inventory if i["risk_level"] == "restricted")
    unknown_count = sum(1 for i in inventory if i["risk_level"] == "unknown")

    # Compliant = no restricted and no unknown
    compliant = restricted_count == 0 and unknown_count == 0

    # Distribution: count per license type
    distribution: dict[str, int] = {}
    for item in inventory:
        lic = item.get("license", "UNKNOWN")
        distribution[lic] = distribution.get(lic, 0) + 1

    # Sort distribution by count descending
    distribution = dict(
        sorted(distribution.items(), key=lambda kv: kv[1], reverse=True)
    )

    # Risk items: packages with non-clear risk
    risk_items: list[dict] = [
        item for item in inventory
        if item["risk_level"] in ("restricted", "unknown", "caution")
    ]

    return {
        "summary": {
            "total": total,
            "clear": clear_count,
            "caution": caution_count,
            "restricted": restricted_count,
            "unknown": unknown_count,
            "compliant": compliant,
        },
        "distribution": distribution,
        "risk_items": risk_items,
    }

# D-673: Expanded SPDX full-database license coverage
_SPDX_ADDITIONAL_PERMISSIVE = {
    "AFL-2.0", "AFL-2.1", "AFL-3.0", "Apache-1.0", "Apache-1.1",
    "Artistic-1.0", "Artistic-2.0",
    "BSD-1-Clause", "BSD-4-Clause",
    "CC-BY-1.0", "CC-BY-2.0", "CC-BY-2.5", "CC-BY-3.0", "CC-BY-4.0",
    "CNRI-Python", "curl", "EFL-2.0", "Entessa",
    "FSFAP", "FTL", "HPND", "ICU", "IPA",
    "JSON", "Libpng", "libtiff",
    "MIT-0", "MIT-CMU", "MITNFA",
    "MulanPSL-1.0", "MulanPSL-2.0",
    "Naumen", "Net-SNMP", "NetCDF", "Nokia", "NTP",
    "OCLC-2.0", "OFL-1.0", "OFL-1.1",
    "OpenSSL", "PHP-3.0", "PHP-3.01", "PostgreSQL",
    "QPL-1.0", "Ruby", "SGI-B-2.0",
    "TCL", "Unicode-DFS-2016", "UPL-1.0",
    "Vim", "W3C", "Watcom-1.0", "WTFPL",
    "X11", "Xnet", "ZPL-2.0", "ZPL-2.1",
}

_SPDX_ADDITIONAL_COPYLEFT = {
    "CECILL-2.1", "CPL-1.0",
    "EPL-1.0", "EPL-2.0",
    "EUPL-1.0", "EUPL-1.1",
    "GPL-1.0", "GPL-1.0-only",
    "LGPL-2.0", "LGPL-2.0-only",
    "MS-PL", "MS-RL",
    "RPSL-1.0", "SPL-1.0", "SSPL-1.0",
}

PERMISSIVE_LICENSES.update(_SPDX_ADDITIONAL_PERMISSIVE)
COPYLEFT_LICENSES.update(_SPDX_ADDITIONAL_COPYLEFT)


class LicensePolicy:
    # D-674: Org-level license policy object
    def __init__(self, allowed=None, restricted=None, forbidden=None, policy_name=None):
        self.allowed = allowed or set()
        self.restricted = restricted or set()
        self.forbidden = forbidden or set()
        self.policy_name = policy_name or "default"

    @classmethod
    def from_env(cls):
        import os as _os
        def _p(v): return {s.strip() for s in _os.environ.get(v, "").split(",") if s.strip()}
        return cls(
            allowed=_p("ZSE_LICENSE_ALLOWED"),
            restricted=_p("ZSE_LICENSE_RESTRICTED"),
            forbidden=_p("ZSE_LICENSE_FORBIDDEN"),
            policy_name=_os.environ.get("ZSE_LICENSE_POLICY_NAME", "default"),
        )

    @classmethod
    def default_enterprise(cls):
        return cls(
            allowed=set(PERMISSIVE_LICENSES),
            restricted={
                "LGPL-2.1","LGPL-2.1-only","LGPL-2.1-or-later",
                "LGPL-3.0","LGPL-3.0-only","LGPL-3.0-or-later",
                "MPL-2.0","EPL-1.0","EPL-2.0","EUPL-1.2",
            },
            forbidden={
                "GPL-2.0","GPL-2.0-only","GPL-2.0-or-later",
                "GPL-3.0","GPL-3.0-only","GPL-3.0-or-later",
                "AGPL-3.0","AGPL-3.0-only","AGPL-3.0-or-later","SSPL-1.0",
            },
            policy_name="enterprise-default",
        )

    def check(self, inventory_items):
        violations = []
        for item in inventory_items:
            lic = item.get("license", "UNKNOWN")
            pkg = item.get("name", "unknown")
            ver = item.get("version", "?")
            if lic in self.forbidden:
                violations.append({"package": pkg, "version": ver, "license": lic,
                    "violation_type": "forbidden",
                    "message": "Package " + repr(pkg) + "@" + ver + " uses " + repr(lic) + " which is forbidden by policy " + repr(self.policy_name) + "."})
            elif lic in self.restricted:
                violations.append({"package": pkg, "version": ver, "license": lic,
                    "violation_type": "restricted",
                    "message": "Package " + repr(pkg) + "@" + ver + " uses " + repr(lic) + " which is restricted under " + repr(self.policy_name) + " -- legal review required."})
            elif self.allowed and lic not in self.allowed:
                violations.append({"package": pkg, "version": ver, "license": lic,
                    "violation_type": "not_in_allowlist",
                    "message": "Package " + repr(pkg) + "@" + ver + " uses " + repr(lic) + " which is not in the approved allowlist for " + repr(self.policy_name) + "."})
        return violations


# D-688: License compatibility matrix
_LICENSE_COMPAT = {
    "MIT": {"MIT":True,"Apache-2.0":True,"BSD-2-Clause":True,"BSD-3-Clause":True,"ISC":True,"Unlicense":True,"CC0-1.0":True,"0BSD":True,"GPL-2.0":True,"GPL-3.0":True,"GPL-3.0-only":True,"AGPL-3.0":True,"LGPL-2.1":True,"LGPL-3.0":True,"MPL-2.0":True,"EPL-1.0":True,"EPL-2.0":True},
    "Apache-2.0": {"MIT":True,"Apache-2.0":True,"BSD-2-Clause":True,"BSD-3-Clause":True,"ISC":True,"Unlicense":True,"CC0-1.0":True,"GPL-2.0":False,"GPL-2.0-only":False,"GPL-2.0-or-later":None,"GPL-3.0":True,"GPL-3.0-only":True,"GPL-3.0-or-later":True,"AGPL-3.0":True,"LGPL-2.1":True,"LGPL-3.0":True,"MPL-2.0":True,"EPL-1.0":False,"EPL-2.0":False},
    "GPL-3.0": {"MIT":True,"Apache-2.0":True,"BSD-2-Clause":True,"BSD-3-Clause":True,"ISC":True,"Unlicense":True,"CC0-1.0":True,"GPL-2.0":False,"GPL-2.0-only":False,"GPL-2.0-or-later":True,"GPL-3.0":True,"GPL-3.0-only":True,"GPL-3.0-or-later":True,"AGPL-3.0":False,"LGPL-2.1":True,"LGPL-3.0":True,"MPL-2.0":True,"EPL-1.0":False,"EPL-2.0":False},
    "AGPL-3.0": {"MIT":True,"Apache-2.0":True,"BSD-2-Clause":True,"BSD-3-Clause":True,"ISC":True,"Unlicense":True,"CC0-1.0":True,"GPL-2.0":False,"GPL-3.0":False,"GPL-3.0-only":False,"GPL-3.0-or-later":True,"AGPL-3.0":True,"AGPL-3.0-only":True,"LGPL-2.1":True,"LGPL-3.0":True,"MPL-2.0":True},
}


def check_license_compatibility(inventory_items, project_license="MIT"):
    # D-688: Check license interaction between dependencies.
    compat_row = _LICENSE_COMPAT.get(project_license, {})
    issues = []
    for item in inventory_items:
        dep_lic = item.get("license", "UNKNOWN")
        pkg = item.get("name", "unknown")
        ver = item.get("version", "?")
        if dep_lic in ("UNKNOWN", "NOASSERTION", ""):
            continue
        compat = compat_row.get(dep_lic)
        if compat is False:
            issues.append({"package":pkg,"version":ver,"dep_license":dep_lic,"project_license":project_license,"compatibility":"incompatible","message":"License conflict: " + repr(pkg) + "@" + ver + " uses " + dep_lic + ", incompatible with " + project_license + ". Cannot legally distribute."})
        elif compat is None:
            issues.append({"package":pkg,"version":ver,"dep_license":dep_lic,"project_license":project_license,"compatibility":"unclear","message":"License interaction unclear: " + repr(pkg) + "@" + ver + " uses " + dep_lic + " with " + project_license + ". Legal review recommended."})
    return issues
