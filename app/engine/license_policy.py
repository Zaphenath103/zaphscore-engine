"""
ZSE License Policy Engine — D-674 fix.

Adds org-level license policy objects so enterprise customers can define
allowed / denied / flagged license sets.  Closes the gap vs Snyk org-level
License Policy JSON.

Usage::

    from app.engine.license_policy import LicensePolicy, evaluate_license_policy

    policy = LicensePolicy(
        policy_name="acme-corp-oss",
        allowed_licenses=["MIT", "Apache-2.0", "BSD-3-Clause"],
        denied_licenses=["AGPL-3.0", "AGPL-3.0-only", "SSPL-1.0"],
        flagged_licenses=["GPL-2.0", "GPL-3.0", "LGPL-2.1"],
    )
    violations = evaluate_license_policy(scan_inventory, policy)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LicensePolicy:
    """Org-level license policy definition.

    Attributes:
        policy_name: Human-readable name (e.g. "acme-oss-policy").
        allowed_licenses: SPDX identifiers explicitly permitted.
            When non-empty, any license NOT in this list is a violation
            unless also in flagged_licenses.
        denied_licenses: SPDX identifiers explicitly prohibited.
            Dependencies with these licenses generate CRITICAL violations.
        flagged_licenses: SPDX identifiers requiring manual review.
            Dependencies with these licenses generate WARNING violations.
        created_at: ISO-8601 timestamp when this policy was created.
        updated_at: ISO-8601 timestamp of last modification.
        version: Policy schema version (default "1.0").
    """

    policy_name: str
    allowed_licenses: list[str] = field(default_factory=list)
    denied_licenses: list[str] = field(default_factory=list)
    flagged_licenses: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    version: str = "1.0"

    @classmethod
    def permissive_only(cls, policy_name: str = "permissive-only") -> "LicensePolicy":
        """Pre-built policy: only allow common permissive licenses."""
        return cls(
            policy_name=policy_name,
            allowed_licenses=[
                "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
                "ISC", "0BSD", "Zlib", "BSL-1.0", "BlueOak-1.0.0",
                "CC0-1.0", "Unlicense", "PSF-2.0", "Python-2.0",
                "CC-BY-4.0", "WTFPL", "AFL-3.0", "NCSA", "UPL-1.0",
            ],
            denied_licenses=[
                "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
                "SSPL-1.0", "BUSL-1.1",
            ],
            flagged_licenses=[
                "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
                "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
                "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
                "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
                "MPL-2.0", "EPL-2.0", "EUPL-1.2",
            ],
        )

    @classmethod
    def oss_friendly(cls, policy_name: str = "oss-friendly") -> "LicensePolicy":
        """Pre-built policy: allow OSI-approved licenses, deny only SSPL/BUSL."""
        return cls(
            policy_name=policy_name,
            allowed_licenses=[],
            denied_licenses=["SSPL-1.0", "BUSL-1.1", "Elastic-2.0"],
            flagged_licenses=[
                "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
                "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0",
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy to a plain dict for JSON storage."""
        return {
            "policy_name": self.policy_name,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "allowed_licenses": self.allowed_licenses,
            "denied_licenses": self.denied_licenses,
            "flagged_licenses": self.flagged_licenses,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LicensePolicy":
        """Deserialize a policy from a plain dict."""
        return cls(
            policy_name=data.get("policy_name", "unnamed"),
            allowed_licenses=data.get("allowed_licenses", []),
            denied_licenses=data.get("denied_licenses", []),
            flagged_licenses=data.get("flagged_licenses", []),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            version=data.get("version", "1.0"),
        )


@dataclass
class PolicyViolation:
    """A single policy violation from evaluation.

    Attributes:
        package: Dependency name that triggered the violation.
        version: Dependency version.
        license: SPDX identifier detected.
        violation_type: "denied" | "flagged" | "not_in_allowlist".
        severity: "critical" | "warning" | "info".
        message: Human-readable explanation.
    """

    package: str
    version: str
    license: str
    violation_type: str
    severity: str
    message: str


def evaluate_license_policy(
    scan_inventory: list[dict],
    policy: LicensePolicy,
) -> list[PolicyViolation]:
    """Evaluate a license scan inventory against a LicensePolicy.

    Args:
        scan_inventory: List of dicts with at minimum "package", "version",
            and "license" keys (as returned by scan_dependency_licenses).
        policy: The LicensePolicy to enforce.

    Returns:
        List of PolicyViolation objects. Empty list means full compliance.
    """
    violations: list[PolicyViolation] = []

    denied_upper = {lic.upper() for lic in policy.denied_licenses}
    flagged_upper = {lic.upper() for lic in policy.flagged_licenses}
    allowed_upper = {lic.upper() for lic in policy.allowed_licenses}

    for entry in scan_inventory:
        pkg = entry.get("package", "")
        version = entry.get("version", "")
        license_id = entry.get("license", "UNKNOWN")
        lic_upper = license_id.upper()

        if lic_upper in denied_upper:
            violations.append(PolicyViolation(
                package=pkg,
                version=version,
                license=license_id,
                violation_type="denied",
                severity="critical",
                message=(
                    f"Package {pkg}@{version} uses license '{license_id}' which is "
                    f"explicitly denied by policy '{policy.policy_name}'."
                ),
            ))
            continue

        if lic_upper in flagged_upper:
            violations.append(PolicyViolation(
                package=pkg,
                version=version,
                license=license_id,
                violation_type="flagged",
                severity="warning",
                message=(
                    f"Package {pkg}@{version} uses license '{license_id}' which is "
                    f"flagged for review by policy '{policy.policy_name}'."
                ),
            ))
            continue

        if allowed_upper and lic_upper not in allowed_upper:
            violations.append(PolicyViolation(
                package=pkg,
                version=version,
                license=license_id,
                violation_type="not_in_allowlist",
                severity="warning",
                message=(
                    f"Package {pkg}@{version} uses license '{license_id}' which is not "
                    f"in the allowlist for policy '{policy.policy_name}'. "
                    f"Manual review required."
                ),
            ))

    logger.info(
        "License policy '%s' evaluation: %d packages checked, %d violations",
        policy.policy_name, len(scan_inventory), len(violations),
    )
    return violations


def policy_summary(violations: list[PolicyViolation]) -> dict[str, Any]:
    """Produce a summary dict from a violation list."""
    critical = [v for v in violations if v.severity == "critical"]
    warnings = [v for v in violations if v.severity == "warning"]
    info = [v for v in violations if v.severity == "info"]

    return {
        "compliant": len(violations) == 0,
        "total_violations": len(violations),
        "critical": len(critical),
        "warnings": len(warnings),
        "info": len(info),
        "violations": [
            {
                "package": v.package,
                "version": v.version,
                "license": v.license,
                "violation_type": v.violation_type,
                "severity": v.severity,
                "message": v.message,
            }
            for v in violations
        ],
    }
