from __future__ import annotations
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class Ecosystem(str, Enum):
    pip = "pip"; npm = "npm"; cargo = "cargo"; maven = "maven"
    gradle = "gradle"; gem = "gem"; composer = "composer"; nuget = "nuget"
    go = "go"; unknown = "unknown"

class SeverityBucket(str, Enum):
    critical = "critical"; high = "high"; medium = "medium"; low = "low"; info = "info"

class DepType(str, Enum):
    direct = "direct"; transitive = "transitive"; unknown = "unknown"

class UpdateType(str, Enum):
    patch = "patch"; minor = "minor"; major = "major"; unknown = "unknown"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_MANIFEST_ECO = {
    "requirements.txt": "pip", "pyproject.toml": "pip", "Pipfile": "pip",
    "package.json": "npm", "yarn.lock": "npm",
    "Cargo.toml": "cargo", "pom.xml": "maven", "build.gradle": "gradle",
    "Gemfile": "gem", "composer.json": "composer", "go.mod": "go",
}


class DependencyFinding(BaseModel):
    package_name: str; current_version: str
    fixed_version: Optional[str] = None; severity: str = "medium"
    vulnerability_id: Optional[str] = None; title: str
    description: Optional[str] = None; ecosystem: Optional[str] = None
    manifest_file: Optional[str] = None; is_transitive: bool = False
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    references: list[str] = Field(default_factory=list)


@dataclass
class UpdateGroup:
    ecosystem: Ecosystem; severity_bucket: SeverityBucket; dep_type: DepType
    findings: list = field(default_factory=list)

    @property
    def group_id(self): return "{}/{}/{}".format(self.ecosystem.value, self.severity_bucket.value, self.dep_type.value)

    @property
    def package_count(self): return len(self.findings)

    @property
    def has_fixes(self): return any(f.fixed_version for f in self.findings)

    @property
    def highest_cvss(self):
        s = [f.cvss_score for f in self.findings if f.cvss_score is not None]
        return max(s) if s else None


def _detect_eco(finding):
    if finding.ecosystem:
        el = finding.ecosystem.lower()
        for e in Ecosystem:
            if e.value == el: return e
    if finding.manifest_file:
        fn = finding.manifest_file.split("/")[-1]
        eco_name = _MANIFEST_ECO.get(fn)
        if eco_name:
            return Ecosystem(eco_name)
    return Ecosystem.unknown


def group_updates_by_ecosystem(findings):
    groups = {}
    for f in findings:
        eco = _detect_eco(f)
        try: sev = SeverityBucket(f.severity.lower())
        except ValueError: sev = SeverityBucket.medium
        dt = DepType.transitive if f.is_transitive else DepType.direct
        key = "{}/{}/{}".format(eco.value, sev.value, dt.value)
        if key not in groups:
            groups[key] = UpdateGroup(ecosystem=eco, severity_bucket=sev, dep_type=dt)
        groups[key].findings.append(f)
    return sorted(groups.values(), key=lambda g: (_SEVERITY_ORDER.get(g.severity_bucket.value, 99), g.ecosystem.value))


def _detect_update_type(cur, fixed):
    if not fixed: return UpdateType.unknown
    try:
        def p(v):
            v = v.lstrip("v=^~>")
            return tuple(int(x) for x in v.split(".")[:3] if x.isdigit())
        c, fx = p(cur), p(fixed)
        if not c or not fx: return UpdateType.unknown
        if fx[0] > c[0]: return UpdateType.major
        if len(fx) > 1 and len(c) > 1 and fx[1] > c[1]: return UpdateType.minor
        return UpdateType.patch
    except: return UpdateType.unknown


def generate_grouped_pr_body(group):
    sev = group.severity_bucket.value.upper()
    eco = group.ecosystem.value
    dl = "direct" if group.dep_type == DepType.direct else "transitive"
    lines = [
        "## Grouped Dependency Update: {} ({} {})".format(eco, sev, dl), "",
        "This PR addresses **{}** {} vulnerabilities.".format(len(group.findings), sev.lower()), "",
        "### Summary", "",
        "| Package | Current | Fixed | Severity | CVE | CVSS |",
        "|---------|---------|-------|----------|-----|------|",
    ]
    for f in sorted(group.findings, key=lambda x: _SEVERITY_ORDER.get(x.severity.lower(), 99)):
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            f.package_name, f.current_version, f.fixed_version or "No fix",
            f.severity.upper(), f.vulnerability_id or "N/A",
            "{:.1f}".format(f.cvss_score) if f.cvss_score else "N/A"))
    lines += ["", "### Details", ""]
    for f in group.findings:
        ut = _detect_update_type(f.current_version, f.fixed_version)
        lines += ["#### {} ({} -> {})".format(f.package_name, f.current_version, f.fixed_version or "no fix"), "",
                  "- **Vulnerability:** {}".format(f.title),
                  "- **Update type:** {}".format(ut.value), ""]
    if group.highest_cvss:
        lines += ["---", "", "**Highest CVSS:** {:.1f}".format(group.highest_cvss), ""]
    lines += ["---", "", "_Generated by ZaphScore Engine (WAR-3/D-798)._"]
    return "\n".join(lines)


class AutoMergePolicy(BaseModel):
    min_severity_to_require_review: str = Field("high")
    auto_merge_patch_updates: bool = Field(True)
    auto_merge_minor_updates: bool = Field(False)
    require_all_checks_pass: bool = Field(True)
    block_on_high_entropy_secrets: bool = Field(True)


def evaluate_auto_merge(pr_payload, policy, ci_passed):
    findings = pr_payload.get("findings", [])
    update_type_str = pr_payload.get("update_type", "unknown").lower()
    has_entropy_secrets = pr_payload.get("has_entropy_secrets", False)
    try: ut = UpdateType(update_type_str)
    except: ut = UpdateType.unknown
    if policy.require_all_checks_pass and not ci_passed:
        return False, "CI checks did not pass."
    if policy.block_on_high_entropy_secrets and has_entropy_secrets:
        return False, "Entropy scanner found secrets."
    threshold = _SEVERITY_ORDER.get(policy.min_severity_to_require_review.lower(), 1)
    for f in findings:
        sev = f.get("severity", "medium").lower()
        if _SEVERITY_ORDER.get(sev, 99) <= threshold:
            return False, "Finding requires review: {}".format(f.get("title", "?"))
    if ut == UpdateType.major: return False, "Major updates require review."
    if ut == UpdateType.minor:
        if not policy.auto_merge_minor_updates: return False, "Minor updates require review per policy."
        return True, "Auto-merge approved: minor, CI passed."
    if ut == UpdateType.patch:
        if not policy.auto_merge_patch_updates: return False, "Patch updates require review per policy."
        return True, "Auto-merge approved: patch, CI passed."
    return False, "Unknown update type."
