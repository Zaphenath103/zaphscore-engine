"""
ZSE Score Calculator — weighted aggregate scoring across all scan categories.

D-828: Added supply_chain as a distinct scoring category (5% weight).
D-829: Bonuses applied after weighted avg but cannot inflate a failing repo.
D-830: Category floors applied AFTER weighted average, not before.
D-831: Secret deduction recalibrated (critical=15, matching vuln.critical).
D-832: Budget-based diminishing returns prevents finding-splitting exploit.
D-833: repo_type parameter allows contextual weight adjustment.
D-834: CVSS numeric value modulates actual deduction within 4-band bucket.
D-835: License weight raised to 15% (enterprise calibration benchmark).
D-836: SBOM-presence penalty (-5) added.
D-837: Category scores stored as float throughout; rounded only at output.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from app.models.schemas import Finding, FindingType, Severity, ScoreSummary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deduction tables: {severity: base_points_deducted} per finding type
# D-837: Values are float to support CVSS-modulated deductions.
# D-831: secret.critical recalibrated 20 -> 15 to match vuln.critical.
# ---------------------------------------------------------------------------

_DEDUCTIONS: dict[FindingType, dict[Severity, float]] = {
    FindingType.vulnerability: {
        Severity.critical: 15.0,
        Severity.high: 8.0,
        Severity.medium: 3.0,
        Severity.low: 1.0,
        Severity.info: 0.0,
    },
    FindingType.sast: {
        Severity.critical: 12.0,
        Severity.high: 6.0,
        Severity.medium: 2.0,
        Severity.low: 1.0,
        Severity.info: 0.0,
    },
    # D-831: critical recalibrated 20 -> 15 (parity with vuln.critical)
    FindingType.secret: {
        Severity.critical: 15.0,
        Severity.high: 10.0,
        Severity.medium: 4.0,
        Severity.low: 1.5,
        Severity.info: 0.0,
    },
    FindingType.iac: {
        Severity.critical: 10.0,
        Severity.high: 5.0,
        Severity.medium: 2.0,
        Severity.low: 1.0,
        Severity.info: 0.0,
    },
    FindingType.license: {
        Severity.critical: 10.0,
        Severity.high: 5.0,
        Severity.medium: 2.0,
        Severity.low: 1.0,
        Severity.info: 0.0,
    },
}

# D-828: supply_chain added as a distinct category.
# D-835: license raised from 5% to 15% (enterprise benchmark).
# Weights must sum exactly to 1.0.
_WEIGHTS: dict[str, float] = {
    "dependency":   0.30,
    "sast":         0.20,
    "secrets":      0.20,
    "iac":          0.10,
    "license":      0.15,   # D-835: was 0.05
    "supply_chain": 0.05,   # D-828: new category
}

# D-028: Guard against future weight drift — caught at import time, not in production.
assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9, (
    f"Scorer weights must sum to 1.0 got {sum(_WEIGHTS.values()):.6f}. "
    "Adjust _WEIGHTS so all values total exactly 1.0."
)

# Map FindingType to category name
_TYPE_TO_CATEGORY: dict[FindingType, str] = {
    FindingType.vulnerability: "dependency",
    FindingType.sast: "sast",
    FindingType.secret: "secrets",
    FindingType.iac: "iac",
    FindingType.license: "license",
    # supply_chain findings injected via supply_chain_findings param (D-828)
}

# D-829: Bonus values are small and applied after weighted avg.
_BONUS_CICD = 3
_BONUS_SECURITY_POLICY = 2

# D-836: SBOM penalty for repos with no machine-readable SBOM.
_PENALTY_NO_SBOM = 5

# CI/CD config files that earn the CI bonus
_CICD_FILES: list[str] = [
    ".github/workflows",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "Jenkinsfile",
    ".circleci/config.yml",
    ".travis.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".buildkite/pipeline.yml",
]

# Security policy files
_SECURITY_FILES: list[str] = [
    "SECURITY.md",
    "SECURITY.txt",
    "SECURITY",
    ".github/SECURITY.md",
]

# D-836: Machine-readable SBOM file names
_SBOM_FILES: list[str] = [
    "sbom.json",
    "sbom.xml",
    "bom.json",
    "bom.xml",
    "cyclonedx.json",
    "cyclonedx.xml",
    "spdx.json",
    "spdx.spdx",
]


def _check_bonus_cicd(repo_dir: str) -> bool:
    """Check if the repo has any CI/CD configuration."""
    for path in _CICD_FILES:
        full = os.path.join(repo_dir, path)
        if os.path.exists(full):
            return True
    return False


def _check_bonus_security_policy(repo_dir: str) -> bool:
    """Check if the repo has a security policy file."""
    for path in _SECURITY_FILES:
        full = os.path.join(repo_dir, path)
        if os.path.isfile(full):
            return True
    return False


def _check_sbom_present(repo_dir: str) -> bool:
    """D-836: Check if the repo has a machine-readable SBOM file."""
    for fname in _SBOM_FILES:
        if os.path.isfile(os.path.join(repo_dir, fname)):
            return True
    return False


def _cvss_modulated_deduction(
    base: float,
    cvss_score: Optional[float],
    severity: Severity,
) -> float:
    """D-834: Scale base deduction by actual CVSS score within the severity band.

    Instead of every critical vuln deducting exactly 15.0 pts, we scale
    proportionally so CVSS 9.9 deducts more than CVSS 9.1:
        critical: CVSS [9.0, 10.0] => deduction in [12.75, 15.0]
        high:     CVSS [7.0,  9.0) => deduction in [ 6.0,  8.0]
        medium:   CVSS [4.0,  7.0) => deduction in [ 2.0,  3.0]
        low:      CVSS [0.1,  4.0) => deduction in [0.85,  1.0]

    Returns base unchanged when cvss_score is None.
    """
    if cvss_score is None:
        return base

    _BANDS: dict[Severity, tuple[float, float]] = {
        Severity.critical: (9.0, 10.0),
        Severity.high:     (7.0,  9.0),
        Severity.medium:   (4.0,  7.0),
        Severity.low:      (0.1,  4.0),
    }
    band = _BANDS.get(severity)
    if band is None:
        return base

    lo, hi = band
    span = hi - lo
    if span <= 0:
        return base

    # Position within band [0.0, 1.0]
    position = max(0.0, min(1.0, (cvss_score - lo) / span))
    # Scale between 85% and 100% of base deduction
    scale = 0.85 + 0.15 * position
    return base * scale


def calculate_score(
    findings: list[Finding],
    repo_dir: Optional[str] = None,
    repo_type: Optional[str] = None,
    supply_chain_findings: Optional[list[dict]] = None,
) -> ScoreSummary:
    """Calculate the overall security score from all findings.

    Args:
        findings: All findings from all scan phases.
        repo_dir: Path to repo (for bonus/penalty checks). Can be None.
        repo_type: D-833 contextual weight adjustment.
                   Accepted values: 'api', 'library', 'cli', 'internal'.
        supply_chain_findings: D-828 optional list of supply chain signal dicts.
                               Each dict must have keys: severity (str), title (str).

    Returns:
        ScoreSummary with overall (0-100) and per-category (0-100) scores.
        Intermediate calculations use float throughout (D-837); rounded to
        int only at the output boundary.
    """
    # D-833: contextual weight adjustment
    weights = dict(_WEIGHTS)
    if repo_type == "api":
        weights["dependency"] += 0.05
        weights["secrets"] += 0.03
        weights["license"] -= 0.05
        weights["supply_chain"] -= 0.03
    elif repo_type == "library":
        weights["license"] += 0.05
        weights["supply_chain"] += 0.03
        weights["secrets"] -= 0.05
        weights["sast"] -= 0.03
    # Renormalise after adjustment so sum == 1.0
    total_w = sum(weights.values())
    if abs(total_w - 1.0) > 1e-9:
        weights = {k: v / total_w for k, v in weights.items()}

    # D-837: float category scores throughout to preserve precision.
    # D-830: Do NOT floor per-category here; floor only after weighted sum.
    category_scores: dict[str, float] = {cat: 100.0 for cat in weights}

    from collections import defaultdict

    # D-832: Track how many findings of each (category, severity) seen so far.
    # factor = 1/(1+count): 1st=1.0, 2nd=0.5, 3rd=0.33 ...
    _category_finding_counts: dict[tuple[str, str], int] = defaultdict(int)

    for finding in findings:
        category = _TYPE_TO_CATEGORY.get(finding.type)
        if not category:
            continue

        deduction_table = _DEDUCTIONS.get(finding.type, {})
        base_deduction = deduction_table.get(finding.severity, 0.0)
        if base_deduction == 0.0:
            continue

        # D-834: modulate by actual CVSS score within the severity band
        actual_base = _cvss_modulated_deduction(
            base_deduction,
            finding.cvss_score,
            finding.severity,
        )

        sev_key = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )
        key = (category, sev_key)
        count = _category_finding_counts[key]  # 0-indexed before increment
        _category_finding_counts[key] += 1

        # D-832: budget-based diminishing returns
        factor = 1.0 / (1.0 + count)
        actual_deduction = actual_base * factor

        # D-830: deduct without flooring — floor applied after weighted sum
        category_scores[category] = category_scores[category] - actual_deduction

    # D-828: Supply chain findings feed the supply_chain category.
    _sc_sev_base: dict[str, float] = {
        "critical": 15.0,
        "high": 8.0,
        "medium": 3.0,
        "low": 1.0,
    }
    if supply_chain_findings:
        sc_count: dict[str, int] = defaultdict(int)
        for sc in supply_chain_findings:
            sev = str(sc.get("severity", "medium")).lower()
            base = _sc_sev_base.get(sev, 3.0)
            cnt = sc_count[sev]
            sc_count[sev] += 1
            factor = 1.0 / (1.0 + cnt)
            category_scores["supply_chain"] -= base * factor

    # D-830: Floor at 0 per category for the weighted-sum computation.
    # The floor is applied NOW (after deductions) not BEFORE.
    overall_float: float = sum(
        max(0.0, category_scores[cat]) * weight
        for cat, weight in weights.items()
    )
    overall_float = max(0.0, overall_float)

    # D-829: Bonuses applied after weighted average.
    # They are small (+3, +2) and cannot inflate a truly failing repo.
    bonus = 0
    penalty = 0

    if repo_dir and os.path.isdir(repo_dir):
        if _check_bonus_cicd(repo_dir):
            bonus += _BONUS_CICD
            logger.debug("CI/CD config detected: +%d bonus", _BONUS_CICD)
        if _check_bonus_security_policy(repo_dir):
            bonus += _BONUS_SECURITY_POLICY
            logger.debug("Security policy detected: +%d bonus", _BONUS_SECURITY_POLICY)
        # D-836: penalty for missing SBOM
        if not _check_sbom_present(repo_dir):
            penalty += _PENALTY_NO_SBOM
            logger.debug("No SBOM detected: -%d penalty", _PENALTY_NO_SBOM)

    overall_float = overall_float + bonus - penalty
    overall = min(100, max(0, round(overall_float)))

    # D-837: Round to int only at output boundary.
    score = ScoreSummary(
        overall=overall,
        dependency=min(100, max(0, round(category_scores["dependency"]))),
        sast=min(100, max(0, round(category_scores["sast"]))),
        secrets=min(100, max(0, round(category_scores["secrets"]))),
        iac=min(100, max(0, round(category_scores["iac"]))),
        license=min(100, max(0, round(category_scores["license"]))),
    )

    logger.info(
        "Score: overall=%d dep=%d sast=%d secrets=%d iac=%d license=%d sc=%.1f",
        score.overall, score.dependency, score.sast, score.secrets, score.iac,
        score.license, category_scores.get("supply_chain", 100.0),
    )
    return score
