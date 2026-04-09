"""
ZSE Score Calculator — weighted aggregate scoring across all scan categories.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from app.models.schemas import Finding, FindingType, Severity, ScoreSummary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deduction tables: {severity: points_deducted} per finding type
# ---------------------------------------------------------------------------

_DEDUCTIONS: dict[FindingType, dict[Severity, int]] = {
    FindingType.vulnerability: {
        Severity.critical: 15,
        Severity.high: 8,
        Severity.medium: 3,
        Severity.low: 1,
        Severity.info: 0,
    },
    FindingType.sast: {
        Severity.critical: 12,
        Severity.high: 6,
        Severity.medium: 2,
        Severity.low: 1,
        Severity.info: 0,
    },
    FindingType.secret: {
        Severity.critical: 20,
        Severity.high: 12,
        Severity.medium: 5,
        Severity.low: 2,
        Severity.info: 0,
    },
    FindingType.iac: {
        Severity.critical: 10,
        Severity.high: 5,
        Severity.medium: 2,
        Severity.low: 1,
        Severity.info: 0,
    },
    FindingType.license: {
        Severity.critical: 10,
        Severity.high: 5,
        Severity.medium: 2,
        Severity.low: 1,
        Severity.info: 0,
    },
}

# Category weights (must sum to 1.0)
_WEIGHTS: dict[str, float] = {
    "dependency": 0.35,
    "sast": 0.25,
    "secrets": 0.25,
    "iac": 0.10,
    "license": 0.05,
}

# D-028: Guard against future weight drift — caught at import time, not production
assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9, (
    f"Scorer weights must sum to 1.0 — got {sum(_WEIGHTS.values()):.6f}. "
    "Adjust _WEIGHTS so all values total exactly 1.0."
)

# Map FindingType to category name
_TYPE_TO_CATEGORY: dict[FindingType, str] = {
    FindingType.vulnerability: "dependency",
    FindingType.sast: "sast",
    FindingType.secret: "secrets",
    FindingType.iac: "iac",
    FindingType.license: "license",
}

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


def calculate_score(
    findings: list[Finding],
    repo_dir: Optional[str] = None,
) -> ScoreSummary:
    """Calculate the overall security score from all findings.

    Args:
        findings: All findings from all scan phases.
        repo_dir: Path to repo (for bonus checks). Can be None if repo is cleaned up.

    Returns:
        ScoreSummary with overall (0-100) and per-category (0-100) scores.
    """
    # Start each category at 100
    category_scores: dict[str, int] = {
        "dependency": 100,
        "sast": 100,
        "secrets": 100,
        "iac": 100,
        "license": 100,
    }

    # D-025: Apply deductions with logarithmic diminishing returns per category.
    # Count findings per (category, severity) to compute progressive deductions.
    # First finding: full deduction. Second: 67%. Third: 44%. 4th+: 30% of base.
    # This ensures repos with 7 criticals are distinguishably worse than 2 criticals
    # but the score never hits absolute 0 from vulns alone (floor: 1).
    from collections import defaultdict
    _category_finding_counts: dict[tuple[str, str], int] = defaultdict(int)

    for finding in findings:
        category = _TYPE_TO_CATEGORY.get(finding.type)
        if not category:
            continue

        deduction_table = _DEDUCTIONS.get(finding.type, {})
        base_deduction = deduction_table.get(finding.severity, 0)
        if base_deduction == 0:
            continue

        key = (category, finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity))
        count = _category_finding_counts[key]  # 0-indexed before increment
        _category_finding_counts[key] += 1

        # Diminishing returns: factor = 1.0 / (1 + count * 0.5)
        # count=0 → 1.0x, count=1 → 0.67x, count=2 → 0.5x, count=3+ → 0.4x, etc.
        factor = 1.0 / (1.0 + count * 0.5)
        actual_deduction = max(1, round(base_deduction * factor))

        category_scores[category] = max(1, category_scores[category] - actual_deduction)

    # Floor at 1 (never absolute 0 — shows differentiation between bad and catastrophic)
    for cat in category_scores:
        category_scores[cat] = max(1, category_scores[cat])

    # Weighted average
    overall = sum(
        category_scores[cat] * weight
        for cat, weight in _WEIGHTS.items()
    )
    overall = round(overall)

    # Bonuses
    if repo_dir and os.path.isdir(repo_dir):
        if _check_bonus_cicd(repo_dir):
            overall += 5
            logger.debug("CI/CD config detected: +5 bonus")
        if _check_bonus_security_policy(repo_dir):
            overall += 3
            logger.debug("Security policy detected: +3 bonus")

    # Cap at 100
    overall = min(100, max(0, overall))

    score = ScoreSummary(
        overall=overall,
        dependency=category_scores["dependency"],
        sast=category_scores["sast"],
        secrets=category_scores["secrets"],
        iac=category_scores["iac"],
        license=category_scores["license"],
    )

    logger.info(
        "Score calculated: overall=%d | dep=%d sast=%d secrets=%d iac=%d license=%d",
        score.overall, score.dependency, score.sast, score.secrets, score.iac, score.license,
    )
    return score
