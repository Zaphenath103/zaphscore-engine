"""
D-024: Unit tests for app/engine/scorer.py

Tests cover:
  - Weight sum assertion (D-028 guard)
  - Score floor: never returns 0 even under maximum findings
  - Diminishing returns: each additional finding of same type deducts less
  - Clean repo: returns 100 (no findings, no bonuses from disk)
  - Weighted average correctness
  - Category isolation: finding in one category doesn't affect others
  - Score cap: never exceeds 100
"""

from __future__ import annotations

import uuid

import pytest

from app.engine.scorer import _WEIGHTS, calculate_score
from app.models.schemas import Finding, FindingType, ScoreSummary, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    type: FindingType = FindingType.vulnerability,
    severity: Severity = Severity.critical,
) -> Finding:
    return Finding(id=uuid.uuid4(), type=type, severity=severity, title="test")


# ---------------------------------------------------------------------------
# Weight integrity
# ---------------------------------------------------------------------------

def test_weights_sum_to_one():
    """D-028: weights must sum exactly to 1.0."""
    total = sum(_WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9, f"Weights sum to {total}, expected 1.0"


def test_all_expected_categories_present():
    expected = {"dependency", "sast", "secrets", "iac", "license"}
    assert set(_WEIGHTS.keys()) == expected


# ---------------------------------------------------------------------------
# Score floor
# ---------------------------------------------------------------------------

def test_score_floor_never_zero():
    """Even with 100 critical vulnerabilities, score must be >= 1."""
    findings = [_finding(FindingType.vulnerability, Severity.critical) for _ in range(100)]
    result = calculate_score(findings, repo_dir=None)
    assert result.overall >= 1
    assert result.dependency >= 1


def test_score_floor_across_all_categories():
    """Flood every category with criticals — each category score stays >= 1."""
    findings = []
    for _ in range(20):
        findings.append(_finding(FindingType.vulnerability, Severity.critical))
        findings.append(_finding(FindingType.sast, Severity.critical))
        findings.append(_finding(FindingType.secret, Severity.critical))
        findings.append(_finding(FindingType.iac, Severity.critical))
        findings.append(_finding(FindingType.license, Severity.critical))

    result = calculate_score(findings, repo_dir=None)
    assert result.dependency >= 1
    assert result.sast >= 1
    assert result.secrets >= 1
    assert result.iac >= 1
    assert result.license >= 1


# ---------------------------------------------------------------------------
# Diminishing returns
# ---------------------------------------------------------------------------

def test_diminishing_returns_second_critical_deducts_less():
    """Second critical of same type must deduct less than the first."""
    one_critical = calculate_score(
        [_finding(FindingType.vulnerability, Severity.critical)], repo_dir=None
    )
    two_criticals = calculate_score(
        [_finding(FindingType.vulnerability, Severity.critical)] * 2, repo_dir=None
    )
    # Going from 1 → 2 criticals should drop the score, but less than the first drop
    first_drop = 100 - one_critical.dependency
    second_drop = one_critical.dependency - two_criticals.dependency
    assert second_drop < first_drop, (
        f"Diminishing returns failed: first_drop={first_drop}, second_drop={second_drop}"
    )


def test_diminishing_returns_ordering():
    """More findings always means same or lower score (monotonically non-increasing)."""
    scores = []
    for n in range(1, 8):
        findings = [_finding(FindingType.sast, Severity.high) for _ in range(n)]
        result = calculate_score(findings, repo_dir=None)
        scores.append(result.sast)

    for i in range(1, len(scores)):
        assert scores[i] <= scores[i - 1], (
            f"Score increased from n={i} to n={i+1}: {scores[i-1]} → {scores[i]}"
        )


# ---------------------------------------------------------------------------
# Clean repo
# ---------------------------------------------------------------------------

def test_clean_repo_scores_100():
    """No findings, no repo_dir → perfect score of 100."""
    result = calculate_score([], repo_dir=None)
    assert result.overall == 100
    assert result.dependency == 100
    assert result.sast == 100
    assert result.secrets == 100
    assert result.iac == 100
    assert result.license == 100


# ---------------------------------------------------------------------------
# Category isolation
# ---------------------------------------------------------------------------

def test_critical_vuln_only_affects_dependency_category():
    """A vulnerability finding must only deduct from dependency, not sast/secrets/iac/license."""
    result = calculate_score(
        [_finding(FindingType.vulnerability, Severity.critical)], repo_dir=None
    )
    assert result.sast == 100
    assert result.secrets == 100
    assert result.iac == 100
    assert result.license == 100
    assert result.dependency < 100


def test_secret_only_affects_secrets_category():
    result = calculate_score(
        [_finding(FindingType.secret, Severity.high)], repo_dir=None
    )
    assert result.dependency == 100
    assert result.sast == 100
    assert result.iac == 100
    assert result.license == 100
    assert result.secrets < 100


# ---------------------------------------------------------------------------
# Score cap
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    """Score is always capped at 100 even with bonuses."""
    result = calculate_score([], repo_dir=None)
    assert result.overall <= 100


# ---------------------------------------------------------------------------
# Weighted average correctness
# ---------------------------------------------------------------------------

def test_weighted_average_single_medium_vuln():
    """With one medium vulnerability, only dependency drops; overall reflects weight."""
    result = calculate_score(
        [_finding(FindingType.vulnerability, Severity.medium)], repo_dir=None
    )
    # dependency should be 100 - 3 = 97 (first medium vuln deduction = 3)
    assert result.dependency == 97

    # overall = 97*0.35 + 100*0.25 + 100*0.25 + 100*0.10 + 100*0.05
    expected_overall = round(97 * _WEIGHTS["dependency"] + 100 * sum(
        w for k, w in _WEIGHTS.items() if k != "dependency"
    ))
    assert result.overall == expected_overall


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

def test_returns_score_summary_instance():
    result = calculate_score([], repo_dir=None)
    assert isinstance(result, ScoreSummary)
    assert isinstance(result.overall, int)
    assert isinstance(result.dependency, int)


def test_info_findings_do_not_deduct():
    """Info-severity findings must never deduct points (deduction table = 0)."""
    findings = [_finding(FindingType.vulnerability, Severity.info) for _ in range(50)]
    result = calculate_score(findings, repo_dir=None)
    assert result.dependency == 100
    assert result.overall == 100
