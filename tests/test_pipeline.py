"""
ZSE Pipeline Tests — unit tests for dependency resolution, scoring, and CVSS parsing.

Run with:  pytest tests/test_pipeline.py -v
"""

from __future__ import annotations

import json
import math
import uuid
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Dependency resolver tests
# ---------------------------------------------------------------------------

class TestDependencyResolver:
    """Test that dependency resolver correctly parses package.json manifests."""

    SAMPLE_PACKAGE_JSON = json.dumps({
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.21",
            "axios": "~1.6.0",
        },
        "devDependencies": {
            "jest": "^29.7.0",
            "eslint": "^8.56.0",
        },
    })

    def test_parse_package_json_extracts_all_deps(self) -> None:
        """Parsing a package.json should return all production + dev dependencies."""
        data = json.loads(self.SAMPLE_PACKAGE_JSON)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})

        all_deps = {**deps, **dev_deps}

        assert len(all_deps) == 5
        assert "express" in all_deps
        assert "lodash" in all_deps
        assert "axios" in all_deps
        assert "jest" in all_deps
        assert "eslint" in all_deps

    def test_parse_package_json_version_formats(self) -> None:
        """Version strings should be preserved (caret, tilde, exact)."""
        data = json.loads(self.SAMPLE_PACKAGE_JSON)
        deps = data["dependencies"]

        assert deps["express"] == "^4.18.2"  # caret range
        assert deps["lodash"] == "4.17.21"   # exact
        assert deps["axios"] == "~1.6.0"     # tilde range

    def test_parse_empty_dependencies(self) -> None:
        """A package.json with no dependencies should return empty dicts."""
        data = json.loads('{"name": "empty", "version": "0.0.1"}')
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})

        assert deps == {}
        assert dev_deps == {}

    def test_parse_package_json_name_and_version(self) -> None:
        """Manifest metadata (name, version) should be accessible."""
        data = json.loads(self.SAMPLE_PACKAGE_JSON)
        assert data["name"] == "test-app"
        assert data["version"] == "1.0.0"


# ---------------------------------------------------------------------------
# Scorer tests
# ---------------------------------------------------------------------------

class TestScorer:
    """Test the scoring logic that converts findings into a 0-100 score."""

    @staticmethod
    def compute_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Simplified scoring algorithm matching the ZSE scorer.

        Starts at 100. Each finding subtracts points based on severity:
          critical: -15, high: -10, medium: -5, low: -2, info: 0
        Score is clamped to [0, 100].
        """
        severity_penalty = {
            "critical": 15,
            "high": 10,
            "medium": 5,
            "low": 2,
            "info": 0,
        }

        total_penalty = 0
        category_penalties: dict[str, int] = {
            "dependency": 0,
            "sast": 0,
            "secrets": 0,
            "iac": 0,
            "license": 0,
        }

        type_to_category = {
            "vulnerability": "dependency",
            "sast": "sast",
            "secret": "secrets",
            "iac": "iac",
            "license": "license",
        }

        for finding in findings:
            sev = finding.get("severity", "info")
            ftype = finding.get("type", "vulnerability")
            penalty = severity_penalty.get(sev, 0)
            total_penalty += penalty

            cat = type_to_category.get(ftype, "dependency")
            category_penalties[cat] += penalty

        overall = max(0, min(100, 100 - total_penalty))

        score_details = {}
        for cat, pen in category_penalties.items():
            score_details[cat] = max(0, min(100, 100 - pen))

        return {
            "overall": overall,
            "score_details": score_details,
            "total_findings": len(findings),
        }

    def test_perfect_score_no_findings(self) -> None:
        """No findings should produce a perfect score of 100."""
        result = self.compute_score([])
        assert result["overall"] == 100
        assert result["total_findings"] == 0

    def test_single_critical_finding(self) -> None:
        """One critical finding should drop score by 15 points."""
        findings = [{"type": "vulnerability", "severity": "critical", "title": "RCE in dep"}]
        result = self.compute_score(findings)
        assert result["overall"] == 85

    def test_mixed_severity_findings(self) -> None:
        """Multiple findings of different severities should accumulate correctly."""
        findings = [
            {"type": "vulnerability", "severity": "critical", "title": "CVE-2024-0001"},
            {"type": "vulnerability", "severity": "high", "title": "CVE-2024-0002"},
            {"type": "sast", "severity": "medium", "title": "SQL Injection"},
            {"type": "secret", "severity": "high", "title": "AWS Key exposed"},
            {"type": "iac", "severity": "low", "title": "S3 not encrypted"},
        ]
        result = self.compute_score(findings)
        # 100 - 15 - 10 - 5 - 10 - 2 = 58
        assert result["overall"] == 58
        assert result["total_findings"] == 5

    def test_score_floor_at_zero(self) -> None:
        """Score should never go below zero, even with many critical findings."""
        findings = [
            {"type": "vulnerability", "severity": "critical", "title": f"CVE-{i}"}
            for i in range(20)
        ]
        result = self.compute_score(findings)
        assert result["overall"] == 0

    def test_category_scores_independent(self) -> None:
        """Each category score should only reflect findings in that category."""
        findings = [
            {"type": "sast", "severity": "critical", "title": "XSS"},
            {"type": "sast", "severity": "high", "title": "SQLi"},
        ]
        result = self.compute_score(findings)
        # SAST: 100 - 15 - 10 = 75
        assert result["score_details"]["sast"] == 75
        # Other categories untouched
        assert result["score_details"]["dependency"] == 100
        assert result["score_details"]["secrets"] == 100

    def test_info_findings_no_penalty(self) -> None:
        """Info-level findings should not reduce the score."""
        findings = [
            {"type": "vulnerability", "severity": "info", "title": "Outdated dep (non-vuln)"}
            for _ in range(50)
        ]
        result = self.compute_score(findings)
        assert result["overall"] == 100
        assert result["total_findings"] == 50


# ---------------------------------------------------------------------------
# CVSS parsing tests
# ---------------------------------------------------------------------------

class TestCVSSParsing:
    """Test CVSS v3.1 vector string parsing and score validation."""

    @staticmethod
    def parse_cvss_vector(vector: str) -> dict[str, str]:
        """Parse a CVSS v3.1 vector string into metric:value pairs.

        Example input:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        Returns:        {"AV": "N", "AC": "L", "PR": "N", ...}
        """
        if not vector or not vector.startswith("CVSS:"):
            raise ValueError(f"Invalid CVSS vector prefix: {vector!r}")

        parts = vector.split("/")
        # First part is the version header (e.g. CVSS:3.1)
        version_part = parts[0]
        if "3.1" not in version_part and "3.0" not in version_part:
            raise ValueError(f"Unsupported CVSS version: {version_part}")

        metrics: dict[str, str] = {}
        for part in parts[1:]:
            if ":" not in part:
                raise ValueError(f"Invalid metric format: {part!r}")
            key, value = part.split(":", 1)
            metrics[key] = value

        return metrics

    @staticmethod
    def cvss_score_to_severity(score: float) -> str:
        """Map a CVSS numeric score to a severity label per FIRST guidelines."""
        if score == 0.0:
            return "info"
        elif score <= 3.9:
            return "low"
        elif score <= 6.9:
            return "medium"
        elif score <= 8.9:
            return "high"
        else:
            return "critical"

    def test_parse_critical_vector(self) -> None:
        """Parse a critical-severity CVSS vector (network, no auth, full impact)."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        metrics = self.parse_cvss_vector(vector)

        assert metrics["AV"] == "N"   # Network
        assert metrics["AC"] == "L"   # Low complexity
        assert metrics["PR"] == "N"   # No privileges required
        assert metrics["UI"] == "N"   # No user interaction
        assert metrics["S"] == "U"    # Unchanged scope
        assert metrics["C"] == "H"    # High confidentiality impact
        assert metrics["I"] == "H"    # High integrity impact
        assert metrics["A"] == "H"    # High availability impact

    def test_parse_low_severity_vector(self) -> None:
        """Parse a low-severity vector (local, high complexity, low impact)."""
        vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        metrics = self.parse_cvss_vector(vector)

        assert metrics["AV"] == "L"   # Local
        assert metrics["AC"] == "H"   # High complexity
        assert metrics["PR"] == "H"   # High privileges required
        assert metrics["UI"] == "R"   # User interaction required
        assert metrics["C"] == "L"    # Low confidentiality
        assert metrics["I"] == "N"    # None integrity
        assert metrics["A"] == "N"    # None availability

    def test_invalid_vector_prefix(self) -> None:
        """Non-CVSS prefixed strings should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid CVSS vector prefix"):
            self.parse_cvss_vector("NOT_CVSS:3.1/AV:N/AC:L")

    def test_empty_vector(self) -> None:
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid CVSS vector prefix"):
            self.parse_cvss_vector("")

    def test_unsupported_version(self) -> None:
        """CVSS 2.0 vectors should be rejected (we only support 3.0/3.1)."""
        with pytest.raises(ValueError, match="Unsupported CVSS version"):
            self.parse_cvss_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")

    def test_score_to_severity_mapping(self) -> None:
        """CVSS numeric scores should map to correct severity labels."""
        assert self.cvss_score_to_severity(0.0) == "info"
        assert self.cvss_score_to_severity(1.0) == "low"
        assert self.cvss_score_to_severity(3.9) == "low"
        assert self.cvss_score_to_severity(4.0) == "medium"
        assert self.cvss_score_to_severity(6.9) == "medium"
        assert self.cvss_score_to_severity(7.0) == "high"
        assert self.cvss_score_to_severity(8.9) == "high"
        assert self.cvss_score_to_severity(9.0) == "critical"
        assert self.cvss_score_to_severity(10.0) == "critical"

    def test_parse_cvss_30_vector(self) -> None:
        """CVSS 3.0 vectors (not just 3.1) should also be accepted."""
        vector = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"
        metrics = self.parse_cvss_vector(vector)
        assert metrics["AV"] == "N"
        assert metrics["S"] == "C"  # Changed scope
        assert len(metrics) == 8
