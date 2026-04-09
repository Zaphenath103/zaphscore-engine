"""
ZSE Pydantic models — request/response schemas for the entire API surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    complete = "complete"
    failed = "failed"


class FindingType(str, Enum):
    vulnerability = "vulnerability"
    sast = "sast"
    secret = "secret"
    iac = "iac"
    license = "license"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanPhase(str, Enum):
    cloning = "cloning"
    dependency_resolution = "dependency_resolution"
    vulnerability_scan = "vulnerability_scan"
    sast_scan = "sast_scan"
    secret_scan = "secret_scan"
    iac_scan = "iac_scan"
    container_scan = "container_scan"
    license_scan = "license_scan"
    nvd_enrichment = "nvd_enrichment"
    sbom_generation = "sbom_generation"
    fix_generation = "fix_generation"
    scoring = "scoring"
    complete = "complete"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="Full GitHub URL, e.g. https://github.com/owner/repo")
    branch: Optional[str] = Field(None, description="Branch to scan; defaults to repo default branch")
    github_token: Optional[str] = Field(None, description="Optional PAT for private repos")

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        # Accept https://github.com/owner/repo or github.com/owner/repo
        import re
        pattern = r"^(https?://)?(www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
        if not re.match(pattern, v):
            raise ValueError(
                "repo_url must be a valid GitHub repository URL "
                "(e.g. https://github.com/owner/repo)"
            )
        # Normalise to https://
        if not v.startswith("http"):
            v = f"https://{v}"
        return v


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus
    created_at: datetime
    stream_url: str


class ScoreSummary(BaseModel):
    overall: int = Field(..., ge=0, le=100)
    dependency: int = Field(0, ge=0, le=100)
    sast: int = Field(0, ge=0, le=100)
    secrets: int = Field(0, ge=0, le=100)
    iac: int = Field(0, ge=0, le=100)
    license: int = Field(0, ge=0, le=100)


class Finding(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    type: FindingType
    severity: Severity
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    fix_version: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    rule_id: Optional[str] = None


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus
    repo_url: str
    branch: Optional[str] = None
    score: Optional[int] = None
    score_details: Optional[ScoreSummary] = None
    findings: list[Finding] = []
    summary: Optional[ScanSummary] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class ScanProgress(BaseModel):
    phase: ScanPhase
    progress_pct: int = Field(..., ge=0, le=100)
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Repo info
# ---------------------------------------------------------------------------

class RepoInfo(BaseModel):
    owner: str
    repo: str
    stars: int = 0
    language: Optional[str] = None
    size_kb: int = 0
    default_branch: str = "main"


# ---------------------------------------------------------------------------
# Pagination wrapper
# ---------------------------------------------------------------------------

class PaginatedScans(BaseModel):
    items: list[ScanResult]
    total: int
    page: int
    per_page: int
