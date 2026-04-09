"""
ZSE Scan Pipeline — the brain of the engine. Orchestrates the full 12-phase
security scan: clone → deps → vulns → SAST → secrets → IaC → containers →
licenses → NVD enrichment → SBOM → fix generation → score.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import uuid
from datetime import datetime
from typing import Any, Callable, Coroutine, Optional

from app.models.schemas import (
    Finding,
    FindingType,
    ScanPhase,
    ScanSummary,
    ScoreSummary,
    Severity,
)
from app.engine.cloner import clone_repo
from app.engine.dependency_resolver import resolve_dependencies
from app.engine.vuln_scanner import scan_vulnerabilities
from app.engine.sast_scanner import scan_sast
from app.engine.secret_scanner import scan_secrets
from app.engine.iac_scanner import scan_iac
from app.engine.license_scanner import scan_licenses
from app.engine.container_scanner import scan_containers
from app.engine.nvd_scanner import enrich_with_nvd
from app.engine.sbom_generator import generate_sbom, scan_sbom_compliance
from app.engine.fix_generator import generate_fixes
from app.engine.scorer import calculate_score

logger = logging.getLogger(__name__)

# Type alias for the progress callback
ProgressCallback = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class ScanPipelineError(Exception):
    """Raised when the entire pipeline fails irrecoverably (e.g. clone fails)."""


def _build_summary(findings: list[Finding]) -> ScanSummary:
    """Build a ScanSummary from findings."""
    summary = ScanSummary(total_findings=len(findings))
    for f in findings:
        if f.severity == Severity.critical:
            summary.critical += 1
        elif f.severity == Severity.high:
            summary.high += 1
        elif f.severity == Severity.medium:
            summary.medium += 1
        elif f.severity == Severity.low:
            summary.low += 1
        elif f.severity == Severity.info:
            summary.info += 1
    return summary


async def _notify(
    callback: Optional[ProgressCallback],
    phase: ScanPhase,
    pct: int,
    message: str,
) -> None:
    """Send a progress update through the callback, if provided."""
    if callback is None:
        return
    try:
        await callback({
            "phase": phase.value,
            "pct": min(pct, 100),
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as exc:
        logger.warning("Progress callback failed: %s", exc)


async def run_scan(
    scan_id: str | uuid.UUID,
    repo_url: str,
    branch: Optional[str] = None,
    progress_callback: Optional[ProgressCallback] = None,
    github_token: Optional[str] = None,
    repo_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Execute the full 12-phase security scan pipeline.

    Args:
        scan_id: Unique identifier for this scan run.
        repo_url: GitHub repository URL to scan.
        branch: Branch to scan (None = default branch).
        progress_callback: Async callback receiving {phase, pct, message} dicts.
        github_token: Optional PAT for private repos.

    Returns:
        {
            "findings": list[Finding],
            "score": ScoreSummary,
            "summary": ScanSummary,
            "dependencies_count": int,
            "phases_completed": list[str],
            "phases_failed": list[str],
            "duration_seconds": float,
        }

    Raises:
        ScanPipelineError: If cloning fails (all other phases are best-effort).
    """
    start_time = datetime.utcnow()
    all_findings: list[Finding] = []
    dependencies: list[dict] = []
    phases_completed: list[str] = []
    phases_failed: list[str] = []
    warnings: list[str] = []
    tmp_dir: Optional[str] = None
    provided_repo_dir = repo_dir  # preserve caller's value before local reassignment

    try:
        # ------------------------------------------------------------------
        # Phase 1: Clone (skip if repo_dir already provided, e.g. CI mode)
        # ------------------------------------------------------------------
        if provided_repo_dir is not None:
            repo_dir = provided_repo_dir
            logger.info("[%s] Phase 1: Skipping clone — using provided repo_dir: %s", scan_id, repo_dir)
            phases_completed.append("clone")
            await _notify(progress_callback, ScanPhase.cloning, 12, "Using local repository directory")
        else:
            await _notify(progress_callback, ScanPhase.cloning, 0, "Cloning repository...")

            tmp_dir = tempfile.mkdtemp(prefix=f"zse-{scan_id}-")
            logger.info("[%s] Phase 1: Cloning %s (branch=%s) to %s", scan_id, repo_url, branch, tmp_dir)

            try:
                repo_dir = await clone_repo(
                    repo_url=repo_url,
                    branch=branch,
                    dest_dir=tmp_dir,
                    github_token=github_token,
                )
                phases_completed.append("clone")
                await _notify(progress_callback, ScanPhase.cloning, 12, "Repository cloned successfully")
            except Exception as exc:
                logger.error("[%s] Clone failed: %s", scan_id, exc)
                await _notify(progress_callback, ScanPhase.cloning, 0, f"Clone failed: {exc}")
                raise ScanPipelineError(f"Clone failed: {exc}") from exc

        # ------------------------------------------------------------------
        # Phase 2: Dependency resolution
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.dependency_resolution, 15, "Resolving dependencies...")
        logger.info("[%s] Phase 2: Resolving dependencies", scan_id)

        try:
            dependencies = await resolve_dependencies(repo_dir)
            phases_completed.append("dependency_resolution")
            await _notify(
                progress_callback, ScanPhase.dependency_resolution, 25,
                f"Resolved {len(dependencies)} dependencies",
            )
        except Exception as exc:
            logger.error("[%s] Dependency resolution failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("dependency_resolution")
            warnings.append(f"Dependency resolution failed: {exc}")
            await _notify(progress_callback, ScanPhase.dependency_resolution, 25, f"Dependency resolution failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 3: Vulnerability scan (OSV.dev)
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.vulnerability_scan, 28, "Scanning for vulnerabilities...")
        logger.info("[%s] Phase 3: Vulnerability scan (%d deps)", scan_id, len(dependencies))

        try:
            vuln_findings = await scan_vulnerabilities(dependencies)
            all_findings.extend(vuln_findings)
            phases_completed.append("vulnerability_scan")
            await _notify(
                progress_callback, ScanPhase.vulnerability_scan, 45,
                f"Found {len(vuln_findings)} vulnerabilities",
            )
        except Exception as exc:
            logger.error("[%s] Vulnerability scan failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("vulnerability_scan")
            warnings.append(f"Vulnerability scan failed: {exc}")
            await _notify(progress_callback, ScanPhase.vulnerability_scan, 45, f"Vulnerability scan failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 4: SAST scan (Semgrep)
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.sast_scan, 48, "Running static analysis...")
        logger.info("[%s] Phase 4: SAST scan", scan_id)

        try:
            sast_findings = await scan_sast(repo_dir)
            all_findings.extend(sast_findings)
            phases_completed.append("sast_scan")
            await _notify(
                progress_callback, ScanPhase.sast_scan, 60,
                f"Found {len(sast_findings)} SAST issues",
            )
        except Exception as exc:
            logger.error("[%s] SAST scan failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("sast_scan")
            warnings.append(f"SAST scan failed: {exc}")
            await _notify(progress_callback, ScanPhase.sast_scan, 60, f"SAST scan failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 5: Secret detection (TruffleHog)
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.secret_scan, 62, "Scanning for secrets...")
        logger.info("[%s] Phase 5: Secret scan", scan_id)

        try:
            secret_findings = await scan_secrets(repo_dir)
            all_findings.extend(secret_findings)
            phases_completed.append("secret_scan")
            await _notify(
                progress_callback, ScanPhase.secret_scan, 75,
                f"Found {len(secret_findings)} secrets",
            )
        except Exception as exc:
            logger.error("[%s] Secret scan failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("secret_scan")
            warnings.append(f"Secret scan failed: {exc}")
            await _notify(progress_callback, ScanPhase.secret_scan, 75, f"Secret scan failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 6: IaC scan (Checkov)
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.iac_scan, 78, "Scanning infrastructure-as-code...")
        logger.info("[%s] Phase 6: IaC scan", scan_id)

        try:
            iac_findings = await scan_iac(repo_dir)
            all_findings.extend(iac_findings)
            phases_completed.append("iac_scan")
            await _notify(
                progress_callback, ScanPhase.iac_scan, 85,
                f"Found {len(iac_findings)} IaC issues",
            )
        except Exception as exc:
            logger.error("[%s] IaC scan failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("iac_scan")
            warnings.append(f"IaC scan failed: {exc}")
            await _notify(progress_callback, ScanPhase.iac_scan, 85, f"IaC scan failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 6b: Container scanning (Trivy)
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.container_scan, 86, "Scanning containers...")
        logger.info("[%s] Phase 6b: Container scan", scan_id)

        try:
            container_findings = await scan_containers(repo_dir)
            all_findings.extend(container_findings)
            phases_completed.append("container_scan")
            await _notify(
                progress_callback, ScanPhase.container_scan, 88,
                f"Found {len(container_findings)} container issues",
            )
        except Exception as exc:
            logger.error("[%s] Container scan failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("container_scan")
            warnings.append(f"Container scan failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 7: License compliance
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.license_scan, 89, "Checking license compliance...")
        logger.info("[%s] Phase 7: License scan", scan_id)

        try:
            license_findings = await scan_licenses(repo_dir, dependencies)
            all_findings.extend(license_findings)
            phases_completed.append("license_scan")
        except Exception as exc:
            logger.error("[%s] License scan failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("license_scan")
            warnings.append(f"License scan failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 7b: NVD enrichment (upgrade vuln data)
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.nvd_enrichment, 90, "Enriching with NVD data...")
        logger.info("[%s] Phase 7b: NVD enrichment", scan_id)

        try:
            vuln_finding_dicts = [
                f.model_dump() if hasattr(f, 'model_dump') else f
                for f in all_findings
                if (hasattr(f, 'cve_id') and f.cve_id) or (isinstance(f, dict) and f.get('cve_id'))
            ]
            if vuln_finding_dicts:
                enriched = await enrich_with_nvd(vuln_finding_dicts)
                logger.info("[%s] NVD enriched %d findings", scan_id, len(enriched))
                # Replace original findings with enriched versions
                enriched_by_id = {e.get("id") or e.get("cve_id"): e for e in enriched}
                for i, f in enumerate(all_findings):
                    f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
                    f_key = f_dict.get("id") or f_dict.get("cve_id")
                    if f_key and f_key in enriched_by_id:
                        enriched_data = enriched_by_id[f_key]
                        if hasattr(f, 'model_copy'):
                            all_findings[i] = f.model_copy(update={
                                k: v for k, v in enriched_data.items()
                                if v is not None and hasattr(f, k)
                            })
                        else:
                            all_findings[i] = Finding(**enriched_data)
            phases_completed.append("nvd_enrichment")
        except Exception as exc:
            logger.error("[%s] NVD enrichment failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("nvd_enrichment")
            warnings.append(f"NVD enrichment failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 7c: SBOM generation
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.sbom_generation, 91, "Generating SBOM...")
        logger.info("[%s] Phase 7c: SBOM generation", scan_id)

        sbom = None
        try:
            dep_dicts = [d if isinstance(d, dict) else d for d in dependencies]
            sbom = await generate_sbom(repo_dir, dep_dicts, format="cyclonedx")
            sbom_findings = await scan_sbom_compliance(sbom)
            all_findings.extend(sbom_findings)
            phases_completed.append("sbom_generation")
        except Exception as exc:
            logger.error("[%s] SBOM generation failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("sbom_generation")
            warnings.append(f"SBOM generation failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 7d: Fix generation
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.fix_generation, 92, "Generating fix suggestions...")
        logger.info("[%s] Phase 7d: Fix generation", scan_id)

        fixes = []
        try:
            finding_dicts = [
                f.model_dump() if hasattr(f, 'model_dump') else f
                for f in all_findings
            ]
            dep_dicts = [d if isinstance(d, dict) else d for d in dependencies]
            fixes = await generate_fixes(finding_dicts, dep_dicts, repo_dir)
            phases_completed.append("fix_generation")
            await _notify(
                progress_callback, ScanPhase.scoring, 93,
                f"Generated {len(fixes)} fix suggestions",
            )
        except Exception as exc:
            logger.error("[%s] Fix generation failed: %s", scan_id, exc, exc_info=True)
            phases_failed.append("fix_generation")
            warnings.append(f"Fix generation failed: {exc}")

        # ------------------------------------------------------------------
        # Phase 8: Score calculation
        # ------------------------------------------------------------------
        await _notify(progress_callback, ScanPhase.scoring, 95, "Calculating security score...")
        logger.info("[%s] Phase 8: Score calculation (%d total findings)", scan_id, len(all_findings))

        score = calculate_score(all_findings, repo_dir=repo_dir)
        summary = _build_summary(all_findings)
        phases_completed.append("scoring")

        await _notify(
            progress_callback, ScanPhase.scoring, 98,
            f"Score: {score.overall}/100 | {summary.total_findings} findings",
        )

        # ------------------------------------------------------------------
        # Done
        # ------------------------------------------------------------------
        duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info(
            "[%s] Scan complete in %.1fs — score=%d, findings=%d, "
            "phases_ok=%s, phases_failed=%s",
            scan_id, duration, score.overall, len(all_findings),
            phases_completed, phases_failed,
        )

        await _notify(progress_callback, ScanPhase.complete, 100, "Scan complete")

        return {
            "findings": all_findings,
            "score": score,
            "summary": summary,
            "dependencies_count": len(dependencies),
            "phases_completed": phases_completed,
            "phases_failed": phases_failed,
            "warnings": warnings,
            "duration_seconds": round(duration, 2),
            "sbom": sbom,
            "fixes": fixes,
        }

    finally:
        # ------------------------------------------------------------------
        # Cleanup: remove the temp directory
        # ------------------------------------------------------------------
        if tmp_dir:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                logger.debug("[%s] Cleaned up temp dir: %s", scan_id, tmp_dir)
            except Exception as exc:
                logger.warning("[%s] Failed to clean up %s: %s", scan_id, tmp_dir, exc)
