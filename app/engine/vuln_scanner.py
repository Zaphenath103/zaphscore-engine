"""
ZSE Vulnerability Scanner — queries OSV.dev for known vulnerabilities
in resolved dependencies. Uses batch query + individual detail fetch.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

import aiohttp

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
BATCH_SIZE = 1000
MAX_CONCURRENT_DETAIL = 100
MAX_RETRIES = 3
BASE_BACKOFF = 1.0  # seconds

# Map dependency ecosystem names to OSV ecosystem names
_ECO_MAP: dict[str, str] = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Go": "Go",
    "crates.io": "crates.io",
    "Maven": "Maven",
    "RubyGems": "RubyGems",
    "Packagist": "Packagist",
}


# ---------------------------------------------------------------------------
# CVSS parsing
# ---------------------------------------------------------------------------

def _parse_cvss_score(vector: str) -> Optional[float]:
    """Extract the numeric base score from a CVSS 3.x vector string.

    We compute a rough score from the vector components. For production use,
    a full CVSS calculator library would be ideal, but this gives a usable
    approximation from the vector alone.
    """
    if not vector:
        return None

    # If the vector already contains a score suffix like "/Score:7.5"
    m = re.search(r"[Ss]core[:/](\d+\.?\d*)", vector)
    if m:
        return min(float(m.group(1)), 10.0)

    # Rough mapping from vector metrics to base score bucket
    # AV:N (network) is highest impact
    metrics: dict[str, float] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    if not metrics:
        return None

    # Simplified scoring heuristic
    score = 5.0  # baseline
    av = metrics.get("AV", "N")
    if av == "N":
        score += 2.0
    elif av == "A":
        score += 1.0

    ac = metrics.get("AC", "L")
    if ac == "L":
        score += 1.0

    # Impact metrics
    for impact_key in ("C", "I", "A"):
        val = metrics.get(impact_key, "N")
        if val == "H":
            score += 0.8
        elif val == "L":
            score += 0.3

    return min(round(score, 1), 10.0)


def _severity_from_score(score: Optional[float]) -> Severity:
    """Map a CVSS score to our Severity enum."""
    if score is None:
        return Severity.medium
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score >= 0.1:
        return Severity.low
    return Severity.info


def _extract_severity(vuln: dict) -> tuple[Severity, Optional[float], Optional[str]]:
    """Extract severity, CVSS score, and CVSS vector from a vulnerability.

    Tries in order:
    1. CVSS 3.1 vector from severity array
    2. database_specific.severity
    3. Ecosystem-specific default
    """
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # Try severity array (CVSS vectors)
    for sev_entry in vuln.get("severity", []):
        stype = sev_entry.get("type", "")
        score_str = sev_entry.get("score", "")
        if "CVSS" in stype.upper() and score_str:
            cvss_vector = score_str
            cvss_score = _parse_cvss_score(score_str)
            if cvss_score is not None:
                return _severity_from_score(cvss_score), cvss_score, cvss_vector

    # Try database_specific.severity
    db_sev = (vuln.get("database_specific") or {}).get("severity", "")
    if isinstance(db_sev, str) and db_sev.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        mapped = db_sev.upper()
        if mapped == "MODERATE":
            mapped = "MEDIUM"
        return Severity(mapped.lower()), cvss_score, cvss_vector

    # Default to medium
    return Severity.medium, cvss_score, cvss_vector


def _extract_aliases(vuln: dict) -> tuple[Optional[str], Optional[str]]:
    """Extract CVE-ID and GHSA-ID from aliases."""
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = cve_id or alias
        elif alias.startswith("GHSA-"):
            ghsa_id = ghsa_id or alias
    # The vuln id itself may be a GHSA or CVE
    vuln_id = vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        cve_id = cve_id or vuln_id
    elif vuln_id.startswith("GHSA-"):
        ghsa_id = ghsa_id or vuln_id
    return cve_id, ghsa_id


def _extract_fix_version(vuln: dict, pkg_name: str) -> Optional[str]:
    """Find the earliest fix version for a given package from affected ranges."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "") != pkg_name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _build_summary(vuln: dict) -> str:
    """Build a human-readable summary from the vulnerability."""
    summary = vuln.get("summary", "")
    if summary:
        return summary[:500]
    details = vuln.get("details", "")
    if details:
        # Strip markdown, take first 500 chars
        cleaned = re.sub(r"[#*`\[\]]", "", details).strip()
        return cleaned[:500]
    return "No description available."


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

async def _post_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    json_body: dict,
) -> dict:
    """POST with exponential backoff on 429/5xx."""
    for attempt in range(MAX_RETRIES):
        try:
            async with session.post(url, json=json_body) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 429 or resp.status >= 500:
                    wait = BASE_BACKOFF * (2 ** attempt)
                    logger.warning("OSV API %d on %s, retry in %.1fs", resp.status, url, wait)
                    await asyncio.sleep(wait)
                    continue
                # Other error
                text = await resp.text()
                logger.error("OSV API error %d: %s", resp.status, text[:200])
                return {}
        except aiohttp.ClientError as exc:
            wait = BASE_BACKOFF * (2 ** attempt)
            logger.warning("OSV request failed: %s, retry in %.1fs", exc, wait)
            await asyncio.sleep(wait)
    return {}


async def _get_with_retry(
    session: aiohttp.ClientSession,
    url: str,
) -> dict:
    """GET with exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 429 or resp.status >= 500:
                    wait = BASE_BACKOFF * (2 ** attempt)
                    await asyncio.sleep(wait)
                    continue
                return {}
        except aiohttp.ClientError as exc:
            wait = BASE_BACKOFF * (2 ** attempt)
            logger.warning("OSV GET failed: %s, retry in %.1fs", exc, wait)
            await asyncio.sleep(wait)
    return {}


# ---------------------------------------------------------------------------
# Batch query
# ---------------------------------------------------------------------------

async def _query_batch(
    session: aiohttp.ClientSession,
    dependencies: list[dict],
) -> dict[str, set[str]]:
    """Query OSV batch API. Returns {pkg_key: set_of_vuln_ids}.

    pkg_key = "ecosystem:name:version"
    """
    results: dict[str, set[str]] = {}

    # Build queries in batches of BATCH_SIZE
    for i in range(0, len(dependencies), BATCH_SIZE):
        batch = dependencies[i:i + BATCH_SIZE]
        queries = []
        batch_keys: list[str] = []

        for dep in batch:
            ecosystem = _ECO_MAP.get(dep["ecosystem"])
            if not ecosystem:
                continue
            query: dict[str, Any] = {
                "package": {
                    "name": dep["name"],
                    "ecosystem": ecosystem,
                },
            }
            if dep["version"] and dep["version"] != "*":
                query["version"] = dep["version"]
            queries.append({"query": query})
            batch_keys.append(f"{dep['ecosystem']}:{dep['name']}:{dep['version']}")

        if not queries:
            continue

        body = {"queries": queries}
        data = await _post_with_retry(session, OSV_BATCH_URL, body)

        for idx, result in enumerate(data.get("results", [])):
            vulns = result.get("vulns", [])
            if vulns and idx < len(batch_keys):
                key = batch_keys[idx]
                results.setdefault(key, set())
                for v in vulns:
                    vid = v.get("id", "")
                    if vid:
                        results[key].add(vid)

    return results


# ---------------------------------------------------------------------------
# Detail fetch
# ---------------------------------------------------------------------------

async def _fetch_vuln_details(
    session: aiohttp.ClientSession,
    vuln_ids: set[str],
) -> dict[str, dict]:
    """Fetch full vulnerability details for each ID, with concurrency limit."""
    sem = asyncio.Semaphore(MAX_CONCURRENT_DETAIL)
    details: dict[str, dict] = {}

    async def _fetch_one(vid: str) -> None:
        async with sem:
            data = await _get_with_retry(session, f"{OSV_VULN_URL}/{vid}")
            if data:
                details[vid] = data

    tasks = [_fetch_one(vid) for vid in vuln_ids]
    await asyncio.gather(*tasks)
    return details


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def scan_vulnerabilities(dependencies: list[dict]) -> list[Finding]:
    """Scan a list of resolved dependencies against OSV.dev.

    Args:
        dependencies: List of dicts with keys: name, version, ecosystem.

    Returns:
        List of Finding objects for each known vulnerability.
    """
    if not dependencies:
        return []

    findings: list[Finding] = []
    timeout = aiohttp.ClientTimeout(total=300)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Phase 1: Batch query
        logger.info("Querying OSV.dev for %d dependencies", len(dependencies))
        pkg_vulns = await _query_batch(session, dependencies)

        # Collect all unique vuln IDs
        all_vuln_ids: set[str] = set()
        for vid_set in pkg_vulns.values():
            all_vuln_ids.update(vid_set)

        if not all_vuln_ids:
            logger.info("No vulnerabilities found")
            return []

        logger.info("Found %d unique vulnerabilities, fetching details", len(all_vuln_ids))

        # Phase 2: Fetch full details
        vuln_details = await _fetch_vuln_details(session, all_vuln_ids)

    # Phase 3: Build findings
    # Create a lookup from dep key to dep info
    dep_lookup: dict[str, dict] = {}
    for dep in dependencies:
        key = f"{dep['ecosystem']}:{dep['name']}:{dep['version']}"
        dep_lookup[key] = dep

    seen_findings: set[str] = set()  # dedup by (vuln_id, pkg_name)

    for pkg_key, vuln_ids in pkg_vulns.items():
        dep_info = dep_lookup.get(pkg_key, {})
        pkg_name = dep_info.get("name", "unknown")

        for vid in vuln_ids:
            dedup_key = f"{vid}:{pkg_name}"
            if dedup_key in seen_findings:
                continue
            seen_findings.add(dedup_key)

            vuln = vuln_details.get(vid, {})
            if not vuln:
                # We have the ID but couldn't fetch details
                findings.append(Finding(
                    type=FindingType.vulnerability,
                    severity=Severity.medium,
                    title=f"{vid} in {pkg_name}",
                    description=f"Vulnerability {vid} affects {pkg_name}@{dep_info.get('version', '?')}",
                    cve_id=vid if vid.startswith("CVE-") else None,
                    ghsa_id=vid if vid.startswith("GHSA-") else None,
                ))
                continue

            severity, cvss_score, cvss_vector = _extract_severity(vuln)
            cve_id, ghsa_id = _extract_aliases(vuln)
            fix_version = _extract_fix_version(vuln, pkg_name)
            summary = _build_summary(vuln)

            findings.append(Finding(
                type=FindingType.vulnerability,
                severity=severity,
                title=f"{vid}: {vuln.get('summary', pkg_name)[:120]}",
                description=(
                    f"**Package:** {pkg_name}@{dep_info.get('version', '?')}\n"
                    f"**Ecosystem:** {dep_info.get('ecosystem', '?')}\n"
                    f"{summary}"
                ),
                cve_id=cve_id,
                ghsa_id=ghsa_id,
                fix_version=fix_version,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
            ))

    logger.info("Produced %d vulnerability findings", len(findings))
    return findings
