"""ZSE NVD Scanner — supplements OSV.dev with NIST NVD data for comprehensive coverage.

Queries the NVD 2.0 REST API to enrich vulnerability findings with
official CVSS v3.1 scores, CWE classifications, and reference URLs.

Rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key:   50 requests per 30 seconds

Set NVD_API_KEY in environment to unlock higher rate limits.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Optional

import aiohttp

logger = logging.getLogger("zse.nvd_scanner")

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting — 5 req / 30s without key, 50 / 30s with key
_api_key: Optional[str] = os.environ.get("NVD_API_KEY")
_CONCURRENCY = 50 if _api_key else 5
_WINDOW_SECONDS = 6.0 if _api_key else 6.0  # spread requests across window
_semaphore = asyncio.Semaphore(_CONCURRENCY)

MAX_RETRIES = 3
BASE_BACKOFF = 2.0  # seconds


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _headers() -> dict[str, str]:
    """Build request headers, including API key if available."""
    h: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "ZaphScore-Engine/0.1",
    }
    if _api_key:
        h["apiKey"] = _api_key
    return h


async def _get_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    params: Optional[dict] = None,
) -> dict:
    """GET with exponential backoff on 403/429/5xx."""
    for attempt in range(MAX_RETRIES):
        try:
            async with _semaphore:
                async with session.get(
                    url, params=params, headers=_headers()
                ) as resp:
                    if resp.status == 200:
                        # Rate-limit pacing: wait between requests
                        await asyncio.sleep(_WINDOW_SECONDS / _CONCURRENCY)
                        return await resp.json()

                    if resp.status in (403, 429) or resp.status >= 500:
                        wait = BASE_BACKOFF * (2 ** attempt)
                        logger.warning(
                            "NVD API %d on %s, retry in %.1fs (attempt %d/%d)",
                            resp.status, url, wait, attempt + 1, MAX_RETRIES,
                        )
                        await asyncio.sleep(wait)
                        continue

                    text = await resp.text()
                    logger.error("NVD API error %d: %s", resp.status, text[:300])
                    return {}
        except aiohttp.ClientError as exc:
            wait = BASE_BACKOFF * (2 ** attempt)
            logger.warning(
                "NVD request failed: %s, retry in %.1fs", exc, wait
            )
            await asyncio.sleep(wait)
    return {}


# ---------------------------------------------------------------------------
# NVD data extraction
# ---------------------------------------------------------------------------

def _extract_cvss31(cve_item: dict) -> tuple[Optional[float], Optional[str]]:
    """Extract CVSS v3.1 base score and vector from an NVD CVE item.

    Returns (score, vector_string) or (None, None).
    """
    metrics = cve_item.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        for metric in metric_list:
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            if score is not None:
                return float(score), vector

    return None, None


def _extract_cwes(cve_item: dict) -> list[str]:
    """Extract CWE IDs from an NVD CVE item."""
    cwes: list[str] = []
    weaknesses = cve_item.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return cwes


def _extract_references(cve_item: dict) -> list[dict[str, str]]:
    """Extract reference URLs from an NVD CVE item."""
    refs: list[dict[str, str]] = []
    for ref in cve_item.get("references", []):
        url = ref.get("url", "")
        source = ref.get("source", "")
        if url:
            refs.append({"url": url, "source": source})
    return refs[:10]  # cap at 10 references


def _extract_published(cve_item: dict) -> Optional[str]:
    """Extract the published date from an NVD CVE item."""
    return cve_item.get("published")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enrich_with_nvd(findings: list[dict]) -> list[dict]:
    """Enrich vulnerability findings with NVD data.

    For each finding that has a CVE ID, queries the NVD API to add:
    - Official CVSS v3.1 score and vector (replaces approximate scores)
    - CWE classification IDs
    - Reference URLs
    - Published date

    Args:
        findings: List of finding dicts (must have 'cve_id' key).

    Returns:
        The same list with enriched metadata.
    """
    # Filter findings that have CVE IDs
    cve_findings = [
        (i, f) for i, f in enumerate(findings) if f.get("cve_id")
    ]

    if not cve_findings:
        logger.info("No CVE IDs to enrich with NVD data")
        return findings

    logger.info("Enriching %d findings with NVD data", len(cve_findings))

    timeout = aiohttp.ClientTimeout(total=300)
    enriched_count = 0

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for idx, finding in cve_findings:
            tasks.append(_enrich_single(session, idx, finding, findings))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.warning("NVD enrichment error: %s", result)
            elif result:
                enriched_count += 1

    logger.info(
        "NVD enrichment complete: %d/%d findings enriched",
        enriched_count, len(cve_findings),
    )
    return findings


async def _enrich_single(
    session: aiohttp.ClientSession,
    idx: int,
    finding: dict,
    findings: list[dict],
) -> bool:
    """Enrich a single finding with NVD data. Returns True if enriched."""
    cve_id = finding["cve_id"]
    data = await _get_with_retry(session, NVD_CVE_URL, {"cveId": cve_id})

    if not data:
        return False

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return False

    cve_item = vulnerabilities[0].get("cve", {})
    if not cve_item:
        return False

    # Extract NVD data
    nvd_score, nvd_vector = _extract_cvss31(cve_item)
    cwes = _extract_cwes(cve_item)
    references = _extract_references(cve_item)
    published = _extract_published(cve_item)

    # Update the finding in-place
    metadata = finding.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    # Replace CVSS score if NVD has an official one
    if nvd_score is not None:
        old_score = finding.get("cvss_score")
        finding["cvss_score"] = nvd_score
        finding["cvss_vector"] = nvd_vector
        metadata["nvd_cvss_source"] = "NVD_OFFICIAL"
        if old_score is not None and old_score != nvd_score:
            metadata["osv_cvss_score"] = old_score
            logger.debug(
                "CVE %s: CVSS updated %.1f -> %.1f (NVD official)",
                cve_id, old_score, nvd_score,
            )

    # Add CWE classification
    if cwes:
        metadata["cwe_ids"] = cwes

    # Add references
    if references:
        metadata["nvd_references"] = references

    # Add published date
    if published:
        metadata["nvd_published"] = published

    finding["metadata"] = metadata
    findings[idx] = finding
    return True


async def search_nvd(
    keyword: str,
    results_per_page: int = 20,
) -> list[dict[str, Any]]:
    """Search NVD for vulnerabilities by keyword.

    Useful for proactive scanning to find vulnerabilities for packages
    that may not be in OSV.dev.

    Args:
        keyword: Search term (package name, CVE pattern, etc.)
        results_per_page: Number of results to return (max 2000).

    Returns:
        List of dicts with keys: cve_id, description, cvss_score,
        severity, published.
    """
    results: list[dict[str, Any]] = []
    timeout = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 2000),
        }
        data = await _get_with_retry(session, NVD_SEARCH_URL, params)

    if not data:
        logger.warning("NVD keyword search returned no data for '%s'", keyword)
        return results

    for vuln_wrapper in data.get("vulnerabilities", []):
        cve_item = vuln_wrapper.get("cve", {})
        if not cve_item:
            continue

        cve_id = cve_item.get("id", "")
        published = cve_item.get("published")

        # Get description (prefer English)
        description = ""
        for desc in cve_item.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description:
            descs = cve_item.get("descriptions", [])
            if descs:
                description = descs[0].get("value", "")

        cvss_score, _ = _extract_cvss31(cve_item)

        # Determine severity from score
        severity = "medium"
        if cvss_score is not None:
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            elif cvss_score >= 0.1:
                severity = "low"
            else:
                severity = "info"

        results.append({
            "cve_id": cve_id,
            "description": description[:500],
            "cvss_score": cvss_score,
            "severity": severity,
            "published": published,
        })

    logger.info(
        "NVD search for '%s' returned %d results", keyword, len(results)
    )
    return results
