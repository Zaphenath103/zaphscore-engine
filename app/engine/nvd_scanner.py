"""ZSE NVD Scanner — supplements OSV.dev with NIST NVD data for comprehensive coverage.

Queries the NVD 2.0 REST API to enrich vulnerability findings with
official CVSS v4.0/v3.1 scores, CWE classifications, CISA KEV status,
and reference URLs.

Rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key:   50 requests per 30 seconds

Set NVD_API_KEY in environment to unlock higher rate limits.
Set NVD_API_KEYS (comma-separated) for key rotation pool (D-862).

D-853: Callers should schedule enrich_with_nvd() results to be cached in a
       shared store (Redis/Supabase) rather than per-scan. This module exposes
       a process-level LRU cache as a best-effort fallback.
D-854: _CVE_CACHE backed by a simple LRU; persistent caching (Redis/DB) is the
       recommended deployment pattern -- see pipeline.py for the hook.
D-856: CVSS v4.0 (cvssMetricV40) now extracted with priority over v3.x.
D-857: CISA KEV catalog queried once per process and cached; kev_in_catalog
       flag added to every enriched finding.
D-858: _extract_references cap raised from 10 to 50; vendor patch links
       are sorted to the front before capping.
D-862: NVD_API_KEYS rotation pool; keys are round-robined across concurrent scans
       so 10 simultaneous scans do not all share a single 50-req/30s budget.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections import OrderedDict
from itertools import cycle
from typing import Any, Optional

import aiohttp

logger = logging.getLogger("zse.nvd_scanner")

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ---------------------------------------------------------------------------
# D-862: API key rotation pool
# ---------------------------------------------------------------------------

def _load_api_keys() -> list[str]:
    """Load NVD API keys from environment.

    Supports:
    - NVD_API_KEYS: comma-separated list of keys (preferred for rotation)
    - NVD_API_KEY: single key (legacy, still supported)
    """
    multi = os.environ.get("NVD_API_KEYS", "")
    if multi:
        keys = [k.strip() for k in multi.split(",") if k.strip()]
        if keys:
            return keys
    single = os.environ.get("NVD_API_KEY", "").strip()
    if single:
        return [single]
    return []


_API_KEYS: list[str] = _load_api_keys()
_key_cycle = cycle(_API_KEYS) if _API_KEYS else None

# With at least one API key we get 50 req/30s per key; without: 5/30s.
_HAS_KEY = bool(_API_KEYS)
_CONCURRENCY = min(50 * len(_API_KEYS), 50) if _HAS_KEY else 5
_WINDOW_SECONDS = 6.0
_semaphore = asyncio.Semaphore(_CONCURRENCY)

MAX_RETRIES = 3
BASE_BACKOFF = 2.0

# ---------------------------------------------------------------------------
# D-854: Process-level LRU cache for CVE enrichment data.
# For production deployments, populate this from a shared Redis/Supabase cache
# at startup and write back enriched entries after each scan.
# ---------------------------------------------------------------------------

_LRU_MAX = 10_000  # entries; ~10MB at ~1KB per entry


class _LRUCache(OrderedDict):
    """Simple LRU cache backed by OrderedDict."""

    def __init__(self, maxsize: int) -> None:
        super().__init__()
        self._maxsize = maxsize

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        if key not in self:
            return default
        self.move_to_end(key)
        return self[key]

    def put(self, key: str, value: Any) -> None:
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self._maxsize:
            self.popitem(last=False)


_CVE_CACHE: _LRUCache = _LRUCache(_LRU_MAX)

# ---------------------------------------------------------------------------
# D-857: CISA KEV catalog cache (process-level, refreshed once per process)
# ---------------------------------------------------------------------------

_KEV_CACHE: set[str] = set()
_KEV_LOADED: bool = False
_kev_lock: Optional[asyncio.Lock] = None  # created lazily on first use


def _get_kev_lock() -> asyncio.Lock:
    global _kev_lock
    if _kev_lock is None:
        _kev_lock = asyncio.Lock()
    return _kev_lock


async def _ensure_kev_loaded(session: aiohttp.ClientSession) -> None:
    """Fetch the CISA KEV catalog once and cache all CVE IDs.

    The catalog is ~1MB JSON with ~1000 CVE IDs; fetched at most once per
    process lifetime. In production, schedule a refresh every 4 hours.
    """
    global _KEV_LOADED
    if _KEV_LOADED:
        return
    async with _get_kev_lock():
        if _KEV_LOADED:
            return
        try:
            async with session.get(CISA_KEV_URL, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for vuln in data.get("vulnerabilities", []):
                        cve_id = vuln.get("cveID", "")
                        if cve_id:
                            _KEV_CACHE.add(cve_id)
                    _KEV_LOADED = True
                    logger.info(
                        "CISA KEV catalog loaded: %d CVEs in active exploitation",
                        len(_KEV_CACHE),
                    )
                else:
                    logger.warning("CISA KEV fetch returned HTTP %d", resp.status)
        except Exception as exc:
            logger.warning("CISA KEV fetch failed: %s (KEV flags will be absent)", exc)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _next_api_key() -> Optional[str]:
    """Return the next API key from the rotation pool, or None."""
    if _key_cycle is None:
        return None
    return next(_key_cycle)


def _headers(api_key: Optional[str] = None) -> dict[str, str]:
    """Build request headers, including API key if available."""
    h: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "ZaphScore-Engine/0.1",
    }
    key = api_key or (_next_api_key() if _HAS_KEY else None)
    if key:
        h["apiKey"] = key
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
            logger.warning("NVD request failed: %s, retry in %.1fs", exc, wait)
            await asyncio.sleep(wait)
    return {}


# ---------------------------------------------------------------------------
# NVD data extraction
# ---------------------------------------------------------------------------

def _extract_cvss(cve_item: dict) -> tuple[Optional[float], Optional[str], str]:
    """D-856: Extract the best available CVSS score and vector from an NVD CVE item.

    Priority order: CVSS v4.0 > v3.1 > v3.0.
    Returns (score, vector_string, cvss_version) or (None, None, "").
    """
    metrics = cve_item.get("metrics", {})

    # D-856: Try CVSS v4.0 first (NVD publishing v4.0 scores since late 2024)
    for metric in metrics.get("cvssMetricV40", []):
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        if score is not None:
            return float(score), vector, "4.0"

    # Fall back to CVSS v3.1 then v3.0
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for metric in metrics.get(key, []):
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            if score is not None:
                return float(score), vector, version

    return None, None, ""


# Backwards-compatible alias used by existing callers that expect (score, vector)
def _extract_cvss31(cve_item: dict) -> tuple[Optional[float], Optional[str]]:
    """Backwards-compatible wrapper; returns (score, vector). D-856: now checks v4.0 first."""
    score, vector, _ = _extract_cvss(cve_item)
    return score, vector


def _extract_cwes(cve_item: dict) -> list[str]:
    """Extract CWE IDs from an NVD CVE item."""
    cwes: list[str] = []
    for weakness in cve_item.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return cwes


def _extract_references(cve_item: dict) -> list[dict[str, str]]:
    """D-858: Extract reference URLs from an NVD CVE item.

    Cap raised from 10 to 50. Vendor patch links (tags containing 'Patch'
    or 'Vendor Advisory') are sorted to the front so the most actionable
    links are never truncated.
    """
    _PRIORITY_TAGS = {"Patch", "Vendor Advisory", "Mitigation"}
    priority: list[dict[str, str]] = []
    others: list[dict[str, str]] = []

    for ref in cve_item.get("references", []):
        url = ref.get("url", "")
        source = ref.get("source", "")
        tags = set(ref.get("tags", []))
        if not url:
            continue
        entry: dict[str, str] = {"url": url, "source": source}
        if tags & _PRIORITY_TAGS:
            priority.append(entry)
        else:
            others.append(entry)

    combined = priority + others
    return combined[:50]  # D-858: cap raised from 10 to 50


def _extract_published(cve_item: dict) -> Optional[str]:
    """Extract the published date from an NVD CVE item."""
    return cve_item.get("published")


def _is_rejected(cve_item: dict) -> bool:
    """Check if a CVE has been rejected/withdrawn by NVD."""
    vuln_status = cve_item.get("vulnStatus", "")
    return vuln_status.upper() in ("REJECTED", "WITHDRAWN")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enrich_with_nvd(findings: list[dict]) -> list[dict]:
    """Enrich vulnerability findings with NVD data.

    For each finding that has a CVE ID, queries the NVD API to add:
    - Official CVSS v4.0/v3.1 score and vector (D-856)
    - CWE classification IDs
    - Reference URLs (up to 50, vendor patches first) (D-858)
    - Published date
    - CISA KEV catalog flag (D-857)

    D-854: Results are stored in _CVE_CACHE (process-level LRU). For persistent
           caching across cold starts, callers should persist the enriched findings
           to a shared store (Redis/Supabase) and pre-warm the cache at startup.

    D-853: For scheduled NVD sync, call enrich_with_nvd() from a background task
           that runs every 2 hours against a list of recently-seen CVEs, updating
           the shared cache. The per-scan call then hits cache, not NVD directly.

    Args:
        findings: List of finding dicts (must have 'cve_id' key).

    Returns:
        The same list with enriched metadata.
    """
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
        # D-857: Pre-load CISA KEV catalog before enriching
        await _ensure_kev_loaded(session)

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

    # D-854: Check process-level LRU cache first
    cached = _CVE_CACHE.get(cve_id)
    if cached is not None:
        _apply_nvd_data(finding, cached, cve_id)
        findings[idx] = finding
        return True

    data = await _get_with_retry(session, NVD_CVE_URL, {"cveId": cve_id})
    if not data:
        return False

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return False

    cve_item = vulnerabilities[0].get("cve", {})
    if not cve_item:
        return False

    # Store extracted data in LRU cache
    nvd_data = {
        "cvss": _extract_cvss(cve_item),            # (score, vector, version)
        "cwes": _extract_cwes(cve_item),
        "references": _extract_references(cve_item),
        "published": _extract_published(cve_item),
        "rejected": _is_rejected(cve_item),
    }
    _CVE_CACHE.put(cve_id, nvd_data)

    _apply_nvd_data(finding, nvd_data, cve_id)
    findings[idx] = finding
    return True


def _apply_nvd_data(finding: dict, nvd_data: dict, cve_id: str) -> None:
    """Apply extracted NVD data to a finding dict in-place."""
    nvd_score, nvd_vector, cvss_version = nvd_data["cvss"]
    cwes = nvd_data["cwes"]
    references = nvd_data["references"]
    published = nvd_data["published"]
    rejected = nvd_data.get("rejected", False)

    metadata = finding.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    # Replace CVSS score if NVD has an official one
    if nvd_score is not None:
        old_score = finding.get("cvss_score")
        finding["cvss_score"] = nvd_score
        finding["cvss_vector"] = nvd_vector
        metadata["nvd_cvss_source"] = f"NVD_OFFICIAL_v{cvss_version}"
        if old_score is not None and old_score != nvd_score:
            metadata["osv_cvss_score"] = old_score
            logger.debug(
                "CVE %s: CVSS updated %.1f -> %.1f (NVD official v%s)",
                cve_id, old_score, nvd_score, cvss_version,
            )

    if cwes:
        metadata["cwe_ids"] = cwes

    if references:
        metadata["nvd_references"] = references

    if published:
        metadata["nvd_published"] = published

    # D-857: CISA KEV catalog flag
    metadata["kev_in_catalog"] = cve_id in _KEV_CACHE
    if metadata["kev_in_catalog"]:
        logger.info("CVE %s is in CISA KEV catalog (actively exploited)", cve_id)

    # Flag withdrawn/rejected CVEs so callers can suppress them
    if rejected:
        metadata["nvd_status"] = "REJECTED"
        logger.info("CVE %s has NVD status REJECTED -- consider suppressing", cve_id)

    finding["metadata"] = metadata


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
        cvss_version, severity, published, kev_in_catalog.
    """
    results: list[dict[str, Any]] = []
    timeout = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # D-857: Ensure KEV catalog is loaded
        await _ensure_kev_loaded(session)
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 2000),
        }
        data = await _get_with_retry(session, NVD_CVE_URL, params)

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

        # D-856: Use unified _extract_cvss which tries v4.0 first
        cvss_score, _, cvss_version = _extract_cvss(cve_item)

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
            "cvss_version": cvss_version,         # D-856: expose version
            "severity": severity,
            "published": published,
            "kev_in_catalog": cve_id in _KEV_CACHE,  # D-857
        })

    logger.info(
        "NVD search for '%s' returned %d results", keyword, len(results)
    )
    return results
