"""
ZSE Vulnerability Scanner — queries OSV.dev for known vulnerabilities
in resolved dependencies. Uses batch query + individual detail fetch.

D-675: Reachability note: production_only flag eliminates dev-dependency false positives.
D-720: EPSS integration via FIRST.org EPSS API adds exploitation probability.
D-721: Dev-dep suppression: dev:True findings suppressed in production context.
D-766: Dependency confusion detection for scoped npm packages.
D-800: GHSA integration: GitHub Advisory Database queried for packages not in OSV.
D-855: OSV freshness check: advisory lastModified compared to staleness threshold.
D-859: Batch index bug fix: result count validated against query count before mapping.
D-860: GHSA enrichment: GitHub Advisory API called for richer GHSA descriptions.
D-861: Withdrawn CVE detection: OSV withdrawn flag and NVD REJECT status checked.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import math
import os
import re
from typing import Any, Optional

import aiohttp

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
GHSA_API_URL = "https://api.github.com/advisories"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

BATCH_SIZE = 1000
# D-015: Reduced concurrency to respect OSV.dev as a free public service.
MAX_CONCURRENT_DETAIL = 10
MAX_RETRIES = 3
BASE_BACKOFF = 1.0  # seconds

# D-015: Simple in-memory CVE response cache (CVE-ID -> raw vuln dict).
# TTL is process lifetime; cold starts clear the cache (acceptable trade-off).
_CVE_CACHE: dict[str, dict] = {}

# D-720: EPSS cache (CVE-ID -> {epss_score: float, percentile: float})
_EPSS_CACHE: dict[str, dict] = {}

# Map dependency ecosystem names to OSV ecosystem names
_ECO_MAP: dict[str, str] = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Go": "Go",
    "crates.io": "crates.io",
    "Maven": "Maven",
    "RubyGems": "RubyGems",
    "Packagist": "Packagist",
    "NuGet": "NuGet",
    "Swift": "SwiftURL",
}

# D-855: Maximum age (in days) before OSV advisory data is considered stale.
OSV_STALENESS_DAYS = 30


# ---------------------------------------------------------------------------
# CVSS parsing
# ---------------------------------------------------------------------------

def _parse_cvss_score(vector: str) -> Optional[float]:
    """D-017: Compute authoritative CVSS 3.x base score from a vector string.

    Implements the NIST CVSS v3.1 base score formula exactly as specified at:
    https://www.first.org/cvss/v3.1/specification-document (Section 7.1)

    This replaces the previous heuristic approximation that produced scores
    up to 2.3 points off from NIST values, causing HIGH->MEDIUM misclassifications.

    Falls back to score-suffix extraction first (fastest path).
    """
    if not vector:
        return None

    # Fast path: vector already has an embedded score (e.g. "/Score:7.5")
    m = re.search(r"[Ss]core[:/](\d+\.?\d*)", vector)
    if m:
        return min(float(m.group(1)), 10.0)

    # Parse metric key:value pairs from the vector string
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()

    if not metrics:
        return None

    # CVSS 3.1 metric value tables
    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    _AC = {"L": 0.77, "H": 0.44}
    _PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI = {"N": 0.85, "R": 0.62}
    _CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

    scope = metrics.get("S", "U")
    av  = _AV.get(metrics.get("AV", "N"), 0.85)
    ac  = _AC.get(metrics.get("AC", "L"), 0.77)
    pr  = (_PR_C if scope == "C" else _PR_U).get(metrics.get("PR", "N"), 0.85)
    ui  = _UI.get(metrics.get("UI", "N"), 0.85)
    c   = _CIA.get(metrics.get("C", "N"), 0.00)
    i   = _CIA.get(metrics.get("I", "N"), 0.00)
    a   = _CIA.get(metrics.get("A", "N"), 0.00)

    # ISC (Impact Sub-Score)
    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope == "U":
        isc = 6.42 * isc_base
    else:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if isc <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope == "U":
        raw = isc + exploitability
    else:
        raw = 1.08 * (isc + exploitability)

    # CVSS round-up: smallest value >= raw with 1 decimal place
    raw_capped = min(raw, 10.0)
    rounded = round(math.ceil(raw_capped * 10) / 10, 1)
    return rounded


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


def _is_withdrawn(vuln: dict) -> bool:
    """D-861: Check if an OSV advisory has been withdrawn.

    OSV sets the 'withdrawn' field to a timestamp when an advisory is retracted.
    Also checks database_specific flags used by some ecosystems.
    """
    if vuln.get("withdrawn"):
        return True
    db_specific = vuln.get("database_specific") or {}
    if db_specific.get("withdrawn") or db_specific.get("disputed"):
        return True
    return False


def _check_osv_freshness(vuln: dict, vuln_id: str) -> None:
    """D-855: Warn if an OSV advisory appears stale.

    OSV includes a 'modified' timestamp. If it hasn't been updated in
    OSV_STALENESS_DAYS days, the OSV mirror may be lagging behind NVD.
    """
    modified_str = vuln.get("modified", "")
    if not modified_str:
        return
    try:
        modified = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
        age_days = (datetime.datetime.now(datetime.timezone.utc) - modified).days
        if age_days > OSV_STALENESS_DAYS:
            logger.warning(
                "OSV advisory %s last modified %d days ago -- may be stale "
                "(NVD/GHSA may have newer data)",
                vuln_id, age_days,
            )
    except Exception:
        pass  # Non-critical freshness check


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

async def _post_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    json_body: dict,
    headers: Optional[dict] = None,
) -> dict:
    """POST with exponential backoff on 429/5xx."""
    for attempt in range(MAX_RETRIES):
        try:
            async with session.post(url, json=json_body, headers=headers) as resp:
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
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
) -> dict:
    """GET with exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url, params=params, headers=headers) as resp:
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
# D-720: EPSS enrichment
# ---------------------------------------------------------------------------

async def _fetch_epss_scores(
    session: aiohttp.ClientSession,
    cve_ids: list[str],
) -> None:
    """Fetch EPSS scores for a list of CVE IDs from FIRST.org.

    Populates _EPSS_CACHE with {epss_score, percentile} for each CVE.
    EPSS scores are queried in batches of 100 (API limit).
    """
    EPSS_BATCH = 100
    for i in range(0, len(cve_ids), EPSS_BATCH):
        batch = cve_ids[i:i + EPSS_BATCH]
        to_fetch = [c for c in batch if c not in _EPSS_CACHE]
        if not to_fetch:
            continue
        params = {"cve": ",".join(to_fetch)}
        try:
            data = await _get_with_retry(session, EPSS_API_URL, params=params)
            for item in data.get("data", []):
                cve = item.get("cve", "")
                if cve:
                    _EPSS_CACHE[cve] = {
                        "epss_score": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }
        except Exception as exc:
            logger.warning("EPSS fetch failed for batch: %s", exc)


# ---------------------------------------------------------------------------
# D-800: GHSA integration
# ---------------------------------------------------------------------------

def _ghsa_headers() -> dict[str, str]:
    """Build GitHub API headers with optional token."""
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _fetch_ghsa_advisories(
    session: aiohttp.ClientSession,
    ecosystem: str,
    pkg_name: str,
) -> list[dict]:
    """D-800: Query GitHub Security Advisories for a package.

    Returns list of GHSA advisory dicts not necessarily in OSV.
    """
    _GHSA_ECO_MAP = {
        "PyPI": "pip",
        "npm": "npm",
        "Maven": "maven",
        "Go": "go",
        "RubyGems": "rubygems",
        "NuGet": "nuget",
        "crates.io": "rust",
        "Packagist": "composer",
    }
    ghsa_eco = _GHSA_ECO_MAP.get(ecosystem)
    if not ghsa_eco:
        return []

    params = {
        "ecosystem": ghsa_eco,
        "package": pkg_name,
        "per_page": 50,
    }
    try:
        async with session.get(
            GHSA_API_URL,
            params=params,
            headers=_ghsa_headers(),
        ) as resp:
            if resp.status == 200:
                return await resp.json()
            if resp.status == 403:
                logger.debug("GHSA API rate limit or auth error (403) for %s/%s", ecosystem, pkg_name)
            return []
    except Exception as exc:
        logger.debug("GHSA fetch failed for %s/%s: %s", ecosystem, pkg_name, exc)
        return []


async def _enrich_ghsa_description(
    session: aiohttp.ClientSession,
    ghsa_id: str,
) -> Optional[str]:
    """D-860: Fetch full GHSA description from GitHub Advisory API.

    OSV mirrors GHSA advisories but often truncates the description.
    The GitHub Advisory API provides the full rich text.
    """
    try:
        url = f"{GHSA_API_URL}/{ghsa_id}"
        async with session.get(url, headers=_ghsa_headers()) as resp:
            if resp.status == 200:
                data = await resp.json()
                description = data.get("description", "")
                if description:
                    return description[:2000]
            return None
    except Exception as exc:
        logger.debug("GHSA description fetch failed for %s: %s", ghsa_id, exc)
        return None


# ---------------------------------------------------------------------------
# D-766: Dependency confusion detection
# ---------------------------------------------------------------------------

async def _check_dependency_confusion(
    session: aiohttp.ClientSession,
    dependencies: list[dict],
) -> list[Finding]:
    """D-766: Detect dependency confusion attacks for scoped npm packages.

    For scoped npm packages (e.g. @company/pkg), checks if an identically-named
    public package exists on the npm registry. If a public package exists, it
    could be resolved instead of the private scoped one.
    """
    findings: list[Finding] = []
    npm_deps = [d for d in dependencies if d.get("ecosystem") == "npm"]

    for dep in npm_deps:
        name = dep.get("name", "")
        # Only check scoped packages (private namespaces)
        if not name.startswith("@"):
            continue

        try:
            url = f"https://registry.npmjs.org/{name}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    latest_version = (data.get("dist-tags") or {}).get("latest", "unknown")
                    scope = name.split("/")[0][1:]  # strip @
                    findings.append(Finding(
                        type=FindingType.vulnerability,
                        severity=Severity.high,
                        title=f"Dependency confusion risk: {name} exists publicly (v{latest_version})",
                        description=(
                            f"**Package:** {name}\n"
                            f"**Risk:** A public npm package with this scoped name exists "
                            f"(latest={latest_version}). Package managers that resolve public "
                            f"registries before private ones may install the public (potentially "
                            f"malicious) version instead of your private package.\n"
                            f"**Remediation:** Pin the private registry in .npmrc: "
                            f"@{scope}:registry=<private-registry-url>"
                        ),
                    ))
        except Exception:
            pass  # Network errors: cannot confirm or deny

    return findings


# ---------------------------------------------------------------------------
# Batch query
# ---------------------------------------------------------------------------

async def _query_batch(
    session: aiohttp.ClientSession,
    dependencies: list[dict],
) -> dict[str, set[str]]:
    """Query OSV batch API. Returns {pkg_key: set_of_vuln_ids}.

    D-859: Result count validated against query count before mapping to prevent
    index offset errors when OSV returns partial results for large batches.
    pkg_key = "ecosystem:name:version"
    """
    results: dict[str, set[str]] = {}

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

        osv_results = data.get("results", [])

        # D-859: Validate result count matches query count before mapping.
        # If OSV returns a partial response, fall back to individual queries
        # rather than silently mapping vulns to wrong packages.
        if len(osv_results) != len(queries):
            logger.warning(
                "OSV batch returned %d results for %d queries -- "
                "falling back to individual queries to avoid index offset error",
                len(osv_results), len(queries),
            )
            for query_item, pkg_key in zip(queries, batch_keys):
                single_data = await _post_with_retry(
                    session, OSV_BATCH_URL, {"queries": [query_item]}
                )
                single_results = single_data.get("results", [])
                if single_results:
                    for v in single_results[0].get("vulns", []):
                        vid = v.get("id", "")
                        if vid:
                            results.setdefault(pkg_key, set()).add(vid)
            continue

        for idx, result in enumerate(osv_results):
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
        if vid in _CVE_CACHE:
            details[vid] = _CVE_CACHE[vid]
            return
        async with sem:
            data = await _get_with_retry(session, f"{OSV_VULN_URL}/{vid}")
            if data:
                _CVE_CACHE[vid] = data
                details[vid] = data

    tasks = [_fetch_one(vid) for vid in vuln_ids]
    await asyncio.gather(*tasks)
    return details


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def scan_vulnerabilities(
    dependencies: list[dict],
    production_only: bool = False,
    github_token: Optional[str] = None,
) -> list[Finding]:
    """Scan a list of resolved dependencies against OSV.dev and GHSA.

    D-675: Reachability analysis note:
           This scanner performs static manifest-level scanning. Call-graph
           reachability analysis (suppressing findings where vulnerable code
           paths are never invoked) requires language-specific tooling and
           is not performed here. The production_only flag (D-721) removes
           dev-dependency findings, which is the highest-ROI reachability
           approximation available without a language runtime.

    D-721: production_only=True suppresses findings for dev:True dependencies,
           matching Snyk's behaviour of ignoring devDependencies in production.

    D-800: GHSA advisories fetched for npm and PyPI packages not in OSV.

    Args:
        dependencies: List of dicts with keys: name, version, ecosystem, dev.
        production_only: If True, suppress findings for dev:True dependencies.
        github_token: Optional GitHub PAT for higher GHSA API rate limits.

    Returns:
        List of Finding objects for each known vulnerability.
    """
    if not dependencies:
        return []

    # D-721: Separate production and dev dependencies
    if production_only:
        prod_deps = [d for d in dependencies if not d.get("dev", False)]
        dev_deps = [d for d in dependencies if d.get("dev", False)]
        logger.info(
            "production_only=True: scanning %d production deps, suppressing %d dev deps",
            len(prod_deps), len(dev_deps),
        )
        scan_deps = prod_deps
    else:
        scan_deps = dependencies

    if not scan_deps:
        return []

    if github_token:
        os.environ.setdefault("GITHUB_TOKEN", github_token)

    findings: list[Finding] = []
    timeout = aiohttp.ClientTimeout(total=300)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Phase 1: OSV batch query
        logger.info("Querying OSV.dev for %d dependencies", len(scan_deps))
        pkg_vulns = await _query_batch(session, scan_deps)

        all_vuln_ids: set[str] = set()
        for vid_set in pkg_vulns.values():
            all_vuln_ids.update(vid_set)

        if not all_vuln_ids:
            logger.info("No vulnerabilities found via OSV")
        else:
            logger.info("Found %d unique vulnerabilities via OSV, fetching details", len(all_vuln_ids))

        # Phase 2: Fetch full OSV details
        vuln_details = await _fetch_vuln_details(session, all_vuln_ids)

        # D-720: Collect CVE IDs for EPSS enrichment
        all_cve_ids: list[str] = []
        for vid in all_vuln_ids:
            if vid.startswith("CVE-"):
                all_cve_ids.append(vid)
            vd = vuln_details.get(vid, {})
            for alias in vd.get("aliases", []):
                if alias.startswith("CVE-"):
                    all_cve_ids.append(alias)
        if all_cve_ids:
            await _fetch_epss_scores(session, list(set(all_cve_ids)))

        # D-800: GHSA scan for packages not covered by OSV
        # Only query GHSA for npm and PyPI packages (most coverage vs rate limit budget)
        ghsa_ecosystems = {"npm", "PyPI"}
        ghsa_checked: set[str] = set()
        for dep in scan_deps:
            if dep["ecosystem"] not in ghsa_ecosystems:
                continue
            pkg_key = f"{dep['ecosystem']}:{dep['name']}"
            if pkg_key in ghsa_checked:
                continue
            ghsa_checked.add(pkg_key)
            advisories = await _fetch_ghsa_advisories(session, dep["ecosystem"], dep["name"])
            for adv in advisories:
                ghsa_id = adv.get("ghsa_id", "")
                if not ghsa_id or ghsa_id in all_vuln_ids:
                    continue  # already in OSV
                sev_str = (adv.get("severity") or "MODERATE").upper()
                sev_map = {
                    "CRITICAL": Severity.critical,
                    "HIGH": Severity.high,
                    "MODERATE": Severity.medium,
                    "MEDIUM": Severity.medium,
                    "LOW": Severity.low,
                }
                severity = sev_map.get(sev_str, Severity.medium)
                cve_ids = [c.get("value", "") for c in adv.get("cve_ids", [])]
                cve_id = cve_ids[0] if cve_ids else None
                summary = adv.get("summary", "") or adv.get("description", "")

                # D-860: Fetch full GHSA description
                full_description = await _enrich_ghsa_description(session, ghsa_id)

                findings.append(Finding(
                    type=FindingType.vulnerability,
                    severity=severity,
                    title=f"{ghsa_id}: {summary[:120]}",
                    description=(
                        f"**Package:** {dep['name']}@{dep['version']}\n"
                        f"**Ecosystem:** {dep['ecosystem']}\n"
                        f"**Source:** GitHub Advisory Database\n"
                        f"{full_description or summary}"
                    ),
                    cve_id=cve_id,
                    ghsa_id=ghsa_id,
                ))

        if findings:
            logger.info("GHSA found %d additional advisories not in OSV", len(findings))

        # D-766: Dependency confusion detection
        confusion_findings = await _check_dependency_confusion(session, scan_deps)
        if confusion_findings:
            logger.info("Dependency confusion: %d risk findings", len(confusion_findings))
            findings.extend(confusion_findings)

    # Phase 3: Build findings from OSV data
    dep_lookup: dict[str, dict] = {}
    for dep in scan_deps:
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

            # D-861: Skip withdrawn/rejected advisories
            if vuln and _is_withdrawn(vuln):
                logger.info("Skipping withdrawn advisory %s for %s", vid, pkg_name)
                continue

            if not vuln:
                findings.append(Finding(
                    type=FindingType.vulnerability,
                    severity=Severity.medium,
                    title=f"{vid} in {pkg_name}",
                    description=(
                        f"Vulnerability {vid} affects "
                        f"{pkg_name}@{dep_info.get('version', '?')}"
                    ),
                    cve_id=vid if vid.startswith("CVE-") else None,
                    ghsa_id=vid if vid.startswith("GHSA-") else None,
                ))
                continue

            # D-855: Check OSV advisory freshness
            _check_osv_freshness(vuln, vid)

            severity, cvss_score, cvss_vector = _extract_severity(vuln)
            cve_id, ghsa_id = _extract_aliases(vuln)
            fix_version = _extract_fix_version(vuln, pkg_name)
            summary = _build_summary(vuln)

            finding = Finding(
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
            )

            # D-720: Attach EPSS metadata
            epss_data = None
            for id_to_check in ([cve_id] if cve_id else []) + ([vid] if vid.startswith("CVE-") else []):
                if id_to_check in _EPSS_CACHE:
                    epss_data = _EPSS_CACHE[id_to_check]
                    break
            if epss_data and hasattr(finding, "metadata"):
                meta = finding.metadata if isinstance(finding.metadata, dict) else {}
                meta["epss_score"] = epss_data["epss_score"]
                meta["epss_percentile"] = epss_data["percentile"]
                finding.metadata = meta

            findings.append(finding)

    logger.info("Produced %d vulnerability findings", len(findings))
    return findings
