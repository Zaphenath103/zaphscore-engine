"""
ZSE SSRF Scanner — EX-10 / CWE-918
Detects Server-Side Request Forgery patterns: HTTP calls with user-controlled
URLs in Python, JavaScript, TypeScript, and PHP files.
"""

from __future__ import annotations

import re
import logging
from pathlib import Path

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns — Python
# ---------------------------------------------------------------------------

# User-controlled URL sources embedded in the argument
_USER_INPUT_SOURCES = re.compile(
    r'(req\.|request\.|args\.get\s*\(|params\[|body\.|flask\.request|'
    r'request\.json|request\.form|request\.args|request\.data|'
    r'request\.query_string|request\.values)',
)

# Generic variable argument (single identifier — not a quoted string)
_VAR_ARG = re.compile(r'\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[\),]')

# Cloud metadata endpoint — always CRITICAL
_METADATA_IP = re.compile(r'169\.254\.169\.254')

# requests.*
_REQUESTS_GET  = re.compile(r'\brequests\.get\s*\(')
_REQUESTS_POST = re.compile(r'\brequests\.post\s*\(')
_REQUESTS_PUT  = re.compile(r'\brequests\.put\s*\(')
_REQUESTS_ANY  = re.compile(r'\brequests\.(get|post|put|delete|patch|head|request)\s*\(')

# httpx.*
_HTTPX_GET  = re.compile(r'\bhttpx\.get\s*\(')
_HTTPX_POST = re.compile(r'\bhttpx\.post\s*\(')
_HTTPX_ANY  = re.compile(r'\bhttpx\.(get|post|put|delete|patch|head|request)\s*\(')

# urllib
_URLLIB_URLOPEN = re.compile(r'\burllib\.request\.urlopen\s*\(')
_URLLIB2_OPEN   = re.compile(r'\burllib2\.urlopen\s*\(')

# aiohttp
_AIOHTTP = re.compile(r'\bsession\.(get|post|put|delete|patch|head)\s*\(')

# ---------------------------------------------------------------------------
# Compiled patterns — JavaScript / TypeScript
# ---------------------------------------------------------------------------

# fetch(variable) or axios.get(variable) / axios.post(variable)
_JS_FETCH = re.compile(r'\bfetch\s*\(\s*(?!["\`])([a-zA-Z_$][a-zA-Z0-9_.$]*)')
_JS_AXIOS = re.compile(r'\baxios\.(get|post|put|delete|patch)\s*\(\s*(?!["\`])([a-zA-Z_$][a-zA-Z0-9_.$]*)')
_JS_HTTP  = re.compile(r'\bhttp(s?)\.(get|request)\s*\(\s*(?!["\`])([a-zA-Z_$][a-zA-Z0-9_.$]*)')

# ---------------------------------------------------------------------------
# Compiled patterns — PHP
# ---------------------------------------------------------------------------

_PHP_CURL_SETOPT = re.compile(r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*(?!["\'])(\$\w+)')
_PHP_FILE_GET    = re.compile(r'file_get_contents\s*\(\s*(?!["\'])(\$\w+)')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PY_EXTENSIONS  = {".py"}
_JS_EXTENSIONS  = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_PHP_EXTENSIONS = {".php"}
_ALL_EXTENSIONS = _PY_EXTENSIONS | _JS_EXTENSIONS | _PHP_EXTENSIONS

_SSRF_DESCRIPTION = (
    "Server-Side Request Forgery — user-controlled URL fetched by server. "
    "Attacker can reach internal services including cloud metadata at "
    "169.254.169.254, internal databases, or localhost admin endpoints."
)
_SSRF_REMEDIATION = (
    "Validate URL against an allowlist of permitted domains before fetching. "
    "Reject requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)."
)


def _iter_files(repo_dir: str):
    root = Path(repo_dir)
    for p in root.rglob("*"):
        if ".git" not in p.parts and p.suffix.lower() in _ALL_EXTENSIONS:
            yield p


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _line_has_user_input(line: str) -> bool:
    return bool(_USER_INPUT_SOURCES.search(line))


def _line_has_var_arg(line: str) -> bool:
    return bool(_VAR_ARG.search(line))


def _make_ssrf_finding(
    rel_path: str,
    lineno: int,
    method: str,
    severity: Severity = Severity.high,
    extra_note: str = "",
) -> Finding:
    desc = _SSRF_DESCRIPTION
    if extra_note:
        desc += " " + extra_note
    return Finding(
        type=FindingType.sast,
        severity=severity,
        title=f"Potential SSRF via {method}",
        description=desc,
        file_path=rel_path,
        line=lineno,
        rule_id="EX-10/CWE-918/SSRF",
    )


# ---------------------------------------------------------------------------
# Python scanner
# ---------------------------------------------------------------------------

def _scan_python_file(lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []

    for lineno, line in enumerate(lines, start=1):

        # Always CRITICAL: any reference to cloud metadata IP
        if _METADATA_IP.search(line):
            findings.append(Finding(
                type=FindingType.sast,
                severity=Severity.critical,
                title="Hardcoded cloud metadata endpoint (SSRF/IMDS)",
                description=(
                    "The AWS/GCP/Azure instance metadata IP (169.254.169.254) is referenced "
                    "in code. If reachable via an SSRF vector, an attacker can retrieve "
                    "cloud credentials and IAM role tokens. Ensure no user input can reach "
                    "this endpoint and apply SSRF mitigations at the network level. (CWE-918)"
                ),
                file_path=rel_path,
                line=lineno,
                rule_id="EX-10/CWE-918/METADATA-IP",
            ))

        # requests.* with variable URL or user input in same line
        if _REQUESTS_ANY.search(line):
            if _line_has_user_input(line) or _line_has_var_arg(line):
                method = _REQUESTS_ANY.search(line).group(0).rstrip("(")
                findings.append(_make_ssrf_finding(rel_path, lineno, method))

        # httpx.* with variable URL or user input
        elif _HTTPX_ANY.search(line):
            if _line_has_user_input(line) or _line_has_var_arg(line):
                method = _HTTPX_ANY.search(line).group(0).rstrip("(")
                findings.append(_make_ssrf_finding(rel_path, lineno, method))

        # urllib.request.urlopen with variable
        elif _URLLIB_URLOPEN.search(line):
            if _line_has_user_input(line) or _line_has_var_arg(line):
                findings.append(_make_ssrf_finding(rel_path, lineno, "urllib.request.urlopen"))

        # urllib2.urlopen with variable
        elif _URLLIB2_OPEN.search(line):
            if _line_has_user_input(line) or _line_has_var_arg(line):
                findings.append(_make_ssrf_finding(rel_path, lineno, "urllib2.urlopen"))

        # aiohttp session calls with variable
        elif _AIOHTTP.search(line):
            if _line_has_user_input(line) or _line_has_var_arg(line):
                method = _AIOHTTP.search(line).group(0).rstrip("(")
                findings.append(_make_ssrf_finding(rel_path, lineno, f"aiohttp.{method}"))

    return findings


# ---------------------------------------------------------------------------
# JavaScript / TypeScript scanner
# ---------------------------------------------------------------------------

def _scan_js_file(lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []

    for lineno, line in enumerate(lines, start=1):

        if _METADATA_IP.search(line):
            findings.append(Finding(
                type=FindingType.sast,
                severity=Severity.critical,
                title="Hardcoded cloud metadata endpoint (SSRF/IMDS)",
                description=(
                    "AWS/GCP/Azure instance metadata IP (169.254.169.254) referenced. "
                    "An SSRF vulnerability could allow an attacker to harvest cloud credentials. "
                    "(CWE-918)"
                ),
                file_path=rel_path,
                line=lineno,
                rule_id="EX-10/CWE-918/METADATA-IP",
            ))

        if _JS_FETCH.search(line):
            findings.append(_make_ssrf_finding(rel_path, lineno, "fetch()"))

        elif _JS_AXIOS.search(line):
            m = _JS_AXIOS.search(line)
            findings.append(_make_ssrf_finding(rel_path, lineno, f"axios.{m.group(1)}()"))

        elif _JS_HTTP.search(line):
            findings.append(_make_ssrf_finding(rel_path, lineno, "http.request()"))

    return findings


# ---------------------------------------------------------------------------
# PHP scanner
# ---------------------------------------------------------------------------

def _scan_php_file(lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []

    for lineno, line in enumerate(lines, start=1):

        if _METADATA_IP.search(line):
            findings.append(Finding(
                type=FindingType.sast,
                severity=Severity.critical,
                title="Hardcoded cloud metadata endpoint (SSRF/IMDS)",
                description=(
                    "AWS/GCP/Azure instance metadata IP (169.254.169.254) referenced in PHP. "
                    "(CWE-918)"
                ),
                file_path=rel_path,
                line=lineno,
                rule_id="EX-10/CWE-918/METADATA-IP",
            ))

        if _PHP_CURL_SETOPT.search(line):
            findings.append(_make_ssrf_finding(rel_path, lineno, "curl_setopt(CURLOPT_URL)"))

        elif _PHP_FILE_GET.search(line):
            findings.append(_make_ssrf_finding(rel_path, lineno, "file_get_contents()"))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_ssrf(repo_dir: str) -> list[Finding]:
    """
    Walk all .py, .js, .ts, .php (and variants) files in repo_dir and detect
    potential SSRF sinks where user-controlled data reaches an HTTP call.

    Returns a list of Finding objects (HIGH by default, CRITICAL for metadata IP).
    Remediation: validate URL against an allowlist of permitted domains.
    """
    findings: list[Finding] = []

    for src_file in _iter_files(repo_dir):
        lines = _read_lines(src_file)
        rel_path = str(src_file)
        ext = src_file.suffix.lower()

        if ext in _PY_EXTENSIONS:
            findings.extend(_scan_python_file(lines, rel_path))
        elif ext in _JS_EXTENSIONS:
            findings.extend(_scan_js_file(lines, rel_path))
        elif ext in _PHP_EXTENSIONS:
            findings.extend(_scan_php_file(lines, rel_path))

    logger.info("[ssrf_scanner] %d SSRF findings in %s", len(findings), repo_dir)
    return findings
