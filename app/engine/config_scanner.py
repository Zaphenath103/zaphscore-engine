"""
Config Scanner -- detects security misconfigurations in application config files.
UFC Fight 1 blind spot: ZaphScore missed EX-05/CWE-16 (Security Misconfiguration).

OWASP Top 10 2024: A05 - Security Misconfiguration
CWE: CWE-16 (Configuration)
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config file selection patterns
# ---------------------------------------------------------------------------
_CONFIG_FILENAMES = {
    "settings.py", "config.py", "app.py", "application.py",
    "configuration.py", "conf.py", "wsgi.py", "asgi.py", "manage.py",
}

_CONFIG_SUFFIXES = {
    ".cfg", ".ini", ".env", ".conf", ".config",
    ".toml", ".yaml", ".yml", ".properties",
}

_CONFIG_PREFIXES = {".env"}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", "migrations", ".tox", "site-packages",
    "test", "tests", "spec", "specs",
}


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

@dataclass
class ConfigRule:
    """A single misconfiguration detection rule."""
    pattern: re.Pattern
    severity: Severity
    title: str
    description: str
    rule_id: str
    exclude_pattern: Optional[re.Pattern] = None


def _build_rules():
    return [
        # DEBUG mode
        ConfigRule(
            pattern=re.compile(r"\bDEBUG\s*=\s*True\b", re.IGNORECASE),
            severity=Severity.high,
            title="Debug mode enabled in production config",
            description=(
                "DEBUG = True exposes detailed tracebacks, environment variables, "
                "and internal server paths to anyone who triggers an error. "
                "Set DEBUG = False in production and use a logging framework "
                "to capture errors server-side. CWE-16 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-001",
        ),
        # Insecure / default SECRET_KEY
        ConfigRule(
            pattern=re.compile(
                r"SECRET_KEY\s*=\s*[\x22\x27](?:django-insecure[^\x22\x27]*|changeme[^\x22\x27]*|"
                r"secret[^\x22\x27]*|your[-_]secret[^\x22\x27]*|placeholder[^\x22\x27]*|"
                r"replace[-_]me[^\x22\x27]*|(?P<short>.{0,19}))[\x22\x27]",
                re.IGNORECASE,
            ),
            severity=Severity.high,
            title="Insecure or default secret key",
            description=(
                "The SECRET_KEY value is a Django insecure placeholder, a well-known "
                "default, or fewer than 20 characters. An attacker who knows the secret "
                "key can forge session cookies and signed data. Generate a strong key: "
                "python -c \"import secrets; print(secrets.token_hex(50))\" "
                "and store it in an environment variable. CWE-321 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-002",
        ),
        # ALLOWED_HOSTS wildcard
        ConfigRule(
            pattern=re.compile(r"ALLOWED_HOSTS\s*=\s*\[.*[\x22\x27]?\*[\x22\x27]?.*\]", re.IGNORECASE),
            severity=Severity.medium,
            title="All hosts allowed (ALLOWED_HOSTS = ['*'])",
            description=(
                "Setting ALLOWED_HOSTS = ['*'] disables Django's Host header validation, "
                "enabling Host header injection attacks used for cache poisoning and "
                "password-reset link hijacking. List only the domains your app serves. "
                "CWE-16 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-003",
        ),
        # CORS -- all origins
        ConfigRule(
            pattern=re.compile(
                r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True|"
                r"allow_origins\s*=\s*\[.*[\x22\x27]?\*[\x22\x27]?.*\]|"
                r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
                re.IGNORECASE,
            ),
            severity=Severity.high,
            title="CORS allows all origins",
            description=(
                "Allowing all CORS origins (*) lets any website make credentialed "
                "cross-origin requests to your API, bypassing the browser same-origin "
                "policy. Restrict allow_origins to your known frontend domains. "
                "CWE-942 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-004",
        ),
        # Default / weak credentials
        ConfigRule(
            pattern=re.compile(
                r"(?:PASSWORD|PASSWD|DB_PASS|DATABASE_PASSWORD|PGPASSWORD|MYSQL_PASSWORD|"
                r"DB_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD)\s*[=:]\s*"
                r"[\x22\x27]?(?:postgres|admin|password|1234|12345|root|test|changeme|"
                r"secret|letmein|qwerty|abc123|welcome)[\x22\x27]?",
                re.IGNORECASE,
            ),
            severity=Severity.high,
            title="Default or weak credentials in config",
            description=(
                "A well-known default password is present in the config file. "
                "Default credentials are the first thing attackers try. "
                "Use strong, randomly generated passwords stored in environment "
                "variables or a secrets manager. Never commit credentials to source "
                "control. CWE-798 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-005",
        ),
        # showExceptions / displayErrors
        ConfigRule(
            pattern=re.compile(
                r"showExceptions\s*[=:]\s*true|"
                r"displayErrors\s*[=:]\s*true|"
                r"PROPAGATE_EXCEPTIONS\s*=\s*True",
                re.IGNORECASE,
            ),
            severity=Severity.medium,
            title="Error details exposed to clients",
            description=(
                "Enabling exception/error detail display sends full stack traces to "
                "the HTTP response body, leaking internal paths, framework versions, "
                "and code logic. Disable in production and log errors server-side. "
                "CWE-209 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-006",
        ),
        # TLS verification disabled
        ConfigRule(
            pattern=re.compile(
                r"verify\s*=\s*False|"
                r"ssl_verify\s*=\s*False|"
                r"SSL_VERIFY\s*=\s*False|"
                r"VERIFY_SSL\s*=\s*False|"
                r"tls_verify\s*=\s*False|"
                r"insecure\s*=\s*True",
                re.IGNORECASE,
            ),
            severity=Severity.high,
            title="TLS/SSL verification disabled",
            description=(
                "Disabling TLS certificate verification allows man-in-the-middle "
                "attacks where an attacker can intercept and modify traffic in transit. "
                "Never set verify=False in production. Fix the certificate chain instead. "
                "CWE-295 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-007",
        ),
        # Debug logging in production
        ConfigRule(
            pattern=re.compile(
                r"LOG_LEVEL\s*=\s*[\x22\x27]?DEBUG[\x22\x27]?|logging\.DEBUG\b",
                re.IGNORECASE,
            ),
            severity=Severity.low,
            title="Debug logging level in production config",
            description=(
                "LOG_LEVEL = DEBUG emits verbose log entries including potentially "
                "sensitive data (SQL queries, request bodies, tokens) that may be "
                "captured in log aggregation systems. Use INFO or WARNING in production. "
                "CWE-532 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-008",
        ),
        # Hardcoded API keys / tokens
        ConfigRule(
            pattern=re.compile(
                r"(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|CLIENT_SECRET)\s*[=:]\s*"
                r"[\x22\x27][A-Za-z0-9+/\-_]{16,}[\x22\x27]",
                re.IGNORECASE,
            ),
            severity=Severity.high,
            title="Hardcoded API key or token in config",
            description=(
                "A hardcoded API key, token, or secret is present in a configuration file. "
                "Credentials committed to source control are visible to all contributors "
                "and can be harvested by automated scanners. Move secrets to environment "
                "variables or a secrets manager. CWE-798 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-009",
        ),
        # CSRF protection disabled
        ConfigRule(
            pattern=re.compile(
                r"WTF_CSRF_ENABLED\s*=\s*False|"
                r"CSRF_ENABLED\s*=\s*False|"
                r"csrf_protect\s*=\s*False",
                re.IGNORECASE,
            ),
            severity=Severity.high,
            title="CSRF protection disabled",
            description=(
                "CSRF protection is explicitly disabled. This allows malicious websites "
                "to submit authenticated requests on behalf of a logged-in user. "
                "Re-enable CSRF protection for all state-changing endpoints. "
                "CWE-352 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-010",
        ),
        # Insecure session cookies
        ConfigRule(
            pattern=re.compile(
                r"SESSION_COOKIE_SECURE\s*=\s*False|"
                r"SESSION_COOKIE_HTTPONLY\s*=\s*False|"
                r"CSRF_COOKIE_SECURE\s*=\s*False",
                re.IGNORECASE,
            ),
            severity=Severity.medium,
            title="Insecure session/CSRF cookie settings",
            description=(
                "Session or CSRF cookies are configured without Secure or HttpOnly flags. "
                "Without Secure, cookies are sent over plain HTTP. Without HttpOnly, "
                "JavaScript can read cookie values (XSS escalation). Set "
                "SESSION_COOKIE_SECURE = True and SESSION_COOKIE_HTTPONLY = True in "
                "production. CWE-614 / OWASP A05:2024."
            ),
            rule_id="ZSE-CFG-011",
        ),
    ]


_RULES = _build_rules()


# ---------------------------------------------------------------------------
# File selection helpers
# ---------------------------------------------------------------------------

def _is_config_file(filename: str) -> bool:
    """Return True if the filename matches a known config file pattern."""
    lower = filename.lower()
    if lower in _CONFIG_FILENAMES:
        return True
    for suffix in _CONFIG_SUFFIXES:
        if lower.endswith(suffix):
            return True
    for prefix in _CONFIG_PREFIXES:
        if lower.startswith(prefix):
            return True
    return False


def _is_comment_line(line: str) -> bool:
    """Return True if the line is a pure comment."""
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_config_files(repo_dir: str) -> list:
    """Scan all config files in repo_dir for security misconfigurations.

    Walks the repository, selects files matching config naming patterns,
    then scans each line against detection rules.

    Args:
        repo_dir: Absolute path to the cloned repository root.

    Returns:
        List of Finding objects, one per misconfiguration detected.
    """
    findings = []
    if not Path(repo_dir).is_dir():
        logger.warning("config_scanner: repo_dir does not exist: %s", repo_dir)
        return findings

    scanned_files = 0
    for dirpath, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            if not _is_config_file(filename):
                continue
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, repo_dir)
            scanned_files += 1
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError as exc:
                logger.debug("config_scanner: cannot read %s: %s", full_path, exc)
                continue

            seen: set = set()
            for line_no, raw_line in enumerate(lines, start=1):
                if _is_comment_line(raw_line):
                    continue
                for rule in _RULES:
                    if rule.pattern.search(raw_line):
                        key = (rule.rule_id, line_no)
                        if key in seen:
                            continue
                        seen.add(key)
                        if rule.exclude_pattern and rule.exclude_pattern.search(raw_line):
                            continue
                        findings.append(Finding(
                            type=FindingType.sast,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            file_path=rel_path,
                            line=line_no,
                            rule_id=rule.rule_id,
                        ))

    logger.info(
        "config_scanner: scanned %d config files, found %d findings",
        scanned_files, len(findings),
    )
    return findings
