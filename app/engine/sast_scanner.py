"""
ZSE SAST Scanner — Semgrep integration for static analysis security testing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Optional

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

SEMGREP_TIMEOUT = 300  # seconds

# ---------------------------------------------------------------------------
# D-677: Extended semgrep rulesets beyond --config auto
# ---------------------------------------------------------------------------

EXTENDED_SEMGREP_RULESETS: list[str] = [
    "p/ci",
    "p/security-audit",
    "p/secrets",
    "p/owasp-top-ten",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/java",
    "p/golang",
    "p/ruby",
    "p/php",
    "p/csharp",
    "p/docker",
    "p/terraform",
    "p/kubernetes",
    "p/sql-injection",
    "p/xss",
    "p/command-injection",
    "p/insecure-transport",
    "p/jwt",
    "p/react",
    "p/flask",
    "p/django",
    "p/expressjs",
    "p/spring",
]


def get_semgrep_args(extended: bool = False) -> list[str]:
    args: list[str] = ["--config", "auto"]
    if extended:
        for ruleset in EXTENDED_SEMGREP_RULESETS:
            args += ["--config", ruleset]
    return args


# ---------------------------------------------------------------------------
# D-723: Community ruleset registry with language targeting and metadata
# ---------------------------------------------------------------------------

SEMGREP_COMMUNITY_RULESETS: list[str] = [
    "p/python", "p/javascript", "p/typescript", "p/java", "p/go",
    "p/ruby", "p/php", "p/csharp", "p/kotlin", "p/swift",
    "p/ci", "p/owasp-top-ten", "p/security-audit", "p/secrets",
    "p/supply-chain", "p/react", "p/nodejs", "p/docker", "p/terraform",
]

RULESET_METADATA: dict[str, dict] = {
    "p/python":         {"estimated_rules": 250, "category": "language"},
    "p/javascript":     {"estimated_rules": 200, "category": "language"},
    "p/typescript":     {"estimated_rules": 180, "category": "language"},
    "p/java":           {"estimated_rules": 220, "category": "language"},
    "p/go":             {"estimated_rules": 150, "category": "language"},
    "p/ruby":           {"estimated_rules": 100, "category": "language"},
    "p/php":            {"estimated_rules": 120, "category": "language"},
    "p/csharp":         {"estimated_rules": 130, "category": "language"},
    "p/kotlin":         {"estimated_rules": 90,  "category": "language"},
    "p/swift":          {"estimated_rules": 80,  "category": "language"},
    "p/ci":             {"estimated_rules": 60,  "category": "devops"},
    "p/owasp-top-ten":  {"estimated_rules": 200, "category": "compliance"},
    "p/security-audit": {"estimated_rules": 300, "category": "audit"},
    "p/secrets":        {"estimated_rules": 150, "category": "secrets"},
    "p/supply-chain":   {"estimated_rules": 100, "category": "supply-chain"},
    "p/react":          {"estimated_rules": 80,  "category": "framework"},
    "p/nodejs":         {"estimated_rules": 100, "category": "framework"},
    "p/docker":         {"estimated_rules": 70,  "category": "iac"},
    "p/terraform":      {"estimated_rules": 120, "category": "iac"},
}

TOTAL_ESTIMATED_RULES: int = sum(m["estimated_rules"] for m in RULESET_METADATA.values())

_LANGUAGE_RULESET_MAP: dict[str, list[str]] = {
    "python":     ["p/python", "p/django", "p/flask"],
    "javascript": ["p/javascript", "p/react", "p/nodejs", "p/expressjs"],
    "typescript": ["p/typescript", "p/react", "p/nodejs"],
    "java":       ["p/java", "p/spring"],
    "go":         ["p/go"],
    "ruby":       ["p/ruby"],
    "php":        ["p/php"],
    "csharp":     ["p/csharp"],
    "kotlin":     ["p/kotlin"],
    "swift":      ["p/swift"],
}

_UNIVERSAL_RULESETS: list[str] = [
    "p/owasp-top-ten", "p/security-audit", "p/secrets", "p/supply-chain",
]


def get_language_rulesets(language: str) -> list[str]:
    """Return the recommended Semgrep rulesets for a given language.

    Combines language-specific rulesets with universal security rulesets.

    Args:
        language: Programming language name (e.g. 'python', 'javascript').

    Returns:
        Deduplicated list of Semgrep ruleset config strings.
    """
    lang = language.lower()
    lang_specific = _LANGUAGE_RULESET_MAP.get(lang, [])
    combined = lang_specific + [r for r in _UNIVERSAL_RULESETS if r not in lang_specific]
    return combined


# ---------------------------------------------------------------------------
# D-725: Taint analysis -- source/sink rules for data-flow vulnerability detection
# ---------------------------------------------------------------------------

TAINT_RULE_SOURCES: list[dict] = [
    {"pattern": "request.args.get(...)", "language": "python"},
    {"pattern": "request.form.get(...)", "language": "python"},
    {"pattern": "request.json", "language": "python"},
    {"pattern": "os.environ.get(...)", "language": "python"},
    {"pattern": "sys.argv[...]", "language": "python"},
    {"pattern": "req.body", "language": "javascript"},
    {"pattern": "req.query[...]", "language": "javascript"},
    {"pattern": "req.params[...]", "language": "javascript"},
    {"pattern": "process.env[...]", "language": "javascript"},
    {"pattern": "request.getParameter(...)", "language": "java"},
    {"pattern": "request.getHeader(...)", "language": "java"},
    {"pattern": "r.URL.Query().Get(...)", "language": "go"},
    {"pattern": "r.FormValue(...)", "language": "go"},
]

TAINT_RULE_SINKS: list[dict] = [
    {"pattern": "subprocess.run(...)", "language": "python"},
    {"pattern": "subprocess.Popen(...)", "language": "python"},
    {"pattern": "os.system(...)", "language": "python"},
    {"pattern": "eval(...)", "language": "python"},
    {"pattern": "exec(...)", "language": "python"},
    {"pattern": "cursor.execute(...)", "language": "python"},
    {"pattern": "eval(...)", "language": "javascript"},
    {"pattern": "exec(...)", "language": "javascript"},
    {"pattern": "child_process.exec(...)", "language": "javascript"},
    {"pattern": "dangerouslySetInnerHTML", "language": "javascript"},
    {"pattern": "Runtime.getRuntime().exec(...)", "language": "java"},
    {"pattern": "Statement.executeQuery(...)", "language": "java"},
    {"pattern": "exec.Command(...)", "language": "go"},
    {"pattern": "db.QueryRow(...)", "language": "go"},
]


def build_taint_rule(source: dict, sink: dict, language: str) -> dict:
    """Build a Semgrep taint-mode rule dict for a source/sink pair.

    Args:
        source: Dict with 'pattern' key for the taint source.
        sink: Dict with 'pattern' key for the taint sink.
        language: Target programming language.

    Returns:
        Semgrep rule dict in taint mode format.
    """
    import hashlib
    rule_hash = hashlib.md5(
        "{}|{}|{}".format(source["pattern"], sink["pattern"], language).encode()
    ).hexdigest()[:8]
    return {
        "id": "zse-taint-{}-{}".format(language, rule_hash),
        "mode": "taint",
        "languages": [language],
        "severity": "WARNING",
        "message": "Tainted data from user input flows to sensitive sink: {}.".format(sink["pattern"]),
        "pattern-sources": [{"pattern": source["pattern"]}],
        "pattern-sinks": [{"pattern": sink["pattern"]}],
        "metadata": {
            "category": "security",
            "cwe": "CWE-89",
            "confidence": "medium",
        },
    }


def _build_taint_rules_for_language(language: str) -> list[dict]:
    """Build all taint rules for a given language from the source/sink lists."""
    lang_sources = [s for s in TAINT_RULE_SOURCES if s.get("language") == language]
    lang_sinks = [s for s in TAINT_RULE_SINKS if s.get("language") == language]
    rules = []
    for source in lang_sources:
        for sink in lang_sinks:
            rules.append(build_taint_rule(source, sink, language))
    return rules


def _rules_to_yaml(rules: list[dict]) -> str:
    """Serialize a list of rule dicts to Semgrep YAML format."""
    import yaml  # type: ignore
    return yaml.dump({"rules": rules}, default_flow_style=False, allow_unicode=True)


def run_taint_analysis(repo_path: str, language: str) -> list[dict]:
    """Run Semgrep taint analysis for the given language on a repository.

    Writes a temporary YAML config with generated taint rules and invokes
    semgrep in subprocess mode. Returns raw finding dicts.

    Args:
        repo_path: Absolute path to the repository to scan.
        language: Language to generate taint rules for.

    Returns:
        List of raw finding dicts from semgrep JSON output.
        Returns empty list if semgrep unavailable or no rules generated.
    """
    import subprocess
    import tempfile
    import os

    if not shutil.which("semgrep"):
        logger.warning("Semgrep not installed -- taint analysis skipped.")
        return []

    rules = _build_taint_rules_for_language(language)
    if not rules:
        logger.info("No taint rules available for language: %s", language)
        return []

    try:
        yaml_content = _rules_to_yaml(rules)
    except Exception:
        # yaml not available -- serialize manually
        lines = ["rules:"]
        for rule in rules:
            lines.append("  - id: {}".format(rule["id"]))
            lines.append("    mode: taint")
            lines.append("    severity: {}".format(rule.get("severity", "WARNING")))
            lines.append("    languages: [{}]".format(", ".join(rule.get("languages", [language]))))
            lines.append("    message: '{}'".format(rule.get("message", "").replace("'", "''")))
            srcs = rule.get("pattern-sources", [])
            if srcs:
                lines.append("    pattern-sources:")
                for s in srcs:
                    lines.append("      - pattern: '{}'".format(s.get("pattern", "").replace("'", "''")))
            sinks = rule.get("pattern-sinks", [])
            if sinks:
                lines.append("    pattern-sinks:")
                for s in sinks:
                    lines.append("      - pattern: '{}'".format(s.get("pattern", "").replace("'", "''")))
        yaml_content = "\n".join(lines) + "\n"

    findings = []
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", prefix="zse_taint_", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(yaml_content)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", tmp_path, "--json", "--quiet", repo_path],
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT,
        )
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
            except json.JSONDecodeError:
                logger.warning("Taint analysis produced non-JSON output")
    except subprocess.TimeoutExpired:
        logger.error("Taint analysis timed out for %s", repo_path)
    except Exception as exc:
        logger.error("Taint analysis failed: %s", exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    logger.info("Taint analysis (%s) on %s: %d findings", language, repo_path, len(findings))
    return findings


# Semgrep severity → ZSE severity
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.high,
    "WARNING": Severity.medium,
    "INFO": Severity.low,
}


def _clean_check_id(check_id: str) -> str:
    """Clean semgrep check_id into a readable title.

    e.g. 'python.lang.security.audit.exec-detected' → 'Exec Detected'
    """
    # Take the last segment after the last dot
    parts = check_id.rsplit(".", 1)
    last = parts[-1] if parts else check_id
    # Convert kebab-case / snake_case to title case
    return last.replace("-", " ").replace("_", " ").title()


async def scan_sast(repo_dir: str) -> list[Finding]:
    """Run Semgrep SAST scan on the repository.

    Args:
        repo_dir: Absolute path to the cloned repository.

    Returns:
        List of Finding objects from static analysis.
        Returns empty list if semgrep is not installed.
    """
    # Check if semgrep is available
    if not shutil.which("semgrep"):
        logger.warning(
            "Semgrep is not installed — SAST scan skipped. "
            "Install with: pip install semgrep"
        )
        return []

    findings: list[Finding] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=SEMGREP_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.error("Semgrep timed out after %ds for %s", SEMGREP_TIMEOUT, repo_dir)
            return []

        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        if proc.returncode not in (0, 1):
            # returncode 1 can mean "findings found" in some semgrep versions
            logger.warning("Semgrep exited with code %d: %s", proc.returncode, stderr_text[:300])

        # Parse JSON output
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        if not stdout_text.strip():
            logger.info("Semgrep produced no output for %s", repo_dir)
            return []

        try:
            data = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse semgrep JSON output: %s", exc)
            return []

        results = data.get("results", [])
        logger.info("Semgrep found %d results in %s", len(results), repo_dir)

        for result in results:
            check_id = result.get("check_id", "unknown")
            message = result.get("extra", {}).get("message", "")
            severity_str = result.get("extra", {}).get("severity", "WARNING")
            path = result.get("path", "")
            start_line = result.get("start", {}).get("line")

            # Map severity
            severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.medium)

            # Make path relative to repo_dir
            if path.startswith(repo_dir):
                path = path[len(repo_dir):].lstrip("/\\")

            findings.append(Finding(
                type=FindingType.sast,
                severity=severity,
                title=_clean_check_id(check_id),
                description=message[:1000] if message else f"Semgrep rule: {check_id}",
                file_path=path or None,
                line=start_line,
                rule_id=check_id,
            ))

    except FileNotFoundError:
        logger.warning("Semgrep binary not found — SAST scan skipped")
    except Exception as exc:
        logger.error("SAST scan failed: %s", exc, exc_info=True)

    return findings

# D-723: Pinned Semgrep community registry rulesets
_SEMGREP_RULESETS = [
    "p/security-audit",
    "p/secrets",
    "p/owasp-top-ten",
    "p/ci",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/golang",
    "p/java",
    "p/ruby",
    "p/php",
]

# D-726: Shannon entropy for secret detection
import math as _math
import collections as _collections


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = _collections.Counter(data)
    length = len(data)
    return -sum((c / length) * _math.log2(c / length) for c in counts.values())


def scan_for_high_entropy_strings(
    repo_dir: str,
    min_length: int = 20,
    entropy_threshold: float = 4.5,
) -> list:
    import os as _os, re as _re
    _TOKEN_RE = _re.compile(r"[A-Za-z0-9+/]{20,}|[A-Za-z0-9_-]{20,}")
    skip_exts = {".png",".jpg",".jpeg",".gif",".ico",".pdf",".woff",".ttf",".eot",".svg",".mp4"}
    skip_dirs = {"node_modules",".git","vendor","__pycache__",".venv","dist","build"}
    findings = []
    for dirpath, dirnames, filenames in _os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            ext = _os.path.splitext(fname)[1].lower()
            if ext in skip_exts:
                continue
            fpath = _os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    for line_no, line in enumerate(fh, 1):
                        for token in _TOKEN_RE.findall(line):
                            if len(token) >= min_length:
                                entropy = _shannon_entropy(token)
                                if entropy >= entropy_threshold:
                                    rel_path = _os.path.relpath(fpath, repo_dir)
                                    findings.append({
                                        "type": "sast",
                                        "severity": "high",
                                        "title": f"High-entropy string (entropy={entropy:.2f})",
                                        "description": (
                                            f"A high-entropy string ({len(token)} chars, entropy={entropy:.2f}) was found. "
                                            f"This may be an embedded secret. "
                                            f"File: {rel_path}:{line_no}"
                                        ),
                                        "file_path": rel_path,
                                        "line": line_no,
                                    })
            except Exception:
                pass
    return findings