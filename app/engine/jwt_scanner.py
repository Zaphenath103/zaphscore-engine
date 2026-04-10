"""
ZSE JWT Security Scanner — EX-07 / CWE-287 / CWE-347
Detects JWT authentication failures: none-algorithm, no-verify, weak secrets,
missing expiry, and non-cryptographic token generation.
"""

from __future__ import annotations

import re
import logging
from pathlib import Path

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# 1. "none" algorithm accepted — allows signature bypass
_NONE_ALG = re.compile(
    r'algorithms\s*=\s*\[[^\]]*["\']none["\']',
    re.IGNORECASE,
)

# 2a. Flag any jwt.decode call — we then check for verify opt-outs
_JWT_DECODE = re.compile(r'jwt\.decode\s*\(')

# 2b. Explicit opt-out of verification in nearby context
_VERIFY_FALSE = re.compile(
    r'options\s*=\s*\{[^}]*["\']verify[\w_]*["\']\s*:\s*False',
    re.IGNORECASE,
)

# 3. jwt.encode with a short (< 16 char) inline string secret
_WEAK_SECRET = re.compile(
    r'jwt\.encode\s*\([^,]+,\s*["\']([^"\']{1,15})["\']',
)

# 4. jwt.encode call — check surrounding context for "exp"
_JWT_ENCODE = re.compile(r'jwt\.encode\s*\(')

# 5. Non-cryptographic random used for token/session generation
_INSECURE_RANDOM = re.compile(
    r'\brandom\.(choices|randint|randrange|sample|choice)\s*\(',
)
_TOKEN_CONTEXT = re.compile(
    r'(token|session|secret|key|nonce|salt|csrf)',
    re.IGNORECASE,
)


def _iter_py_files(repo_dir: str):
    """Yield all .py files under repo_dir, skipping .git."""
    root = Path(repo_dir)
    for p in root.rglob("*.py"):
        if ".git" not in p.parts:
            yield p


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def scan_jwt_issues(repo_dir: str) -> list[Finding]:
    """
    Walk all Python files in repo_dir and detect JWT security misconfigurations.

    Returns a list of Finding objects covering:
      - CWE-347: None algorithm accepted (signature bypass)
      - CWE-287: JWT decoded without verification
      - Weak JWT secret (< 16 chars, trivially brutable)
      - Missing exp claim in JWT payload (CWE-287)
      - Non-cryptographic random used for token generation (CWE-338)
    """
    findings: list[Finding] = []

    for py_file in _iter_py_files(repo_dir):
        lines = _read_lines(py_file)
        rel_path = str(py_file)

        for lineno, line in enumerate(lines, start=1):

            # ------------------------------------------------------------------
            # Check 1: "none" algorithm accepted — signature bypass
            # ------------------------------------------------------------------
            if _NONE_ALG.search(line):
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.critical,
                    title='JWT "none" algorithm accepted',
                    description=(
                        'The application accepts the "none" algorithm in jwt.decode(), '
                        "allowing an attacker to craft tokens without a valid signature. "
                        'Remove "none" from the algorithms list. (CWE-347)'
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-07/CWE-347/NONE-ALG",
                ))

            # ------------------------------------------------------------------
            # Check 2: JWT decoded with verification explicitly disabled
            # ------------------------------------------------------------------
            if _JWT_DECODE.search(line):
                window = "\n".join(lines[lineno - 1: lineno + 5])
                if _VERIFY_FALSE.search(window):
                    findings.append(Finding(
                        type=FindingType.sast,
                        severity=Severity.high,
                        title="JWT decoded with verification disabled",
                        description=(
                            "jwt.decode() is called with options that disable signature or "
                            "expiry verification (e.g. verify_exp=False). Forged or expired "
                            "tokens will be accepted. Remove the verification-disabling options. "
                            "(CWE-287)"
                        ),
                        file_path=rel_path,
                        line=lineno,
                        rule_id="EX-07/CWE-287/NO-VERIFY",
                    ))

            # ------------------------------------------------------------------
            # Check 3: Weak JWT secret (inline string < 16 chars)
            # ------------------------------------------------------------------
            m3 = _WEAK_SECRET.search(line)
            if m3:
                secret_len = len(m3.group(1))
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.high,
                    title=f"Weak JWT secret ({secret_len} chars)",
                    description=(
                        f"jwt.encode() uses a hardcoded secret of only {secret_len} characters. "
                        "Secrets shorter than 32 characters are trivially brutable via offline "
                        "dictionary attacks. Use a cryptographically random secret of at least "
                        "32 bytes loaded from an environment variable. (CWE-347)"
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-07/CWE-347/WEAK-SECRET",
                ))

            # ------------------------------------------------------------------
            # Check 4: jwt.encode without "exp" in payload
            # ------------------------------------------------------------------
            if _JWT_ENCODE.search(line):
                block = "\n".join(lines[max(0, lineno - 6): lineno + 6])
                if '"exp"' not in block and "'exp'" not in block:
                    findings.append(Finding(
                        type=FindingType.sast,
                        severity=Severity.medium,
                        title="JWT payload missing expiry (exp) claim",
                        description=(
                            "jwt.encode() is called without an 'exp' field in the payload. "
                            "Tokens without an expiry never become invalid, giving attackers "
                            "unlimited use of stolen tokens. Always include an expiry claim. "
                            "(CWE-287)"
                        ),
                        file_path=rel_path,
                        line=lineno,
                        rule_id="EX-07/CWE-287/NO-EXP",
                    ))

            # ------------------------------------------------------------------
            # Check 5: Non-cryptographic random used for token/session generation
            # ------------------------------------------------------------------
            m5 = _INSECURE_RANDOM.search(line)
            if m5:
                context_window = "\n".join(
                    lines[max(0, lineno - 4): lineno + 4]
                )
                if _TOKEN_CONTEXT.search(context_window):
                    findings.append(Finding(
                        type=FindingType.sast,
                        severity=Severity.medium,
                        title=f"Insecure random (random.{m5.group(1)}) used for token/session",
                        description=(
                            f"random.{m5.group(1)}() is not cryptographically secure and must "
                            "not be used to generate tokens, session IDs, or secrets. "
                            "Use secrets.token_hex() or secrets.token_urlsafe() instead. "
                            "(CWE-338)"
                        ),
                        file_path=rel_path,
                        line=lineno,
                        rule_id="EX-07/CWE-338/INSECURE-RANDOM",
                    ))

    logger.info("[jwt_scanner] %d JWT findings in %s", len(findings), repo_dir)
    return findings
