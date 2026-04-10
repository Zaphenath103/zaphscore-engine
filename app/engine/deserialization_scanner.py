"""
ZSE Deserialization Scanner — EX-08 / CWE-502
Detects unsafe deserialization patterns: pickle, yaml.load, marshal,
jsonpickle, and shelve with non-literal paths.
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

# 1. pickle.loads on a variable (not a string literal)
#    Argument does not start with a quote — catches pickle.loads(data), pickle.loads(request.body), etc.
_PICKLE_LOADS = re.compile(r'pickle\.loads\s*\(\s*(?!["\'])([^\)]+)\)')

# 2a. yaml.load without any Loader specified (bare call — uses default unsafe Loader)
_YAML_LOAD_BARE = re.compile(r'yaml\.load\s*\(\s*[^,\)]+\s*\)')

# 2b. yaml.load with an explicitly unsafe Loader
_YAML_LOAD_UNSAFE = re.compile(
    r'yaml\.load\s*\([^,]+,\s*Loader\s*=\s*yaml\.(Full|Base|Loader)\b',
)

# 3. marshal.loads — always dangerous with untrusted data
_MARSHAL_LOADS = re.compile(r'marshal\.loads\s*\(')

# 4. jsonpickle.decode — deserializes Python objects from JSON
_JSONPICKLE_DECODE = re.compile(r'jsonpickle\.decode\s*\(')

# 5. shelve.open where argument is a variable (not a string literal)
_SHELVE_OPEN = re.compile(r'shelve\.open\s*\(\s*(?!["\'])([^\)]+)\)')


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


def scan_deserialization(repo_dir: str) -> list[Finding]:
    """
    Walk all Python files in repo_dir and detect unsafe deserialization.

    Returns a list of Finding objects covering:
      - pickle.loads on a variable (CWE-502) — CRITICAL
      - yaml.load without SafeLoader (CWE-502) — HIGH
      - marshal.loads (CWE-502) — HIGH
      - jsonpickle.decode (CWE-502) — HIGH
      - shelve.open with variable path (CWE-502) — MEDIUM
    """
    findings: list[Finding] = []

    for py_file in _iter_py_files(repo_dir):
        lines = _read_lines(py_file)
        rel_path = str(py_file)

        for lineno, line in enumerate(lines, start=1):

            # ------------------------------------------------------------------
            # Check 1: pickle.loads on a variable
            # ------------------------------------------------------------------
            if _PICKLE_LOADS.search(line):
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.critical,
                    title="Unsafe pickle.loads on untrusted data",
                    description=(
                        "pickle.loads() deserializes arbitrary Python objects. When called "
                        "with attacker-controlled data this enables Remote Code Execution. "
                        "Never deserialize pickle data from untrusted sources. "
                        "Use JSON, MessagePack, or Protocol Buffers instead. (CWE-502)"
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-08/CWE-502/PICKLE-LOADS",
                ))

            # ------------------------------------------------------------------
            # Check 2a: yaml.load with no Loader (uses unsafe default)
            # ------------------------------------------------------------------
            if _YAML_LOAD_BARE.search(line):
                # Exclude safe usages: yaml.load(x, Loader=yaml.SafeLoader)
                if "SafeLoader" not in line and "safe_load" not in line:
                    findings.append(Finding(
                        type=FindingType.sast,
                        severity=Severity.high,
                        title="yaml.load() without SafeLoader",
                        description=(
                            "yaml.load() without an explicit Loader defaults to the full YAML "
                            "Loader which can deserialize arbitrary Python objects, enabling "
                            "code execution. Use yaml.safe_load() or "
                            "yaml.load(data, Loader=yaml.SafeLoader). (CWE-502)"
                        ),
                        file_path=rel_path,
                        line=lineno,
                        rule_id="EX-08/CWE-502/YAML-UNSAFE",
                    ))

            # ------------------------------------------------------------------
            # Check 2b: yaml.load with an explicitly unsafe Loader
            # ------------------------------------------------------------------
            elif _YAML_LOAD_UNSAFE.search(line):
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.high,
                    title="yaml.load() with unsafe Loader (FullLoader/BaseLoader/Loader)",
                    description=(
                        "yaml.load() is called with yaml.Loader, yaml.FullLoader, or "
                        "yaml.BaseLoader, all of which support Python object tags and can "
                        "execute arbitrary code on untrusted input. "
                        "Use yaml.safe_load() or Loader=yaml.SafeLoader. (CWE-502)"
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-08/CWE-502/YAML-UNSAFE-LOADER",
                ))

            # ------------------------------------------------------------------
            # Check 3: marshal.loads
            # ------------------------------------------------------------------
            if _MARSHAL_LOADS.search(line):
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.high,
                    title="Unsafe marshal.loads()",
                    description=(
                        "marshal.loads() deserializes Python bytecode objects. Maliciously "
                        "crafted marshal data can crash the interpreter or enable code "
                        "execution. Do not use marshal for untrusted data. (CWE-502)"
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-08/CWE-502/MARSHAL-LOADS",
                ))

            # ------------------------------------------------------------------
            # Check 4: jsonpickle.decode
            # ------------------------------------------------------------------
            if _JSONPICKLE_DECODE.search(line):
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.high,
                    title="Unsafe jsonpickle.decode()",
                    description=(
                        "jsonpickle.decode() reconstructs arbitrary Python objects from JSON, "
                        "including classes with __reduce__ hooks. Attacker-controlled input "
                        "can achieve Remote Code Execution. Use the standard json module "
                        "and validate schema explicitly. (CWE-502)"
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-08/CWE-502/JSONPICKLE-DECODE",
                ))

            # ------------------------------------------------------------------
            # Check 5: shelve.open with variable path
            # ------------------------------------------------------------------
            if _SHELVE_OPEN.search(line):
                findings.append(Finding(
                    type=FindingType.sast,
                    severity=Severity.medium,
                    title="shelve.open() with variable path",
                    description=(
                        "shelve.open() uses pickle internally. If the path argument is "
                        "user-controlled an attacker may read or overwrite arbitrary shelve "
                        "databases, enabling object injection or path traversal. "
                        "Validate and sanitize the path, or avoid shelve for untrusted inputs. "
                        "(CWE-502)"
                    ),
                    file_path=rel_path,
                    line=lineno,
                    rule_id="EX-08/CWE-502/SHELVE-VARIABLE-PATH",
                ))

    logger.info(
        "[deserialization_scanner] %d deserialization findings in %s",
        len(findings),
        repo_dir,
    )
    return findings
