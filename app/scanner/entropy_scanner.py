"""
ZSE Entropy Scanner -- D-726: Shannon entropy analysis for secret detection.
"""
from __future__ import annotations
import logging, math, os, re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

HIGH_ENTROPY_THRESHOLD: float = 4.5
MIN_SECRET_LENGTH: int = 20
MAX_SECRET_LENGTH: int = 2048

_SKIP_EXTENSIONS = frozenset({
    ".png",".jpg",".jpeg",".gif",".ico",".svg",".webp",
    ".mp3",".mp4",".wav",".zip",".tar",".gz",".bz2",".7z",".rar",
    ".pdf",".docx",".xlsx",".pyc",".pyo",".class",".so",".dll",".exe",
    ".woff",".woff2",".ttf",".lock",
})
_SKIP_DIRS = frozenset({".git","node_modules","__pycache__","venv",".venv","vendor",".tox","dist","build"})
_BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEX_CHARS = "0123456789abcdefABCDEF"
_PATTERNS = [
    re.compile(r'"([A-Za-z0-9+/=_\-.~]{20,})"'),
    re.compile(r"'([A-Za-z0-9+/=_\-.~]{20,})'"),
    re.compile(r'(?:=|:\s*)([A-Za-z0-9+/=_\-.~]{20,})(?:\s|$|[,}\]"\'])'),
    re.compile(r'(?:key|token|secret|password|api_key|auth|credential)[_\s]*[=:]\s*([A-Za-z0-9+/=_\-.~]{20,})', re.IGNORECASE),
]

def calculate_entropy(s: str) -> float:
    if not s or len(s) == 1:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt/n)*math.log2(cnt/n) for cnt in freq.values())

def _extract_candidates(content: str) -> list:
    seen = set()
    result = []
    for pat in _PATTERNS:
        for m in pat.finditer(content):
            c = m.group(1)
            if MIN_SECRET_LENGTH <= len(c) <= MAX_SECRET_LENGTH and c not in seen:
                seen.add(c)
                result.append(c)
    return result

@dataclass
class EntropyFinding:
    file_path: str
    line_number: Optional[int]
    matched_string: str
    entropy: float
    char_set: str
    context: str

    @property
    def redacted_display(self):
        s = self.matched_string
        return "{}...{}".format(s[:4], s[-4:]) if len(s) > 8 else "[REDACTED]"

def scan_for_high_entropy_strings(file_path: str) -> list:
    path = Path(file_path)
    if path.suffix.lower() in _SKIP_EXTENSIONS:
        return []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if not content.strip():
        return []
    lines = content.splitlines()
    line_map = {}
    for ln, line in enumerate(lines, 1):
        for c in _extract_candidates(line):
            line_map.setdefault(c, []).append(ln)
    findings = []
    seen = set()
    for c in _extract_candidates(content):
        if c in seen:
            continue
        seen.add(c)
        ent = calculate_entropy(c)
        if ent < HIGH_ENTROPY_THRESHOLD:
            continue
        hex_r = sum(1 for ch in c if ch in _HEX_CHARS) / len(c)
        b64_r = sum(1 for ch in c if ch in _BASE64_CHARS) / len(c)
        char_set = "hex" if hex_r > 0.95 else ("base64" if b64_r > 0.9 else "mixed")
        lns = line_map.get(c, [])
        ln = lns[0] if lns else None
        ctx = ""
        if ln:
            raw = lines[ln-1]
            red = "{}...{}".format(c[:4], c[-4:]) if len(c) > 8 else "[REDACTED]"
            ctx = raw.replace(c, red)[:200]
        findings.append(EntropyFinding(file_path=file_path, line_number=ln, matched_string=c, entropy=round(ent,3), char_set=char_set, context=ctx))
    return findings

def scan_directory_for_entropy(repo_dir: str, max_files: int = 5000) -> list:
    all_findings = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if count >= max_files:
                return all_findings
            all_findings.extend(scan_for_high_entropy_strings(os.path.join(dirpath, fname)))
            count += 1
    logger.info("Entropy: %d files, %d findings in %s", count, len(all_findings), repo_dir)
    return all_findings

def entropy_finding_to_description(finding: EntropyFinding) -> str:
    return (
        "High-entropy string (entropy={:.3f}, threshold={:.1f}).\n"
        "Charset: {}\nRedacted: {}\nContext: {}"
    ).format(
        finding.entropy, HIGH_ENTROPY_THRESHOLD,
        finding.char_set, finding.redacted_display,
        finding.context or "N/A"
    )
