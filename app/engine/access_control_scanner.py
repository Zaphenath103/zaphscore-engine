"""
Access Control Scanner -- detects missing authentication on sensitive endpoints.
UFC Fight 1 blind spot: ZaphScore missed unauthenticated admin routes (EX-01/CWE-285).

OWASP Top 10 2024: A01 - Broken Access Control
CWE: CWE-285 (Improper Authorization)
"""

from __future__ import annotations

import ast
import logging
import os
import re
from pathlib import Path
from typing import Optional

from app.models.schemas import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive route path keywords -- any route containing these needs auth
# ---------------------------------------------------------------------------
_SENSITIVE_PATH_PATTERNS = [
    re.compile(r"/users/?$", re.IGNORECASE),
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/internal", re.IGNORECASE),
    re.compile(r"/delete", re.IGNORECASE),
    re.compile(r"/reset", re.IGNORECASE),
    re.compile(r"/config", re.IGNORECASE),
    re.compile(r"/export", re.IGNORECASE),
]

# FastAPI / Flask route decorator attribute names
_ROUTE_DECORATOR_ATTRS = {
    "get", "post", "put", "patch", "delete", "head", "options",
    "route", "api_route",
}

# Auth parameter names -- presence of any means route is protected
_AUTH_PARAM_NAMES = {
    "current_user", "get_current_user", "api_key", "token",
    "authorization", "authenticated_user", "active_user",
    "verify_token", "require_user", "logged_in_user",
}

# Auth decorator names -- presence of any means route is protected
_AUTH_DECORATOR_NAMES = {
    "require_auth", "login_required", "jwt_required", "token_required",
    "auth_required", "requires_auth", "authenticated",
    "permission_required", "roles_required",
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", "migrations", ".tox", "site-packages",
}


def _is_sensitive_path(path_str: str) -> bool:
    """Return True if path contains a sensitive keyword."""
    for pattern in _SENSITIVE_PATH_PATTERNS:
        if pattern.search(path_str):
            return True
    return False


def _decorator_route_path(decorator) -> Optional[str]:
    """Extract route path string from a decorator node, or None."""
    if not isinstance(decorator, ast.Call):
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr not in _ROUTE_DECORATOR_ATTRS:
        return None
    if decorator.args and isinstance(decorator.args[0], ast.Constant):
        val = decorator.args[0].value
        if isinstance(val, str):
            return val
    return None


def _has_auth_decorator(decorators: list) -> bool:
    """Return True if any decorator is a known auth enforcer."""
    for dec in decorators:
        if isinstance(dec, ast.Name) and dec.id in _AUTH_DECORATOR_NAMES:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr in _AUTH_DECORATOR_NAMES:
            return True
        if isinstance(dec, ast.Call):
            inner = dec.func
            if isinstance(inner, ast.Name) and inner.id in _AUTH_DECORATOR_NAMES:
                return True
            if isinstance(inner, ast.Attribute) and inner.attr in _AUTH_DECORATOR_NAMES:
                return True
    return False


def _has_auth_in_signature(func_node) -> bool:
    """Return True if function signature contains auth dependency indicators."""
    args = func_node.args
    all_args = (
        args.args + args.posonlyargs + args.kwonlyargs
        + ([args.vararg] if args.vararg else [])
        + ([args.kwarg] if args.kwarg else [])
    )
    for arg in all_args:
        if arg.arg.lower() in _AUTH_PARAM_NAMES:
            return True
        if arg.annotation is not None:
            ann_src = ast.dump(arg.annotation)
            if "Depends" in ann_src or any(name in ann_src for name in _AUTH_PARAM_NAMES):
                return True
    all_defaults = args.defaults + args.kw_defaults
    for default in all_defaults:
        if default is None:
            continue
        default_src = ast.dump(default)
        if "Depends" in default_src or any(name in default_src for name in _AUTH_PARAM_NAMES):
            return True
    return False


def _scan_python_file_ast(file_path: str, repo_dir: str) -> list:
    """Parse a Python file with AST and detect unprotected sensitive routes."""
    findings = []
    rel_path = os.path.relpath(file_path, repo_dir)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as exc:
        logger.debug("Cannot read %s: %s", file_path, exc)
        return findings
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_path = None
        for decorator in node.decorator_list:
            candidate = _decorator_route_path(decorator)
            if candidate is not None and _is_sensitive_path(candidate):
                route_path = candidate
                break
        if route_path is None:
            continue
        if _has_auth_decorator(node.decorator_list):
            continue
        if _has_auth_in_signature(node):
            continue
        findings.append(Finding(
            type=FindingType.sast,
            severity=Severity.high,
            title="Unauthenticated sensitive endpoint",
            description=(
                "Route '" + route_path + "' has no authentication check. "
                "Any caller can access it. Add a Depends(get_current_user) "
                "parameter (FastAPI) or @login_required decorator (Flask) to "
                "enforce access control. CWE-285 / OWASP A01:2024."
            ),
            file_path=rel_path,
            line=node.lineno,
            rule_id="ZSE-AC-001",
        ))
    return findings


_ROUTE_LINE_RE = re.compile(
    r"@(?:\w+\.)?(?:get|post|put|patch|delete|head|options|route|api_route)"
    r"\s*\(\s*[\x22\x27]([^\x22\x27]+)[\x22\x27]",
    re.IGNORECASE,
)
_AUTH_INDICATOR_RE = re.compile(
    r"Depends\s*\(|current_user|api_key|login_required|jwt_required|require_auth|token_required",
    re.IGNORECASE,
)


def _scan_python_file_regex(file_path: str, repo_dir: str) -> list:
    """Simple line-by-line regex scan as fallback for unparseable files."""
    findings = []
    rel_path = os.path.relpath(file_path, repo_dir)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return findings
    for i, line in enumerate(lines):
        m = _ROUTE_LINE_RE.search(line)
        if m:
            route_path = m.group(1)
            if _is_sensitive_path(route_path):
                window = "".join(lines[i: min(i + 15, len(lines))])
                if not _AUTH_INDICATOR_RE.search(window):
                    findings.append(Finding(
                        type=FindingType.sast,
                        severity=Severity.high,
                        title="Unauthenticated sensitive endpoint",
                        description=(
                            "Route '" + route_path + "' has no authentication check. "
                            "Any caller can access it. Add a Depends(get_current_user) "
                            "parameter (FastAPI) or @login_required decorator (Flask) to "
                            "enforce access control. CWE-285 / OWASP A01:2024."
                        ),
                        file_path=rel_path,
                        line=i + 1,
                        rule_id="ZSE-AC-001-REGEX",
                    ))
    return findings


def scan_access_control(repo_dir: str) -> list:
    """Walk all Python files in repo_dir and detect unauthenticated sensitive routes.

    Uses AST parsing as primary strategy with a regex fallback for files that
    fail to parse (Python 2 syntax, encoding issues, etc.).

    Args:
        repo_dir: Absolute path to the cloned repository root.

    Returns:
        List of Finding objects, one per unauthenticated sensitive endpoint found.
    """
    findings = []
    if not Path(repo_dir).is_dir():
        logger.warning("access_control_scanner: repo_dir does not exist: %s", repo_dir)
        return findings

    scanned = 0
    for dirpath, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            full_path = os.path.join(dirpath, filename)
            scanned += 1
            ast_results = _scan_python_file_ast(full_path, repo_dir)
            if ast_results:
                findings.extend(ast_results)
            else:
                findings.extend(_scan_python_file_regex(full_path, repo_dir))

    logger.info(
        "access_control_scanner: scanned %d Python files, found %d findings",
        scanned, len(findings),
    )
    return findings
