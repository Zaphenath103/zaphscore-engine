"""
ZSE Fix Generator — generates fix suggestions and can create GitHub Pull
Requests with version bumps.  Closes the #1 critical gap vs Snyk
(auto-remediation).
"""

from __future__ import annotations

import base64
import difflib
import json
import logging
import re
import uuid
from typing import Any, Optional

import aiohttp

from app.models.schemas import Finding, FindingType, Severity
from app.services.github_client import GitHubClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Manifest detection helpers
# ---------------------------------------------------------------------------

_MANIFEST_ECOSYSTEM_MAP: dict[str, list[str]] = {
    "npm": ["package.json"],
    "PyPI": ["requirements.txt", "requirements-dev.txt", "setup.cfg", "pyproject.toml"],
    "Go": ["go.mod"],
    "crates.io": ["Cargo.toml"],
    "Maven": ["pom.xml"],
    "RubyGems": ["Gemfile"],
}

# SAST rule-id to generic advice
_SAST_ADVICE: dict[str, str] = {
    "sql-injection": "Use parameterised queries or an ORM instead of string concatenation.",
    "xss": "Sanitise user input before rendering. Use framework auto-escaping.",
    "path-traversal": "Validate and canonicalise file paths. Reject '..' components.",
    "command-injection": "Avoid shell=True. Use subprocess with an argument list.",
    "hardcoded-secret": "Move credentials to environment variables or a secrets manager.",
    "insecure-deserialization": "Use safe deserialization formats (JSON) instead of pickle/yaml.unsafe_load.",
    "open-redirect": "Validate redirect URLs against an allowlist of trusted domains.",
}


# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def _parse_semver(version: str) -> Optional[tuple[int, int, int]]:
    """Parse a version string into (major, minor, patch) or None."""
    m = _SEMVER_RE.match(version.strip())
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def assess_breaking_risk(current: str, target: str) -> str:
    """Assess the breaking risk of upgrading from *current* to *target*.

    Returns ``"low"``, ``"medium"``, or ``"high"`` based on semver distance.
    """
    cur = _parse_semver(current)
    tgt = _parse_semver(target)

    if cur is None or tgt is None:
        return "medium"

    if tgt[0] != cur[0]:
        return "high"
    if tgt[1] != cur[1]:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Patch / diff generation
# ---------------------------------------------------------------------------

def generate_patch_diff(
    manifest_content: str,
    package_name: str,
    old_version: str,
    new_version: str,
    manifest_type: str,
) -> str:
    """Generate a unified diff string for a version bump inside a manifest.

    Supports ``package.json``, ``requirements.txt``, ``go.mod``,
    and ``Cargo.toml``.
    """
    updated = _apply_version_bump(
        manifest_content, package_name, old_version, new_version, manifest_type,
    )

    if updated == manifest_content:
        return ""

    diff_lines = difflib.unified_diff(
        manifest_content.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=f"a/{manifest_type}",
        tofile=f"b/{manifest_type}",
    )
    return "".join(diff_lines)


def _apply_version_bump(
    content: str,
    package_name: str,
    old_version: str,
    new_version: str,
    manifest_type: str,
) -> str:
    """Apply a version bump to *content* and return the modified string."""

    if manifest_type == "package.json":
        return _bump_package_json(content, package_name, old_version, new_version)
    if manifest_type in ("requirements.txt", "requirements-dev.txt"):
        return _bump_requirements_txt(content, package_name, old_version, new_version)
    if manifest_type == "go.mod":
        return _bump_go_mod(content, package_name, old_version, new_version)
    if manifest_type == "Cargo.toml":
        return _bump_cargo_toml(content, package_name, old_version, new_version)

    logger.warning("Unsupported manifest type for patching: %s", manifest_type)
    return content


def _bump_package_json(content: str, pkg: str, old: str, new: str) -> str:
    """Replace a dependency version in a package.json string."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content

    changed = False
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict) and pkg in deps:
            current_spec = deps[pkg]
            # Preserve range prefix (^, ~, >=, etc.)
            prefix = ""
            for p in ("^", "~", ">=", "<=", ">", "<", "="):
                if current_spec.startswith(p):
                    prefix = p
                    break
            deps[pkg] = f"{prefix}{new}"
            changed = True

    if not changed:
        return content

    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _bump_requirements_txt(content: str, pkg: str, old: str, new: str) -> str:
    """Replace a pinned version in requirements.txt."""
    lines = content.splitlines(keepends=True)
    result: list[str] = []
    # Match lines like: package==1.2.3 or package>=1.2.3
    pattern = re.compile(
        rf"^({re.escape(pkg)})\s*(==|>=|~=|!=|<=|>|<)\s*{re.escape(old)}",
        re.IGNORECASE,
    )
    for line in lines:
        m = pattern.match(line.strip())
        if m:
            operator = m.group(2)
            result.append(f"{pkg}{operator}{new}\n")
        else:
            result.append(line)
    return "".join(result)


def _bump_go_mod(content: str, pkg: str, old: str, new: str) -> str:
    """Replace a module version in go.mod."""
    # go.mod lines look like: \tmodule/path v1.2.3
    old_v = old if old.startswith("v") else f"v{old}"
    new_v = new if new.startswith("v") else f"v{new}"
    escaped_pkg = re.escape(pkg)
    pattern = re.compile(rf"({escaped_pkg}\s+){re.escape(old_v)}")
    return pattern.sub(rf"\g<1>{new_v}", content)


def _bump_cargo_toml(content: str, pkg: str, old: str, new: str) -> str:
    """Replace a crate version in Cargo.toml."""
    # Handles both: pkg = "1.2.3" and pkg = { version = "1.2.3", ... }
    # Simple form
    simple = re.compile(
        rf'({re.escape(pkg)}\s*=\s*"){re.escape(old)}(")',
    )
    result = simple.sub(rf"\g<1>{new}\2", content)
    # Table form
    table = re.compile(
        rf'({re.escape(pkg)}\s*=\s*\{{[^}}]*version\s*=\s*"){re.escape(old)}(")',
    )
    result = table.sub(rf"\g<1>{new}\2", result)
    return result


# ---------------------------------------------------------------------------
# Manifest file resolution
# ---------------------------------------------------------------------------

def _find_manifest_for_dep(
    dep: dict,
    repo_dir: str,
) -> Optional[str]:
    """Given a dependency dict, determine which manifest file it belongs to."""
    import os

    ecosystem = dep.get("ecosystem", "")
    candidates = _MANIFEST_ECOSYSTEM_MAP.get(ecosystem, [])

    for candidate in candidates:
        manifest_path = os.path.join(repo_dir, candidate)
        if os.path.isfile(manifest_path):
            return candidate

    return None


def _read_file_safe(path: str) -> Optional[str]:
    """Read a file and return its content, or None on error."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Fix generation
# ---------------------------------------------------------------------------

async def generate_fixes(
    findings: list[dict],
    dependencies: list[dict],
    repo_dir: str,
) -> list[dict]:
    """Generate fix suggestions for scan findings.

    For each vulnerability that has a ``fix_version``, produce a concrete
    version-bump suggestion.  Also generates advisory suggestions for
    secrets, SAST, and IaC findings.

    Args:
        findings: List of finding dicts (serialised Finding models).
        dependencies: Resolved dependency list from the scan.
        repo_dir: Absolute path to the cloned repository.

    Returns:
        List of fix suggestion dicts.
    """
    import os

    fixes: list[dict] = []

    # Build a lookup: package_name → dependency info
    dep_lookup: dict[str, dict] = {}
    for dep in dependencies:
        dep_lookup[dep.get("name", "")] = dep

    for finding in findings:
        finding_type = finding.get("type", "")
        finding_id = finding.get("id", str(uuid.uuid4()))

        # -----------------------------------------------------------------
        # Vulnerability findings — version bump fixes
        # -----------------------------------------------------------------
        if finding_type == FindingType.vulnerability.value:
            fix_version = finding.get("fix_version")
            if not fix_version:
                continue

            # Extract package name from the description
            pkg_name = _extract_package_name(finding)
            if not pkg_name:
                continue

            dep_info = dep_lookup.get(pkg_name, {})
            current_version = dep_info.get("version", "unknown")

            # Find the manifest file
            manifest_file = _find_manifest_for_dep(dep_info, repo_dir)
            if not manifest_file:
                # Still generate the suggestion, just not auto-fixable
                fixes.append({
                    "finding_id": finding_id,
                    "package": pkg_name,
                    "current_version": current_version,
                    "fix_version": fix_version,
                    "manifest_file": None,
                    "fix_type": "version_bump",
                    "patch": "",
                    "description": (
                        f"Upgrade {pkg_name} from {current_version} to "
                        f"{fix_version} to fix {finding.get('cve_id') or finding.get('ghsa_id') or 'vulnerability'}"
                    ),
                    "breaking_risk": assess_breaking_risk(current_version, fix_version),
                    "auto_fixable": False,
                })
                continue

            # Read manifest and generate patch
            manifest_path = os.path.join(repo_dir, manifest_file)
            manifest_content = _read_file_safe(manifest_path)
            if not manifest_content:
                continue

            patch = generate_patch_diff(
                manifest_content, pkg_name, current_version, fix_version, manifest_file,
            )
            cve_ref = finding.get("cve_id") or finding.get("ghsa_id") or "vulnerability"

            fixes.append({
                "finding_id": finding_id,
                "package": pkg_name,
                "current_version": current_version,
                "fix_version": fix_version,
                "manifest_file": manifest_file,
                "fix_type": "version_bump",
                "patch": patch,
                "description": (
                    f"Upgrade {pkg_name} from {current_version} to "
                    f"{fix_version} to fix {cve_ref}"
                ),
                "breaking_risk": assess_breaking_risk(current_version, fix_version),
                "auto_fixable": bool(patch),
            })

        # -----------------------------------------------------------------
        # Secret findings — .gitignore + rotation advice
        # -----------------------------------------------------------------
        elif finding_type == FindingType.secret.value:
            file_path = finding.get("file_path", "")
            fixes.append({
                "finding_id": finding_id,
                "package": None,
                "current_version": None,
                "fix_version": None,
                "manifest_file": file_path,
                "fix_type": "secret_remediation",
                "patch": "",
                "description": (
                    f"Secret detected in {file_path or 'repository'}. "
                    f"1) Rotate the compromised credential immediately. "
                    f"2) Add the file pattern to .gitignore. "
                    f"3) Consider using a secrets manager (e.g. AWS Secrets Manager, "
                    f"HashiCorp Vault, or GitHub Encrypted Secrets)."
                ),
                "breaking_risk": "high",
                "auto_fixable": False,
            })

            # If the file looks like it should be gitignored, suggest that
            gitignore_patterns = _suggest_gitignore_patterns(file_path)
            if gitignore_patterns:
                gitignore_path = os.path.join(repo_dir, ".gitignore")
                existing_gitignore = _read_file_safe(gitignore_path) or ""
                new_lines = [
                    p for p in gitignore_patterns
                    if p not in existing_gitignore
                ]
                if new_lines:
                    addition = "\n# ZSE: Secret file patterns\n" + "\n".join(new_lines) + "\n"
                    fixes.append({
                        "finding_id": finding_id,
                        "package": None,
                        "current_version": None,
                        "fix_version": None,
                        "manifest_file": ".gitignore",
                        "fix_type": "gitignore_addition",
                        "patch": addition,
                        "description": (
                            f"Add patterns to .gitignore to prevent secret files "
                            f"from being committed: {', '.join(new_lines)}"
                        ),
                        "breaking_risk": "low",
                        "auto_fixable": True,
                    })

        # -----------------------------------------------------------------
        # SAST findings — code pattern advice
        # -----------------------------------------------------------------
        elif finding_type == FindingType.sast.value:
            rule_id = finding.get("rule_id", "")
            advice = _get_sast_advice(rule_id)
            fixes.append({
                "finding_id": finding_id,
                "package": None,
                "current_version": None,
                "fix_version": None,
                "manifest_file": finding.get("file_path"),
                "fix_type": "code_pattern",
                "patch": "",
                "description": advice,
                "breaking_risk": "medium",
                "auto_fixable": False,
            })

        # -----------------------------------------------------------------
        # IaC findings — config change advice
        # -----------------------------------------------------------------
        elif finding_type == FindingType.iac.value:
            rule_id = finding.get("rule_id", "")
            fixes.append({
                "finding_id": finding_id,
                "package": None,
                "current_version": None,
                "fix_version": None,
                "manifest_file": finding.get("file_path"),
                "fix_type": "iac_config",
                "patch": "",
                "description": (
                    f"IaC misconfiguration ({rule_id or 'unknown rule'}): "
                    f"{finding.get('title', '')}. "
                    f"Review the flagged resource and apply the recommended "
                    f"configuration change per CIS/checkov guidelines."
                ),
                "breaking_risk": "medium",
                "auto_fixable": False,
            })

    logger.info("Generated %d fix suggestions for %d findings", len(fixes), len(findings))
    return fixes


# ---------------------------------------------------------------------------
# Pull Request creation
# ---------------------------------------------------------------------------

async def create_fix_pr(
    repo_owner: str,
    repo_name: str,
    fixes: list[dict],
    github_token: str,
) -> dict:
    """Create a GitHub Pull Request with auto-fixable version bumps.

    Uses the GitHub API to:
      1. Create a branch ``zse/fix-{short_id}``
      2. Commit each auto-fixable fix
      3. Open a PR with a summary table

    Args:
        repo_owner: GitHub repository owner.
        repo_name: GitHub repository name.
        fixes: List of fix dicts from :func:`generate_fixes`.
        github_token: Personal access token with ``repo`` scope.

    Returns:
        Dict with ``pr_url``, ``pr_number``, ``fixes_applied``,
        ``fixes_skipped``.
    """
    client = GitHubClient(token_override=github_token)
    session = await client._get_session()

    auto_fixes = [f for f in fixes if f.get("auto_fixable")]
    skipped = [f for f in fixes if not f.get("auto_fixable")]

    if not auto_fixes:
        await client.close()
        return {
            "pr_url": None,
            "pr_number": None,
            "fixes_applied": 0,
            "fixes_skipped": len(skipped),
        }

    scan_id_short = uuid.uuid4().hex[:8]
    branch_name = f"zse/fix-{scan_id_short}"

    try:
        # Get the default branch and its HEAD SHA
        repo_data = await client._request("GET", f"/repos/{repo_owner}/{repo_name}")
        assert isinstance(repo_data, dict)
        default_branch = repo_data.get("default_branch", "main")

        ref_data = await client._request(
            "GET", f"/repos/{repo_owner}/{repo_name}/git/ref/heads/{default_branch}",
        )
        assert isinstance(ref_data, dict)
        base_sha = ref_data["object"]["sha"]

        # Create the fix branch
        await _api_post(session, client, f"/repos/{repo_owner}/{repo_name}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        })

        # Group fixes by manifest file to batch commits
        fixes_by_manifest: dict[str, list[dict]] = {}
        for fix in auto_fixes:
            mf = fix.get("manifest_file", "unknown")
            fixes_by_manifest.setdefault(mf, []).append(fix)

        applied_count = 0

        for manifest_file, manifest_fixes in fixes_by_manifest.items():
            if not manifest_file or manifest_file == "unknown":
                continue

            # Fetch current file content from the new branch
            try:
                file_data = await client._request(
                    "GET",
                    f"/repos/{repo_owner}/{repo_name}/contents/{manifest_file}",
                    params={"ref": branch_name},
                )
                assert isinstance(file_data, dict)
            except Exception:
                logger.warning("Could not fetch %s from branch %s", manifest_file, branch_name)
                continue

            content_b64 = file_data.get("content", "")
            file_sha = file_data.get("sha", "")
            content = base64.b64decode(content_b64).decode("utf-8")

            # Apply all version bumps for this manifest
            updated = content
            applied_packages: list[str] = []

            for fix in manifest_fixes:
                if fix.get("fix_type") == "version_bump" and fix.get("package"):
                    new_content = _apply_version_bump(
                        updated,
                        fix["package"],
                        fix.get("current_version", ""),
                        fix["fix_version"],
                        manifest_file,
                    )
                    if new_content != updated:
                        updated = new_content
                        applied_packages.append(fix["package"])
                        applied_count += 1
                elif fix.get("fix_type") == "gitignore_addition" and fix.get("patch"):
                    updated = content + fix["patch"]
                    applied_count += 1
                    applied_packages.append(".gitignore pattern")

            if updated == content:
                continue

            # Commit the updated file
            commit_msg = (
                f"fix: upgrade {', '.join(applied_packages)} in {manifest_file}\n\n"
                f"Automated security fix by Zaphenath Security Engine."
            )
            new_content_b64 = base64.b64encode(updated.encode("utf-8")).decode("ascii")

            await _api_put(
                session, client,
                f"/repos/{repo_owner}/{repo_name}/contents/{manifest_file}",
                {
                    "message": commit_msg,
                    "content": new_content_b64,
                    "sha": file_sha,
                    "branch": branch_name,
                },
            )

        # Build PR body
        pr_body = _build_pr_body(auto_fixes, skipped)

        vuln_count = len(set(f.get("finding_id") for f in auto_fixes))
        pkg_count = len(set(f.get("package") for f in auto_fixes if f.get("package")))

        pr_data = await _api_post(
            session, client,
            f"/repos/{repo_owner}/{repo_name}/pulls",
            {
                "title": f"fix: Upgrade {pkg_count} dependencies to resolve {vuln_count} vulnerabilities",
                "body": pr_body,
                "head": branch_name,
                "base": default_branch,
            },
        )

        pr_number = pr_data.get("number")
        pr_url = pr_data.get("html_url", "")

        # Add labels (best-effort — labels may not exist)
        if pr_number:
            try:
                await _api_post(
                    session, client,
                    f"/repos/{repo_owner}/{repo_name}/issues/{pr_number}/labels",
                    {"labels": ["security", "dependencies", "automated"]},
                )
            except Exception:
                logger.debug("Could not add labels to PR #%s (labels may not exist)", pr_number)

        return {
            "pr_url": pr_url,
            "pr_number": pr_number,
            "fixes_applied": applied_count,
            "fixes_skipped": len(skipped),
        }

    except Exception as exc:
        logger.error("Failed to create fix PR: %s", exc, exc_info=True)
        return {
            "pr_url": None,
            "pr_number": None,
            "fixes_applied": 0,
            "fixes_skipped": len(fixes),
            "error": str(exc),
        }
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# GitHub API helpers (write operations not on the base client)
# ---------------------------------------------------------------------------

async def _api_post(
    session: aiohttp.ClientSession,
    client: GitHubClient,
    path: str,
    json_body: dict[str, Any],
) -> dict:
    """POST to GitHub API via the client's session."""
    sess = await client._get_session()
    async with sess.request("POST", path, json=json_body) as resp:
        if resp.status >= 400:
            body = await resp.text()
            logger.error("GitHub POST %s failed (%d): %s", path, resp.status, body[:500])
            resp.raise_for_status()
        return await resp.json()


async def _api_put(
    session: aiohttp.ClientSession,
    client: GitHubClient,
    path: str,
    json_body: dict[str, Any],
) -> dict:
    """PUT to GitHub API via the client's session."""
    sess = await client._get_session()
    async with sess.request("PUT", path, json=json_body) as resp:
        if resp.status >= 400:
            body = await resp.text()
            logger.error("GitHub PUT %s failed (%d): %s", path, resp.status, body[:500])
            resp.raise_for_status()
        return await resp.json()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_package_name(finding: dict) -> Optional[str]:
    """Extract the package name from a vulnerability finding's description."""
    desc = finding.get("description", "")
    # Pattern: **Package:** name@version
    m = re.search(r"\*\*Package:\*\*\s+(\S+?)@", desc)
    if m:
        return m.group(1)
    # Fallback: try the title — often "VULN_ID: summary about package"
    title = finding.get("title", "")
    m = re.search(r"in\s+(\S+?)(?:\s|$)", title)
    if m:
        return m.group(1)
    return None


def _suggest_gitignore_patterns(file_path: str) -> list[str]:
    """Suggest .gitignore patterns based on a file path containing secrets."""
    patterns: list[str] = []
    lower = file_path.lower()

    if ".env" in lower:
        patterns.append(".env")
        patterns.append(".env.*")
    if "credentials" in lower or "credential" in lower:
        patterns.append("*credentials*")
    if lower.endswith(".pem") or lower.endswith(".key"):
        patterns.append("*.pem")
        patterns.append("*.key")
    if "secret" in lower:
        patterns.append("*secret*")
    if lower.endswith(".json") and ("service" in lower or "account" in lower):
        patterns.append("*service-account*.json")
    if "id_rsa" in lower or "id_ed25519" in lower:
        patterns.append("id_rsa*")
        patterns.append("id_ed25519*")
    if ".npmrc" in lower:
        patterns.append(".npmrc")
    if ".pypirc" in lower:
        patterns.append(".pypirc")

    return patterns


def _get_sast_advice(rule_id: str) -> str:
    """Return remediation advice for a SAST rule."""
    if not rule_id:
        return (
            "Review the flagged code pattern and apply secure coding "
            "best practices per OWASP guidelines."
        )

    # Try exact match first
    if rule_id in _SAST_ADVICE:
        return _SAST_ADVICE[rule_id]

    # Try substring match
    rule_lower = rule_id.lower()
    for key, advice in _SAST_ADVICE.items():
        if key in rule_lower:
            return advice

    return (
        f"SAST rule {rule_id} triggered. Review the flagged code and apply "
        f"the recommended fix per the rule documentation."
    )


def _build_pr_body(applied: list[dict], skipped: list[dict]) -> str:
    """Build the Pull Request markdown body."""
    lines: list[str] = []
    lines.append("## Zaphenath Security Engine — Automated Fix\n")
    lines.append(
        "This PR was automatically generated by ZSE to resolve "
        "known vulnerabilities.\n"
    )

    # Applied fixes table
    if applied:
        lines.append("### Applied Fixes\n")
        lines.append("| Package | Current | Fixed | CVE / Advisory | Severity | Breaking Risk |")
        lines.append("|---------|---------|-------|----------------|----------|---------------|")
        for fix in applied:
            pkg = fix.get("package", "—")
            cur = fix.get("current_version", "—")
            fv = fix.get("fix_version", "—")
            # Try to get CVE from the finding
            desc = fix.get("description", "")
            cve_match = re.search(r"(CVE-\d{4}-\d+|GHSA-\S+)", desc)
            cve = cve_match.group(1) if cve_match else "—"
            risk = fix.get("breaking_risk", "—")
            lines.append(f"| {pkg} | {cur} | {fv} | {cve} | — | {risk} |")
        lines.append("")

    # Skipped fixes (need manual intervention)
    if skipped:
        lines.append("### Requires Manual Review\n")
        for fix in skipped[:20]:  # Cap at 20 to avoid huge PRs
            desc = fix.get("description", "Unknown fix")
            lines.append(f"- {desc}")
        if len(skipped) > 20:
            lines.append(f"- ... and {len(skipped) - 20} more")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by [Zaphenath Security Engine](https://zaphenath.app)*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# D-676: generate_fix_pr_payload and simulate_ci_check
# Enables downstream automation to actually open fix PRs autonomously.
# ---------------------------------------------------------------------------

import ast as _ast
import textwrap as _textwrap


def generate_fix_pr_payload(
    finding: dict,
    repo_url: str,
    token: str,
) -> dict:
    """Generate a structured PR payload for a single finding.

    Returns a dict that downstream automation can use to open a GitHub PR
    without any further analysis.  No network calls are made here.

    Args:
        finding: A finding dict (from scan results) with at minimum:
            id, title, type, severity, file_path,
            package (optional), fix_version (optional), patch
            (optional unified-diff string).
        repo_url: Full GitHub HTTPS URL of the target repo,
            e.g. "https://github.com/owner/repo".
        token: GitHub personal-access-token (repo scope).
            Stored in the payload so the consumer can authenticate; the
            token itself is never logged.

    Returns:
        Structured payload dict with::

            {
                "branch_name":  str,   # e.g. "zse/fix-abc12345"
                "title":        str,   # PR title
                "body":         str,   # Markdown PR body
                "file_changes": list,  # [{"path": str, "patch": str}, ...]
                "submit_url":   str,   # GitHub pulls API endpoint
                "token":        str,   # forwarded token (treat as secret)
                "base_branch":  str,   # always "main" unless overridden
                "finding_id":   str,
            }
    """
    import uuid as _uuid

    finding_id = str(finding.get("id", "unknown"))
    short_id = _uuid.uuid4().hex[:8]
    branch_name = f"zse/fix-{short_id}"

    title_raw = finding.get("title", "Security fix")
    pkg = finding.get("package") or finding.get("pkg")
    fix_ver = finding.get("fix_version")

    if pkg and fix_ver:
        title = f"fix(security): upgrade {pkg} to {fix_ver}"
    else:
        title = f"fix(security): {title_raw[:72]}"

    # Build markdown PR body
    sev = str(finding.get("severity", "unknown")).upper()
    desc = finding.get("description", "")
    file_path = finding.get("file_path", "")
    cve = finding.get("cve_id", "")

    body_lines = [
        "## ZSE Automated Security Fix
",
        f"**Finding:** {title_raw}",
        f"**Severity:** {sev}",
    ]
    if cve:
        body_lines.append(f"**CVE:** {cve}")
    if pkg and fix_ver:
        cur = finding.get("current_version", "unknown")
        body_lines.append(f"**Package:**  —  → ")
    if file_path:
        body_lines.append(f"**File:** ")
    if desc:
        body_lines.append(f"
### Details
{desc[:800]}")
    body_lines.append("
---")
    body_lines.append("*Automatically generated by [Zaphenath Security Engine](https://zaphenath.app)*")

    body = "
".join(body_lines)

    # File changes list
    file_changes: list[dict] = []
    patch = finding.get("patch", "")
    if patch and file_path:
        file_changes.append({"path": file_path, "patch": patch})

    # Derive GitHub API pulls URL from repo_url
    # repo_url: https://github.com/owner/repo  →  /repos/owner/repo/pulls
    submit_url = ""
    if "github.com/" in repo_url:
        parts = repo_url.rstrip("/").split("github.com/", 1)
        if len(parts) == 2:
            owner_repo = parts[1].rstrip(".git")
            submit_url = f"https://api.github.com/repos/{owner_repo}/pulls"

    return {
        "branch_name": branch_name,
        "title": title,
        "body": body,
        "file_changes": file_changes,
        "submit_url": submit_url,
        "token": token,
        "base_branch": "main",
        "finding_id": finding_id,
    }


def simulate_ci_check(pr_payload: dict) -> bool:
    """Simulate a CI check on a PR payload.

    Performs lightweight syntactic validation of every patch in
    pr_payload["file_changes"] to ensure it is a valid unified diff
    (starts with ---/+++ headers) and, for Python files, that the
    patched hunks contain syntactically valid Python.

    Args:
        pr_payload: Dict as returned by :func:.

    Returns:
        True if all checks pass (CI would be green), False otherwise.
    """
    file_changes = pr_payload.get("file_changes", [])

    if not file_changes:
        # No code changes — trivially passes (e.g. docs-only PR)
        return True

    for change in file_changes:
        patch = change.get("patch", "")
        file_path = change.get("path", "")

        # 1. Must be a non-empty string
        if not isinstance(patch, str) or not patch.strip():
            logger.warning("simulate_ci_check: empty patch for %s", file_path)
            return False

        # 2. Basic unified-diff structure check
        lines = patch.splitlines()
        has_diff_header = any(
            l.startswith("---") or l.startswith("+++") or l.startswith("@@")
            for l in lines
        )
        if not has_diff_header:
            logger.warning(
                "simulate_ci_check: patch for %s lacks unified-diff headers",
                file_path,
            )
            return False

        # 3. For Python files: extract added lines and check they parse
        if file_path.endswith(".py"):
            added_lines = [l[1:] for l in lines if l.startswith("+") and not l.startswith("+++")]
            added_src = "
".join(added_lines)
            if added_src.strip():
                try:
                    _ast.parse(added_src)
                except SyntaxError as exc:
                    logger.warning(
                        "simulate_ci_check: added Python code in %s has syntax error: %s",
                        file_path, exc,
                    )
                    return False

    return True
