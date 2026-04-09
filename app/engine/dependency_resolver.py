"""
ZSE Dependency Resolver — parse every major manifest format, with optional
tool-assisted resolution (npm ls, pip-compile).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

logger = logging.getLogger(__name__)

MAX_MANIFESTS = 20

# Priority order for ecosystems (lower = scanned first)
_ECOSYSTEM_PRIORITY = {
    "npm": 0,
    "PyPI": 1,
    "Go": 2,
    "crates.io": 3,
    "Maven": 4,
    "RubyGems": 5,
    "Packagist": 6,
}


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest_path: str
    dev: bool = False

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}:{self.version}"


# ---------------------------------------------------------------------------
# Manifest discovery
# ---------------------------------------------------------------------------

_MANIFEST_FILES: dict[str, str] = {
    "package-lock.json": "npm",
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "Pipfile.lock": "PyPI",
    "go.sum": "Go",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "Cargo.toml": "crates.io",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile.lock": "RubyGems",
    "composer.lock": "Packagist",
}

# Lock files take precedence over plain manifests
_LOCK_FILES = {
    "package-lock.json",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
}


def _discover_manifests(repo_dir: str) -> list[tuple[str, str]]:
    """Walk the repo and return (abs_path, ecosystem) for each manifest found.

    Skips node_modules, .git, vendor, __pycache__, and venv directories.
    Returns at most MAX_MANIFESTS entries, sorted by root-first then priority.
    """
    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", "venv", ".venv", "dist", "build"}
    found: list[tuple[str, str, int]] = []  # (path, ecosystem, depth)

    for dirpath, dirnames, filenames in os.walk(repo_dir):
        # Prune ignored dirs
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        rel = os.path.relpath(dirpath, repo_dir)
        depth = 0 if rel == "." else rel.count(os.sep) + 1

        for fname in filenames:
            if fname in _MANIFEST_FILES:
                eco = _MANIFEST_FILES[fname]
                abs_path = os.path.join(dirpath, fname)
                found.append((abs_path, eco, depth))

    # Sort: root manifests first, then by ecosystem priority, then alphabetical
    found.sort(key=lambda t: (t[2], _ECOSYSTEM_PRIORITY.get(t[1], 99), t[0]))

    # Deduplicate: if a lock file exists for an ecosystem in the same dir, skip the plain manifest
    result: list[tuple[str, str]] = []
    seen_eco_dirs: set[str] = set()

    for abs_path, eco, _depth in found:
        fname = os.path.basename(abs_path)
        dir_key = f"{os.path.dirname(abs_path)}:{eco}"

        if fname in _LOCK_FILES:
            seen_eco_dirs.add(dir_key)
            result.append((abs_path, eco))
        elif dir_key not in seen_eco_dirs:
            result.append((abs_path, eco))

        if len(result) >= MAX_MANIFESTS:
            break

    return result


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------

def _parse_package_json(path: str) -> list[Dependency]:
    """Parse package.json for dependencies and devDependencies."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section, is_dev in [("dependencies", False), ("devDependencies", True)]:
            for name, version in data.get(section, {}).items():
                # Strip version prefixes like ^, ~, >=
                clean = re.sub(r"^[\^~>=<]*", "", str(version)).strip()
                if clean:
                    deps.append(Dependency(name=name, version=clean, ecosystem="npm", manifest_path=path, dev=is_dev))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_package_lock_json(path: str) -> list[Dependency]:
    """Parse package-lock.json for resolved dependency versions."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # lockfileVersion 2/3 uses "packages"
        packages = data.get("packages", {})
        if packages:
            for pkg_path, info in packages.items():
                if not pkg_path:  # root entry
                    continue
                # node_modules/pkg-name or node_modules/@scope/pkg-name
                name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                version = info.get("version", "")
                is_dev = info.get("dev", False)
                if name and version:
                    deps.append(Dependency(name=name, version=version, ecosystem="npm", manifest_path=path, dev=is_dev))
        else:
            # lockfileVersion 1 uses "dependencies"
            def _walk_deps(dep_dict: dict, is_dev: bool = False) -> None:
                for name, info in dep_dict.items():
                    version = info.get("version", "")
                    if name and version:
                        deps.append(Dependency(name=name, version=version, ecosystem="npm", manifest_path=path, dev=is_dev))
                    if "dependencies" in info:
                        _walk_deps(info["dependencies"], is_dev)

            _walk_deps(data.get("dependencies", {}))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_requirements_txt(path: str) -> list[Dependency]:
    """Parse requirements.txt — one package per line."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle: package==1.0, package>=1.0, package~=1.0
                m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=~<>!]=*)\s*([^\s,;#]+)", line)
                if m:
                    deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem="PyPI", manifest_path=path))
                else:
                    # Just a package name with no version
                    name = re.match(r"^([A-Za-z0-9_.-]+)", line)
                    if name:
                        deps.append(Dependency(name=name.group(1), version="*", ecosystem="PyPI", manifest_path=path))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_pyproject_toml(path: str) -> list[Dependency]:
    """Parse pyproject.toml for [project].dependencies and optional-dependencies."""
    deps: list[Dependency] = []
    try:
        # Use tomllib (3.11+) or tomli
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        with open(path, "rb") as f:
            data = tomllib.load(f)

        project = data.get("project", {})
        for dep_str in project.get("dependencies", []):
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=~<>!]=*)\s*([^\s,;#]*)", dep_str)
            if m:
                deps.append(Dependency(name=m.group(1), version=m.group(2) or "*", ecosystem="PyPI", manifest_path=path))

        for _group, dep_list in project.get("optional-dependencies", {}).items():
            for dep_str in dep_list:
                m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=~<>!]=*)\s*([^\s,;#]*)", dep_str)
                if m:
                    deps.append(Dependency(name=m.group(1), version=m.group(2) or "*", ecosystem="PyPI", manifest_path=path, dev=True))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_pipfile_lock(path: str) -> list[Dependency]:
    """Parse Pipfile.lock JSON."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section, is_dev in [("default", False), ("develop", True)]:
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                if name and version:
                    deps.append(Dependency(name=name, version=version, ecosystem="PyPI", manifest_path=path, dev=is_dev))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_go_mod(path: str) -> list[Dependency]:
    """Parse go.mod require blocks."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Single-line requires: require module/path v1.2.3
        for m in re.finditer(r"^\s*require\s+(\S+)\s+(v\S+)", content, re.MULTILINE):
            deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem="Go", manifest_path=path))

        # Block requires: require ( ... )
        for block in re.finditer(r"require\s*\((.*?)\)", content, re.DOTALL):
            for line in block.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    deps.append(Dependency(name=parts[0], version=parts[1], ecosystem="Go", manifest_path=path))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_go_sum(path: str) -> list[Dependency]:
    """Parse go.sum for exact module versions."""
    deps: list[Dependency] = []
    seen: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].split("/")[0]  # strip /go.mod suffix
                    key = f"{name}@{version}"
                    if key not in seen:
                        seen.add(key)
                        deps.append(Dependency(name=name, version=version, ecosystem="Go", manifest_path=path))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_cargo_toml(path: str) -> list[Dependency]:
    """Parse Cargo.toml for [dependencies] and [dev-dependencies]."""
    deps: list[Dependency] = []
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        with open(path, "rb") as f:
            data = tomllib.load(f)

        for section, is_dev in [("dependencies", False), ("dev-dependencies", True)]:
            for name, value in data.get(section, {}).items():
                if isinstance(value, str):
                    version = value
                elif isinstance(value, dict):
                    version = value.get("version", "*")
                else:
                    version = "*"
                version = re.sub(r"^[\^~>=<]*", "", str(version)).strip() or "*"
                deps.append(Dependency(name=name, version=version, ecosystem="crates.io", manifest_path=path, dev=is_dev))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_cargo_lock(path: str) -> list[Dependency]:
    """Parse Cargo.lock for exact versions."""
    deps: list[Dependency] = []
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        with open(path, "rb") as f:
            data = tomllib.load(f)

        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                deps.append(Dependency(name=name, version=version, ecosystem="crates.io", manifest_path=path))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_pom_xml(path: str) -> list[Dependency]:
    """Parse pom.xml for Maven dependencies."""
    deps: list[Dependency] = []
    try:
        tree = ElementTree.parse(path)
        root = tree.getroot()
        # Handle Maven namespace
        ns = ""
        m = re.match(r"\{(.+?)\}", root.tag)
        if m:
            ns = m.group(1)
            ns_prefix = f"{{{ns}}}"
        else:
            ns_prefix = ""

        for dep_elem in root.iter(f"{ns_prefix}dependency"):
            group_id = dep_elem.findtext(f"{ns_prefix}groupId", "")
            artifact_id = dep_elem.findtext(f"{ns_prefix}artifactId", "")
            version = dep_elem.findtext(f"{ns_prefix}version", "*")
            scope = dep_elem.findtext(f"{ns_prefix}scope", "compile")
            if group_id and artifact_id:
                name = f"{group_id}:{artifact_id}"
                # Version may contain ${...} properties — keep as-is
                deps.append(Dependency(
                    name=name,
                    version=version or "*",
                    ecosystem="Maven",
                    manifest_path=path,
                    dev=(scope in ("test", "provided")),
                ))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_build_gradle(path: str) -> list[Dependency]:
    """Basic regex parse of build.gradle for dependency declarations."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Match: implementation 'group:artifact:version'
        pattern = re.compile(
            r"(?:implementation|compile|api|runtimeOnly|testImplementation|compileOnly)"
            r"""\s+['"]([^'"]+?):([^'"]+?):([^'"]+?)['"]"""
        )
        for m in pattern.finditer(content):
            group, artifact, version = m.group(1), m.group(2), m.group(3)
            deps.append(Dependency(
                name=f"{group}:{artifact}",
                version=version,
                ecosystem="Maven",
                manifest_path=path,
                dev="test" in m.group(0).lower(),
            ))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_gemfile_lock(path: str) -> list[Dependency]:
    """Parse Gemfile.lock for RubyGems dependencies."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            in_specs = False
            for line in f:
                stripped = line.rstrip()
                if stripped == "  specs:":
                    in_specs = True
                    continue
                if in_specs:
                    # Gem entries are indented by 4 spaces: "    gem_name (version)"
                    m = re.match(r"^    (\S+)\s+\(([^)]+)\)", stripped)
                    if m:
                        deps.append(Dependency(
                            name=m.group(1), version=m.group(2),
                            ecosystem="RubyGems", manifest_path=path,
                        ))
                    elif not stripped.startswith("      "):
                        # Exited the specs block
                        if stripped and not stripped.startswith("    "):
                            in_specs = False
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


def _parse_composer_lock(path: str) -> list[Dependency]:
    """Parse composer.lock for Packagist dependencies."""
    deps: list[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section, is_dev in [("packages", False), ("packages-dev", True)]:
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                if name and version:
                    deps.append(Dependency(name=name, version=version, ecosystem="Packagist", manifest_path=path, dev=is_dev))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
    return deps


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PARSER_MAP: dict[str, dict[str, any]] = {
    "package.json": {"fn": _parse_package_json},
    "package-lock.json": {"fn": _parse_package_lock_json},
    "requirements.txt": {"fn": _parse_requirements_txt},
    "pyproject.toml": {"fn": _parse_pyproject_toml},
    "Pipfile.lock": {"fn": _parse_pipfile_lock},
    "go.mod": {"fn": _parse_go_mod},
    "go.sum": {"fn": _parse_go_sum},
    "Cargo.toml": {"fn": _parse_cargo_toml},
    "Cargo.lock": {"fn": _parse_cargo_lock},
    "pom.xml": {"fn": _parse_pom_xml},
    "build.gradle": {"fn": _parse_build_gradle},
    "Gemfile.lock": {"fn": _parse_gemfile_lock},
    "composer.lock": {"fn": _parse_composer_lock},
}


# ---------------------------------------------------------------------------
# Tool-assisted resolution
# ---------------------------------------------------------------------------

async def _try_npm_ls(repo_dir: str) -> Optional[list[Dependency]]:
    """Try running npm ls --json --all for accurate resolution."""
    package_json = os.path.join(repo_dir, "package.json")
    if not os.path.isfile(package_json):
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "ls", "--json", "--all", "--long",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        data = json.loads(stdout.decode("utf-8", errors="replace"))

        deps: list[Dependency] = []
        seen: set[str] = set()

        def _walk(node: dict, is_dev: bool = False) -> None:
            for name, info in node.get("dependencies", {}).items():
                version = info.get("version", "")
                key = f"{name}@{version}"
                if version and key not in seen:
                    seen.add(key)
                    deps.append(Dependency(
                        name=name, version=version, ecosystem="npm",
                        manifest_path=package_json, dev=is_dev or info.get("dev", False),
                    ))
                _walk(info, is_dev or info.get("dev", False))

        _walk(data)
        if deps:
            logger.info("npm ls resolved %d dependencies", len(deps))
            return deps
    except Exception as exc:
        logger.debug("npm ls failed (falling back to parse): %s", exc)
    return None


async def _try_pip_compile(repo_dir: str) -> Optional[list[Dependency]]:
    """Try running pip-compile for accurate Python resolution."""
    req_in = os.path.join(repo_dir, "requirements.in")
    req_txt = os.path.join(repo_dir, "requirements.txt")
    if not os.path.isfile(req_in) and not os.path.isfile(req_txt):
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            "pip-compile", "--dry-run", "--quiet",
            req_in if os.path.isfile(req_in) else req_txt,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            return None

        deps: list[Dependency] = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)==(.+)", line)
            if m:
                deps.append(Dependency(
                    name=m.group(1), version=m.group(2),
                    ecosystem="PyPI", manifest_path=req_txt,
                ))
        if deps:
            logger.info("pip-compile resolved %d dependencies", len(deps))
            return deps
    except Exception as exc:
        logger.debug("pip-compile failed (falling back to parse): %s", exc)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def resolve_dependencies(repo_dir: str) -> list[dict]:
    """Resolve all dependencies in a repository.

    Returns a list of dicts: {name, version, ecosystem, manifest_path, dev}.
    """
    manifests = _discover_manifests(repo_dir)
    logger.info("Found %d manifests in %s", len(manifests), repo_dir)

    all_deps: list[Dependency] = []
    ecosystems_resolved: set[str] = set()

    # Try tool-assisted resolution first
    npm_deps = await _try_npm_ls(repo_dir)
    if npm_deps:
        all_deps.extend(npm_deps)
        ecosystems_resolved.add("npm")

    pip_deps = await _try_pip_compile(repo_dir)
    if pip_deps:
        all_deps.extend(pip_deps)
        ecosystems_resolved.add("PyPI")

    # Parse remaining manifests
    for abs_path, ecosystem in manifests:
        if ecosystem in ecosystems_resolved:
            continue
        fname = os.path.basename(abs_path)
        parser_info = _PARSER_MAP.get(fname)
        if parser_info:
            parsed = parser_info["fn"](abs_path)
            all_deps.extend(parsed)
            logger.debug("Parsed %d deps from %s", len(parsed), abs_path)

    # Deduplicate by (ecosystem, name, version)
    seen: set[str] = set()
    unique: list[Dependency] = []
    for dep in all_deps:
        key = dep.key()
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    logger.info("Resolved %d unique dependencies across %d ecosystems",
                len(unique), len({d.ecosystem for d in unique}))

    return [
        {
            "name": d.name,
            "version": d.version,
            "ecosystem": d.ecosystem,
            "manifest_path": os.path.relpath(d.manifest_path, repo_dir),
            "dev": d.dev,
        }
        for d in unique
    ]
