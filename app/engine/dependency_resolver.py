"""
ZSE Dependency Resolver — parse every major manifest format, with optional
tool-assisted resolution (npm ls, pip-compile).

D-763: install_script_detection -- flags npm packages with postinstall/preinstall scripts.
D-764: typosquatting_detection -- Levenshtein distance check vs popular package names.
D-765: protestware_detection -- flags packages matching known protestware CVE/name patterns.
D-767: supply_chain_signals -- aggregates multiple behavioural risk signals per package.
D-770: deprecated_package_check -- queries npm registry for deprecation notices.
D-771: new_package_history_check -- flags packages published within the last 30 days.
D-801: private_registry_support -- reads .npmrc for private registry configuration.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from xml.etree import ElementTree

import aiohttp

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


# ---------------------------------------------------------------------------
# D-801: Private registry support
# ---------------------------------------------------------------------------

def _read_npmrc_registries(repo_dir: str) -> dict[str, str]:
    """D-801: Parse .npmrc for private registry mappings.

    Returns {scope_or_global: registry_url} dict.
    Example .npmrc:
        @mycompany:registry=https://npm.mycompany.com/
        //npm.mycompany.com/:_authToken=${NPM_TOKEN}
    """
    registries: dict[str, str] = {}
    for npmrc_path in [
        os.path.join(repo_dir, ".npmrc"),
        os.path.expanduser("~/.npmrc"),
    ]:
        if not os.path.isfile(npmrc_path):
            continue
        try:
            with open(npmrc_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # @scope:registry=URL  or  registry=URL
                    m = re.match(r"^(@[^:]+):registry\s*=\s*(.+)$", line)
                    if m:
                        registries[m.group(1)] = m.group(2).strip()
                        continue
                    m = re.match(r"^registry\s*=\s*(.+)$", line)
                    if m:
                        registries["*"] = m.group(1).strip()
        except Exception as exc:
            logger.debug("Failed to parse %s: %s", npmrc_path, exc)
    return registries


def get_npm_registry_for_package(package_name: str, repo_dir: str) -> str:
    """D-801: Return the npm registry URL for a given package name.

    Checks .npmrc for scope-specific registry overrides. Falls back to
    the public npm registry.
    """
    registries = _read_npmrc_registries(repo_dir)
    if package_name.startswith("@"):
        scope = package_name.split("/")[0]  # e.g. @mycompany
        if scope in registries:
            return registries[scope].rstrip("/")
    if "*" in registries:
        return registries["*"].rstrip("/")
    return "https://registry.npmjs.org"


# ---------------------------------------------------------------------------
# Supply chain signal analysis (D-763, D-764, D-765, D-767, D-770, D-771)
# ---------------------------------------------------------------------------

# D-764: Popular npm package names for typosquatting comparison.
# Extended list of the most-downloaded npm packages.
_POPULAR_NPM_PACKAGES: frozenset[str] = frozenset([
    "lodash", "express", "react", "react-dom", "vue", "angular",
    "webpack", "babel-core", "typescript", "axios", "moment",
    "chalk", "commander", "request", "async", "underscore",
    "jquery", "bootstrap", "next", "gatsby", "svelte",
    "prettier", "eslint", "jest", "mocha", "chai",
    "dotenv", "nodemon", "cors", "helmet", "morgan",
    "socket.io", "mongoose", "sequelize", "knex", "redis",
    "pg", "mysql", "mongodb", "faker", "uuid",
    "classnames", "prop-types", "redux", "mobx", "zustand",
    "tailwindcss", "sass", "postcss", "autoprefixer",
    "cross-env", "rimraf", "cpx", "mkdirp", "glob",
    "semver", "minimist", "yargs", "inquirer", "ora",
    "colors", "debug", "winston", "pino", "bunyan",
    "bluebird", "rxjs", "immutable", "immer", "ramda",
    "date-fns", "dayjs", "luxon", "numeral", "accounting",
    "sharp", "jimp", "multer", "formidable", "busboy",
    "node-fetch", "got", "superagent", "needle", "node-http",
    "passport", "jsonwebtoken", "bcrypt", "crypto-js",
    "xml2js", "cheerio", "puppeteer", "playwright", "selenium",
    "lodash-es", "core-js", "regenerator-runtime", "tslib",
])

# D-765: Known protestware package names/patterns
_KNOWN_PROTESTWARE: frozenset[str] = frozenset([
    "colors", "faker", "node-ipc", "peacenotwar",
    "event-source-polyfill",  # had malicious injection
])

# D-765: CVE IDs associated with protestware
_PROTESTWARE_CVES: frozenset[str] = frozenset([
    "CVE-2022-23812",  # node-ipc / peacenotwar
    "CVE-2022-21803",  # node-ipc
])


def _levenshtein_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Standard DP approach
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + cost))
        prev = curr
    return prev[len(b)]


def detect_typosquat(package_name: str, ecosystem: str) -> Optional[dict]:
    """D-764: Check if a package name is suspiciously close to a popular package.

    Returns a signal dict if a potential typosquat is detected, else None.
    """
    if ecosystem != "npm":
        return None

    # Strip scope for comparison
    name = package_name.split("/")[-1] if "/" in package_name else package_name
    name_lower = name.lower()

    for popular in _POPULAR_NPM_PACKAGES:
        if name_lower == popular:
            return None  # Exact match -- not a typosquat
        dist = _levenshtein_distance(name_lower, popular)
        # Flag if edit distance is 1 or 2 and the name isn't a known variant
        if 1 <= dist <= 2 and len(name_lower) >= 4:
            return {
                "type": "typosquatting",
                "severity": "high",
                "title": f"Possible typosquat: {package_name} resembles {popular} (edit dist={dist})",
                "package": package_name,
                "similar_to": popular,
                "edit_distance": dist,
            }
    return None


def detect_protestware(package_name: str) -> Optional[dict]:
    """D-765: Check if a package is a known protestware package."""
    name_lower = package_name.lower().split("/")[-1]
    if name_lower in _KNOWN_PROTESTWARE:
        return {
            "type": "protestware",
            "severity": "critical",
            "title": f"Known protestware package: {package_name}",
            "package": package_name,
            "note": (
                f"{package_name} has been associated with protestware modifications "
                f"that intentionally damaged systems. Audit the exact version in use "
                f"and check for unexpected behaviour."
            ),
        }
    return None


async def check_npm_install_scripts(
    session: aiohttp.ClientSession,
    package_name: str,
    version: str,
    registry_url: str = "https://registry.npmjs.org",
) -> Optional[dict]:
    """D-763: Check if an npm package has install scripts (postinstall, preinstall).

    Fetches package metadata from the npm registry and inspects the scripts field.
    Returns a signal dict if install scripts are present, else None.
    """
    try:
        url = f"{registry_url.rstrip('/')}/{package_name}/{version}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            scripts = data.get("scripts") or {}
            dangerous_scripts = [
                s for s in ("preinstall", "install", "postinstall")
                if s in scripts
            ]
            if dangerous_scripts:
                return {
                    "type": "install_script",
                    "severity": "high",
                    "title": f"npm package {package_name}@{version} has install scripts: {dangerous_scripts}",
                    "package": package_name,
                    "version": version,
                    "scripts": {s: scripts[s] for s in dangerous_scripts},
                    "note": (
                        "Install scripts execute arbitrary code during npm install. "
                        "Review the script content carefully before trusting this package."
                    ),
                }
    except Exception as exc:
        logger.debug("Failed to check install scripts for %s@%s: %s", package_name, version, exc)
    return None


async def check_npm_deprecation(
    session: aiohttp.ClientSession,
    package_name: str,
    version: str,
    registry_url: str = "https://registry.npmjs.org",
) -> Optional[dict]:
    """D-770: Check if an npm package or specific version is deprecated.

    Returns a signal dict if deprecated, else None.
    """
    try:
        url = f"{registry_url.rstrip('/')}/{package_name}/{version}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            deprecated = data.get("deprecated")
            if deprecated:
                return {
                    "type": "deprecated",
                    "severity": "medium",
                    "title": f"npm package {package_name}@{version} is deprecated",
                    "package": package_name,
                    "version": version,
                    "deprecation_message": str(deprecated)[:500],
                }
    except Exception as exc:
        logger.debug("Failed to check deprecation for %s@%s: %s", package_name, version, exc)
    return None


async def check_npm_publish_age(
    session: aiohttp.ClientSession,
    package_name: str,
    version: str,
    registry_url: str = "https://registry.npmjs.org",
    max_age_days: int = 30,
) -> Optional[dict]:
    """D-771: Check if an npm package version was published very recently.

    New packages with no prior release history are high-risk supply chain targets.
    Returns a signal dict if the package is younger than max_age_days, else None.
    """
    try:
        url = f"{registry_url.rstrip('/')}/{package_name}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            time_data = data.get("time") or {}
            # Check first published date (the 'created' key)
            created_str = time_data.get("created", "")
            if created_str:
                created = datetime.datetime.fromisoformat(
                    created_str.replace("Z", "+00:00")
                )
                age_days = (datetime.datetime.now(datetime.timezone.utc) - created).days
                total_versions = len([k for k in time_data if k not in ("created", "modified")])
                if age_days <= max_age_days:
                    return {
                        "type": "new_package",
                        "severity": "medium",
                        "title": (
                            f"npm package {package_name} is {age_days} days old "
                            f"({total_versions} version(s)) -- no release history"
                        ),
                        "package": package_name,
                        "version": version,
                        "age_days": age_days,
                        "total_versions": total_versions,
                        "note": (
                            "Packages published within the last 30 days have no track record. "
                            "Verify the publisher identity and review the package source before use."
                        ),
                    }
    except Exception as exc:
        logger.debug("Failed to check publish age for %s: %s", package_name, exc)
    return None


async def analyze_supply_chain_signals(
    dependencies: list[dict],
    repo_dir: str = "",
) -> list[dict]:
    """D-767: Run all supply chain signal checks against npm dependencies.

    Runs: typosquatting (D-764), protestware (D-765), install scripts (D-763),
    deprecation (D-770), new package age (D-771) checks.

    Returns list of signal dicts, each with keys:
        type, severity, title, package, [additional context keys]
    """
    signals: list[dict] = []
    npm_deps = [d for d in dependencies if d.get("ecosystem") == "npm"]

    if not npm_deps:
        return signals

    # Static checks (no network required)
    for dep in npm_deps:
        name = dep.get("name", "")

        # D-764: Typosquatting
        typo_signal = detect_typosquat(name, "npm")
        if typo_signal:
            signals.append(typo_signal)

        # D-765: Protestware
        protest_signal = detect_protestware(name)
        if protest_signal:
            signals.append(protest_signal)

    # Network checks (batched, rate-limited to 5 concurrent)
    sem = asyncio.Semaphore(5)
    timeout = aiohttp.ClientTimeout(total=120)

    async def _check_one(dep: dict) -> list[dict]:
        name = dep.get("name", "")
        version = dep.get("version", "")
        if not name or not version or version == "*":
            return []
        registry = get_npm_registry_for_package(name, repo_dir) if repo_dir else "https://registry.npmjs.org"
        found: list[dict] = []
        async with sem:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # D-763: Install scripts
                script_signal = await check_npm_install_scripts(session, name, version, registry)
                if script_signal:
                    found.append(script_signal)
                # D-770: Deprecation
                dep_signal = await check_npm_deprecation(session, name, version, registry)
                if dep_signal:
                    found.append(dep_signal)
                # D-771: New package
                age_signal = await check_npm_publish_age(session, name, version, registry)
                if age_signal:
                    found.append(age_signal)
        return found

    tasks = [_check_one(dep) for dep in npm_deps]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            signals.extend(result)
        elif isinstance(result, Exception):
            logger.debug("Supply chain signal check failed: %s", result)

    logger.info(
        "Supply chain analysis: %d signals detected from %d npm packages",
        len(signals), len(npm_deps),
    )
    return signals
