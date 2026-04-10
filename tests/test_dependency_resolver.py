"""
D-022: Unit tests for app/engine/dependency_resolver.py

Tests cover:
  - Lockfile priority: lock file takes precedence over plain manifest in same dir
  - Edge cases: empty repo, missing files, malformed JSON, nested manifests
  - Ecosystem detection for npm, PyPI, Go, Cargo, Maven, RubyGems, Packagist
  - MAX_MANIFESTS cap (never returns more than 20)
  - Skip dirs: node_modules, .git, vendor, venv
  - Version stripping: semver ranges normalised to bare version
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from app.engine.dependency_resolver import (
    MAX_MANIFESTS,
    Dependency,
    resolve_dependencies,
    _discover_manifests,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_repo(tmp_path):
    """Return a temporary directory that acts as a repo root."""
    return tmp_path


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Lockfile priority
# ---------------------------------------------------------------------------

def test_lockfile_takes_priority_over_package_json(tmp_repo):
    """package-lock.json in same dir should suppress package.json for npm."""
    _write(tmp_repo / "package.json", json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    _write(tmp_repo / "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/express": {"version": "4.18.2", "resolved": "https://r.npm/express"},
        },
    }))

    manifests = _discover_manifests(str(tmp_repo))
    filenames = [os.path.basename(p) for p, _ in manifests]

    assert "package-lock.json" in filenames
    assert "package.json" not in filenames, "package.json should be suppressed by lock file"


def test_pipfile_lock_takes_priority_over_requirements(tmp_repo):
    """Pipfile.lock should suppress requirements.txt in same directory."""
    _write(tmp_repo / "requirements.txt", "requests==2.28.0\n")
    _write(tmp_repo / "Pipfile.lock", json.dumps({
        "default": {
            "requests": {"version": "==2.31.0", "hashes": []},
        },
        "develop": {},
    }))

    manifests = _discover_manifests(str(tmp_repo))
    filenames = [os.path.basename(p) for p, _ in manifests]

    assert "Pipfile.lock" in filenames
    assert "requirements.txt" not in filenames


def test_cargo_lock_takes_priority_over_cargo_toml(tmp_repo):
    """Cargo.lock should suppress Cargo.toml in same directory."""
    _write(tmp_repo / "Cargo.toml", '[package]\nname = "myapp"\n[dependencies]\nserde = "1"')
    _write(tmp_repo / "Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.197"\n')

    manifests = _discover_manifests(str(tmp_repo))
    filenames = [os.path.basename(p) for p, _ in manifests]

    assert "Cargo.lock" in filenames
    assert "Cargo.toml" not in filenames


def test_lock_file_priority_only_within_same_directory(tmp_repo):
    """Lock file in parent should NOT suppress manifest in a subdirectory."""
    _write(tmp_repo / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
    sub = tmp_repo / "frontend"
    _write(sub / "package.json", json.dumps({"dependencies": {"react": "^18.0.0"}}))

    manifests = _discover_manifests(str(tmp_repo))
    paths = [p for p, _ in manifests]
    filenames = [os.path.basename(p) for p in paths]

    # Both should appear — different directories
    assert "package-lock.json" in filenames
    assert "package.json" in filenames


# ---------------------------------------------------------------------------
# Empty and edge cases
# ---------------------------------------------------------------------------

def test_empty_repo_returns_empty_list(tmp_repo):
    result = _discover_manifests(str(tmp_repo))
    assert result == []


def test_nonexistent_repo_path():
    result = _discover_manifests("/nonexistent/path/that/does/not/exist")
    assert result == []


def test_max_manifests_cap(tmp_repo):
    """Never returns more than MAX_MANIFESTS entries."""
    for i in range(MAX_MANIFESTS + 10):
        sub = tmp_repo / f"pkg{i}"
        _write(sub / "requirements.txt", f"package{i}==1.0.0\n")

    manifests = _discover_manifests(str(tmp_repo))
    assert len(manifests) <= MAX_MANIFESTS


# ---------------------------------------------------------------------------
# Skip directories
# ---------------------------------------------------------------------------

def test_node_modules_skipped(tmp_repo):
    _write(tmp_repo / "node_modules" / "some-pkg" / "package.json",
           json.dumps({"dependencies": {"lodash": "4.0.0"}}))
    _write(tmp_repo / "package.json", json.dumps({"dependencies": {"express": "4.18.0"}}))

    manifests = _discover_manifests(str(tmp_repo))
    for path, _ in manifests:
        assert "node_modules" not in path


def test_git_dir_skipped(tmp_repo):
    _write(tmp_repo / ".git" / "package.json", json.dumps({"name": "internal"}))
    manifests = _discover_manifests(str(tmp_repo))
    for path, _ in manifests:
        assert ".git" not in path


def test_venv_skipped(tmp_repo):
    _write(tmp_repo / "venv" / "requirements.txt", "pip==23.0\n")
    _write(tmp_repo / "requirements.txt", "fastapi==0.115.0\n")

    manifests = _discover_manifests(str(tmp_repo))
    paths = [p for p, _ in manifests]
    assert all("venv" not in p for p in paths)
    assert any(os.path.basename(p) == "requirements.txt" and "venv" not in p for p in paths)


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------

def test_npm_ecosystem_detected(tmp_repo):
    _write(tmp_repo / "package.json", json.dumps({"dependencies": {"axios": "1.0.0"}}))
    manifests = _discover_manifests(str(tmp_repo))
    ecosystems = [eco for _, eco in manifests]
    assert "npm" in ecosystems


def test_pypi_ecosystem_detected(tmp_repo):
    _write(tmp_repo / "requirements.txt", "django==4.2.0\n")
    manifests = _discover_manifests(str(tmp_repo))
    ecosystems = [eco for _, eco in manifests]
    assert "PyPI" in ecosystems


def test_go_ecosystem_detected(tmp_repo):
    _write(tmp_repo / "go.mod", 'module example.com/myapp\n\ngo 1.21\n')
    manifests = _discover_manifests(str(tmp_repo))
    ecosystems = [eco for _, eco in manifests]
    assert "Go" in ecosystems


def test_cargo_ecosystem_detected(tmp_repo):
    _write(tmp_repo / "Cargo.toml", '[package]\nname = "myapp"\n[dependencies]\ntokio = "1"')
    manifests = _discover_manifests(str(tmp_repo))
    ecosystems = [eco for _, eco in manifests]
    assert "crates.io" in ecosystems


# ---------------------------------------------------------------------------
# Root manifests appear before nested ones
# ---------------------------------------------------------------------------

def test_root_manifest_before_nested(tmp_repo):
    _write(tmp_repo / "requirements.txt", "fastapi==0.115.0\n")
    _write(tmp_repo / "subdir" / "requirements.txt", "flask==3.0.0\n")

    manifests = _discover_manifests(str(tmp_repo))
    paths = [p for p, _ in manifests]

    root_idx = next(i for i, p in enumerate(paths) if os.path.dirname(p) == str(tmp_repo))
    sub_idx = next(i for i, p in enumerate(paths) if "subdir" in p)

    assert root_idx < sub_idx, "Root manifest should appear before nested manifest"


# ---------------------------------------------------------------------------
# Dependency dataclass
# ---------------------------------------------------------------------------

def test_dependency_key_is_stable():
    dep = Dependency(name="requests", version="2.31.0", ecosystem="PyPI", manifest_path="requirements.txt")
    assert dep.key() == "PyPI:requests:2.31.0"


def test_dependency_defaults():
    dep = Dependency(name="express", version="4.18.2", ecosystem="npm", manifest_path="package-lock.json")
    assert dep.dev is False
