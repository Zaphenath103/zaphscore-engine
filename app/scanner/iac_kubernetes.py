"""
ZSE IaC Kubernetes Scanner -- D-680: Security analysis for Kubernetes manifests.

Scans Kubernetes YAML manifests for security misconfigurations:
- Privileged containers
- Missing resource limits (CPU/memory)
- Running as root (runAsUser: 0 or missing runAsNonRoot)
- Missing liveness/readiness probes
- Latest image tags
- hostNetwork/hostPID/hostIPC enabled
- Missing securityContext
- Writable root filesystem
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _parse_yaml_simple(content: str) -> list[dict[str, Any]]:
    """Parse one or more YAML documents from content using minimal parser.

    Returns a list of parsed documents. Each document is a dict.
    Handles --- document separators.
    """
    docs = []
    # Split on YAML document separator
    raw_docs = re.split(r'^---\s*$', content, flags=re.MULTILINE)
    for raw in raw_docs:
        raw = raw.strip()
        if not raw:
            continue
        # Try JSON first (some K8s files are JSON)
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                docs.append(parsed)
            continue
        except json.JSONDecodeError:
            pass
        # Minimal YAML line-by-line key extraction
        doc = _parse_yaml_doc(raw)
        if doc:
            docs.append(doc)
    return docs


def _parse_yaml_doc(content: str) -> dict[str, Any]:
    """Parse a single YAML document into a nested dict using indentation."""
    lines = content.splitlines()
    result: dict[str, Any] = {}
    _yaml_lines_to_dict(lines, 0, result)
    return result


def _yaml_lines_to_dict(lines: list[str], base_indent: int, target: dict) -> int:
    """Recursively parse indented YAML lines into a dict. Returns lines consumed."""
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(stripped)
        if indent < base_indent:
            break
        if indent > base_indent:
            i += 1
            continue
        if stripped.startswith("- "):
            # List item at this level -- caller handles
            break
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if val:
                target[key] = _coerce_value(val)
                i += 1
            else:
                # Nested block
                child_lines = []
                j = i + 1
                child_indent = base_indent + 2
                # Find child indent
                while j < len(lines):
                    cl = lines[j].lstrip()
                    if cl and not cl.startswith("#"):
                        child_indent = len(lines[j]) - len(cl)
                        break
                    j += 1
                if child_indent <= base_indent:
                    target[key] = {}
                    i += 1
                    continue
                # Collect child lines
                end = j
                while end < len(lines):
                    cl = lines[end].lstrip()
                    ci = len(lines[end]) - len(cl) if cl else child_indent
                    if cl and not cl.startswith("#") and ci < child_indent:
                        break
                    end += 1
                child_block = lines[j:end]
                if child_block and child_block[0].lstrip().startswith("- "):
                    # It's a list
                    target[key] = _parse_yaml_list(child_block, child_indent)
                else:
                    child_dict: dict[str, Any] = {}
                    _yaml_lines_to_dict(child_block, child_indent, child_dict)
                    target[key] = child_dict
                i = end
        else:
            i += 1
    return i


def _parse_yaml_list(lines: list[str], base_indent: int) -> list[Any]:
    """Parse a YAML list block."""
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if stripped.startswith("- "):
            item_content = stripped[2:].strip()
            if item_content:
                # Inline value or start of inline dict
                if ":" in item_content and not item_content.startswith('"'):
                    item_dict: dict[str, Any] = {}
                    k, _, v = item_content.partition(":")
                    item_dict[k.strip()] = _coerce_value(v.strip())
                    # Check for more kv pairs in subsequent lines at same indent
                    j = i + 1
                    item_indent = len(line) - len(stripped) + 2
                    while j < len(lines):
                        nl = lines[j]
                        ns = nl.lstrip()
                        ni = len(nl) - len(ns) if ns else 0
                        if not ns or ns.startswith("#"):
                            j += 1
                            continue
                        if ni < item_indent or ns.startswith("- "):
                            break
                        if ":" in ns:
                            nk, _, nv = ns.partition(":")
                            item_dict[nk.strip()] = _coerce_value(nv.strip())
                        j += 1
                    result.append(item_dict)
                    i = j
                else:
                    result.append(_coerce_value(item_content))
                    i += 1
            else:
                result.append({})
                i += 1
        else:
            i += 1
    return result


def _coerce_value(val: str) -> Any:
    if not val or val in ("null", "~", "Null", "NULL"):
        return None
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val.strip('"\'')


def _get_containers(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all containers (including initContainers) from a pod spec."""
    containers = spec.get("containers", [])
    if not isinstance(containers, list):
        containers = []
    init_containers = spec.get("initContainers", [])
    if not isinstance(init_containers, list):
        init_containers = []
    return containers + init_containers


def _get_pod_spec(manifest: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Extract pod spec from any K8s workload manifest."""
    kind = manifest.get("kind", "")
    spec = manifest.get("spec", {})
    if not isinstance(spec, dict):
        return None

    if kind == "Pod":
        return spec
    # Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs, CronJobs
    template = spec.get("template", {})
    if isinstance(template, dict):
        template_spec = template.get("spec", {})
        if isinstance(template_spec, dict):
            return template_spec
    # CronJob has spec.jobTemplate.spec.template.spec
    job_template = spec.get("jobTemplate", {})
    if isinstance(job_template, dict):
        job_spec = job_template.get("spec", {})
        if isinstance(job_spec, dict):
            tmpl = job_spec.get("template", {})
            if isinstance(tmpl, dict):
                return tmpl.get("spec", {})
    return None


def scan_k8s_manifest(manifest_path: str) -> list[dict[str, Any]]:
    """Scan a Kubernetes manifest file for security misconfigurations.

    Args:
        manifest_path: Absolute path to a Kubernetes YAML or JSON manifest.

    Returns:
        List of finding dicts with keys: rule_id, resource, kind, message, severity, file.
    """
    path = Path(manifest_path)
    if not path.exists():
        logger.warning("K8s manifest not found: %s", manifest_path)
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.error("Cannot read manifest %s: %s", manifest_path, exc)
        return []

    docs = _parse_yaml_simple(content)
    all_findings: list[dict[str, Any]] = []

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "Unknown")
        name = ""
        metadata = doc.get("metadata", {})
        if isinstance(metadata, dict):
            name = metadata.get("name", "")

        resource_id = "{}/{}".format(kind, name) if name else kind
        findings = _check_manifest(doc, resource_id, manifest_path)
        all_findings.extend(findings)

    logger.info("K8s manifest scan %s: %d findings", manifest_path, len(all_findings))
    return all_findings


def _check_manifest(manifest: dict[str, Any], resource_id: str, file_path: str) -> list[dict[str, Any]]:
    """Run all security checks on a single K8s manifest document."""
    findings: list[dict[str, Any]] = []
    kind = manifest.get("kind", "")

    # Pod-level checks
    pod_spec = _get_pod_spec(manifest)
    if pod_spec and isinstance(pod_spec, dict):
        # hostNetwork/hostPID/hostIPC
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(flag) is True:
                findings.append({
                    "rule_id": "K8sHost{}".format(flag[4:]),
                    "resource": resource_id,
                    "kind": kind,
                    "message": "{} has {} enabled, sharing host namespace.".format(resource_id, flag),
                    "severity": "high",
                    "file": file_path,
                })

        containers = _get_containers(pod_spec)
        for container in containers:
            if not isinstance(container, dict):
                continue
            cname = container.get("name", "unknown")
            cid = "{}/container:{}".format(resource_id, cname)
            findings.extend(_check_container(container, cid, file_path))

    return findings


def _check_container(container: dict[str, Any], cid: str, file_path: str) -> list[dict[str, Any]]:
    """Check a single container for security issues."""
    findings: list[dict[str, Any]] = []

    # Privileged
    sc = container.get("securityContext", {})
    if not isinstance(sc, dict):
        sc = {}

    if sc.get("privileged") is True:
        findings.append({
            "rule_id": "K8sPrivilegedContainer",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} is running in privileged mode.".format(cid),
            "severity": "critical",
            "file": file_path,
        })

    # runAsRoot
    run_as_user = sc.get("runAsUser")
    run_as_non_root = sc.get("runAsNonRoot")
    if run_as_user == 0:
        findings.append({
            "rule_id": "K8sRunAsRoot",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} explicitly runs as root (runAsUser: 0).".format(cid),
            "severity": "high",
            "file": file_path,
        })
    elif run_as_non_root is not True and run_as_user is None:
        findings.append({
            "rule_id": "K8sMissingRunAsNonRoot",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} does not set runAsNonRoot or runAsUser, may run as root.".format(cid),
            "severity": "medium",
            "file": file_path,
        })

    # Writable root filesystem
    if sc.get("readOnlyRootFilesystem") is False or sc.get("readOnlyRootFilesystem") is None:
        findings.append({
            "rule_id": "K8sWritableRootFS",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} does not set readOnlyRootFilesystem: true.".format(cid),
            "severity": "low",
            "file": file_path,
        })

    # Missing resource limits
    resources = container.get("resources", {})
    if not isinstance(resources, dict):
        resources = {}
    limits = resources.get("limits", {})
    if not isinstance(limits, dict) or not limits:
        findings.append({
            "rule_id": "K8sMissingResourceLimits",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} has no resource limits defined.".format(cid),
            "severity": "medium",
            "file": file_path,
        })

    # Latest image tag
    image = container.get("image", "")
    if isinstance(image, str):
        if image.endswith(":latest") or (":" not in image and "@" not in image):
            findings.append({
                "rule_id": "K8sLatestImageTag",
                "resource": cid,
                "kind": "Container",
                "message": "Container {} uses mutable/latest image tag: {}.".format(cid, image),
                "severity": "low",
                "file": file_path,
            })

    # Missing liveness probe
    if not container.get("livenessProbe"):
        findings.append({
            "rule_id": "K8sMissingLivenessProbe",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} has no livenessProbe configured.".format(cid),
            "severity": "info",
            "file": file_path,
        })

    # Missing readiness probe
    if not container.get("readinessProbe"):
        findings.append({
            "rule_id": "K8sMissingReadinessProbe",
            "resource": cid,
            "kind": "Container",
            "message": "Container {} has no readinessProbe configured.".format(cid),
            "severity": "info",
            "file": file_path,
        })

    return findings


def scan_k8s_directory(manifests_dir: str) -> list[dict[str, Any]]:
    """Scan all Kubernetes manifests in a directory recursively.

    Args:
        manifests_dir: Directory containing K8s YAML/JSON manifests.

    Returns:
        Aggregated list of findings.
    """
    dir_path = Path(manifests_dir)
    if not dir_path.is_dir():
        logger.warning("K8s manifests directory not found: %s", manifests_dir)
        return []

    all_findings: list[dict[str, Any]] = []
    _SKIP = {".git", "node_modules", "__pycache__", "vendor"}
    for ext in ("*.yaml", "*.yml", "*.json"):
        for mf in dir_path.rglob(ext):
            if any(p in mf.parts for p in _SKIP):
                continue
            all_findings.extend(scan_k8s_manifest(str(mf)))

    logger.info("K8s dir scan %s: %d total findings", manifests_dir, len(all_findings))
    return all_findings
