"""
ZSE IaC Drift Scanner -- D-682: Infrastructure configuration drift detection.

Compares a desired (declared) infrastructure state against an actual (live)
state dict, producing DriftRecord entries for each field that has diverged.

Supports nested dicts and lists with recursive comparison.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class DriftType(str, Enum):
    """Category of detected drift."""
    modified = "modified"   # Field value changed
    added = "added"         # Field present in actual but not desired
    removed = "removed"     # Field present in desired but not in actual
    type_changed = "type_changed"  # Field type differs (e.g., str vs int)


@dataclass
class DriftRecord:
    """Single field-level drift between desired and actual state.

    Attributes:
        resource_id: Identifier for the resource being compared (e.g., "aws_s3_bucket.logs").
        field_path: Dot-separated path to the drifted field (e.g., "properties.encryption.enabled").
        drift_type: Category of drift (modified, added, removed, type_changed).
        desired_value: The value declared in the desired state (None if added).
        actual_value: The value found in the actual state (None if removed).
        severity: Assessed severity of the drift (critical/high/medium/low/info).
        description: Human-readable description of the drift.
    """
    resource_id: str
    field_path: str
    drift_type: DriftType
    desired_value: Any
    actual_value: Any
    severity: str = "medium"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "field_path": self.field_path,
            "drift_type": self.drift_type.value,
            "desired_value": self.desired_value,
            "actual_value": self.actual_value,
            "severity": self.severity,
            "description": self.description,
        }


# Fields that indicate security-critical drift (higher severity)
_SECURITY_SENSITIVE_FIELDS = frozenset({
    "encryption",
    "encrypted",
    "kms_key_id",
    "kms_key_arn",
    "ssl_enforcement_enabled",
    "https_only",
    "publicly_accessible",
    "public_access",
    "access_control",
    "acl",
    "policy",
    "iam_policy",
    "security_group",
    "security_groups",
    "ingress",
    "egress",
    "allow_all",
    "open",
    "password",
    "auth",
    "authentication",
    "tls",
    "ssl",
    "certificate",
    "logging",
    "audit",
    "retention",
    "backup",
    "deletion_protection",
})

_INFO_FIELDS = frozenset({
    "tags",
    "labels",
    "annotations",
    "description",
    "name",
    "display_name",
    "comment",
})


def _assess_severity(field_path: str, drift_type: DriftType) -> str:
    """Assess the severity of a drift based on the field name and drift type."""
    # Extract leaf field name from path
    leaf = field_path.split(".")[-1].lower()
    # Also check all segments for security sensitivity
    segments = {seg.lower() for seg in field_path.split(".")}

    if any(s in _SECURITY_SENSITIVE_FIELDS for s in segments):
        if drift_type == DriftType.removed:
            return "critical"
        return "high"
    if any(s in _INFO_FIELDS for s in segments):
        return "info"
    if drift_type == DriftType.type_changed:
        return "high"
    if drift_type == DriftType.added:
        return "low"
    if drift_type == DriftType.removed:
        return "medium"
    return "medium"


def _build_description(
    resource_id: str,
    field_path: str,
    drift_type: DriftType,
    desired: Any,
    actual: Any,
) -> str:
    """Build a human-readable drift description."""
    if drift_type == DriftType.modified:
        return (
            "Resource '{}' field '{}' has drifted: desired={!r}, actual={!r}.".format(
                resource_id, field_path, desired, actual
            )
        )
    if drift_type == DriftType.added:
        return (
            "Resource '{}' has unexpected field '{}' (actual={!r}) not in desired state.".format(
                resource_id, field_path, actual
            )
        )
    if drift_type == DriftType.removed:
        return (
            "Resource '{}' field '{}' (desired={!r}) is missing from actual state.".format(
                resource_id, field_path, desired
            )
        )
    if drift_type == DriftType.type_changed:
        return (
            "Resource '{}' field '{}' type changed: desired={} ({!r}), actual={} ({!r}).".format(
                resource_id, field_path,
                type(desired).__name__, desired,
                type(actual).__name__, actual,
            )
        )
    return "Drift detected in resource '{}' at '{}'.".format(resource_id, field_path)


def _compare_values(
    resource_id: str,
    path: str,
    desired: Any,
    actual: Any,
    records: list[DriftRecord],
    ignore_paths: Optional[set[str]] = None,
) -> None:
    """Recursively compare desired vs actual values, appending DriftRecords."""
    if ignore_paths and path in ignore_paths:
        return

    # Both dicts: recurse
    if isinstance(desired, dict) and isinstance(actual, dict):
        all_keys = set(desired.keys()) | set(actual.keys())
        for key in sorted(all_keys):
            child_path = "{}.{}".format(path, key) if path else key
            if key in desired and key in actual:
                _compare_values(resource_id, child_path, desired[key], actual[key], records, ignore_paths)
            elif key in desired:
                # Key removed from actual
                sev = _assess_severity(child_path, DriftType.removed)
                desc = _build_description(resource_id, child_path, DriftType.removed, desired[key], None)
                records.append(DriftRecord(
                    resource_id=resource_id,
                    field_path=child_path,
                    drift_type=DriftType.removed,
                    desired_value=desired[key],
                    actual_value=None,
                    severity=sev,
                    description=desc,
                ))
            else:
                # Key added in actual
                sev = _assess_severity(child_path, DriftType.added)
                desc = _build_description(resource_id, child_path, DriftType.added, None, actual[key])
                records.append(DriftRecord(
                    resource_id=resource_id,
                    field_path=child_path,
                    drift_type=DriftType.added,
                    desired_value=None,
                    actual_value=actual[key],
                    severity=sev,
                    description=desc,
                ))
        return

    # Type change (both non-None, different types, not dict comparison above)
    if desired is not None and actual is not None and type(desired) != type(actual):
        # Allow int/float coercion without flagging
        if isinstance(desired, (int, float)) and isinstance(actual, (int, float)):
            if desired == actual:
                return
        sev = _assess_severity(path, DriftType.type_changed)
        desc = _build_description(resource_id, path, DriftType.type_changed, desired, actual)
        records.append(DriftRecord(
            resource_id=resource_id,
            field_path=path,
            drift_type=DriftType.type_changed,
            desired_value=desired,
            actual_value=actual,
            severity=sev,
            description=desc,
        ))
        return

    # List comparison: compare element by element (positional)
    if isinstance(desired, list) and isinstance(actual, list):
        max_len = max(len(desired), len(actual))
        for idx in range(max_len):
            child_path = "{}[{}]".format(path, idx)
            if idx < len(desired) and idx < len(actual):
                _compare_values(resource_id, child_path, desired[idx], actual[idx], records, ignore_paths)
            elif idx < len(desired):
                sev = _assess_severity(child_path, DriftType.removed)
                desc = _build_description(resource_id, child_path, DriftType.removed, desired[idx], None)
                records.append(DriftRecord(
                    resource_id=resource_id,
                    field_path=child_path,
                    drift_type=DriftType.removed,
                    desired_value=desired[idx],
                    actual_value=None,
                    severity=sev,
                    description=desc,
                ))
            else:
                sev = _assess_severity(child_path, DriftType.added)
                desc = _build_description(resource_id, child_path, DriftType.added, None, actual[idx])
                records.append(DriftRecord(
                    resource_id=resource_id,
                    field_path=child_path,
                    drift_type=DriftType.added,
                    desired_value=None,
                    actual_value=actual[idx],
                    severity=sev,
                    description=desc,
                ))
        return

    # Scalar comparison
    if desired != actual:
        sev = _assess_severity(path, DriftType.modified)
        desc = _build_description(resource_id, path, DriftType.modified, desired, actual)
        records.append(DriftRecord(
            resource_id=resource_id,
            field_path=path,
            drift_type=DriftType.modified,
            desired_value=desired,
            actual_value=actual,
            severity=sev,
            description=desc,
        ))


def detect_drift(
    desired_state: dict[str, Any],
    actual_state: dict[str, Any],
    resource_id: str = "resource",
    ignore_paths: Optional[set[str]] = None,
) -> list[DriftRecord]:
    """Detect configuration drift between desired and actual infrastructure state.

    Performs a deep recursive comparison of two state dicts. Each difference
    produces a DriftRecord describing the field path, drift type, values, and
    assessed severity.

    Args:
        desired_state: The declared/expected state (e.g., from Terraform plan or CF template).
        actual_state: The observed/live state (e.g., from cloud provider API).
        resource_id: Identifier string for the resource (used in descriptions).
        ignore_paths: Optional set of dot-separated field paths to skip during comparison.

    Returns:
        List of DriftRecord objects, one per diverged field.
    """
    if not isinstance(desired_state, dict):
        raise TypeError("desired_state must be a dict, got {}".format(type(desired_state).__name__))
    if not isinstance(actual_state, dict):
        raise TypeError("actual_state must be a dict, got {}".format(type(actual_state).__name__))

    records: list[DriftRecord] = []
    _compare_values(resource_id, "", desired_state, actual_state, records, ignore_paths)
    # Strip leading dot from paths (artifact of empty root path)
    for r in records:
        r.field_path = r.field_path.lstrip(".")

    logger.info(
        "Drift detection for '%s': %d drift records found",
        resource_id, len(records)
    )
    return records


def detect_drift_multi(
    desired_states: dict[str, dict[str, Any]],
    actual_states: dict[str, dict[str, Any]],
    ignore_paths: Optional[set[str]] = None,
) -> dict[str, list[DriftRecord]]:
    """Detect drift across multiple resources at once.

    Args:
        desired_states: Dict mapping resource_id -> desired state dict.
        actual_states: Dict mapping resource_id -> actual state dict.
        ignore_paths: Field paths to skip for all resources.

    Returns:
        Dict mapping resource_id -> list of DriftRecord. Resources present in
        desired but absent from actual are reported as fully removed, and vice versa.
    """
    results: dict[str, list[DriftRecord]] = {}
    all_ids = set(desired_states.keys()) | set(actual_states.keys())

    for resource_id in sorted(all_ids):
        desired = desired_states.get(resource_id)
        actual = actual_states.get(resource_id)

        if desired is None:
            # Resource exists in actual but not desired -- unexpected addition
            results[resource_id] = [
                DriftRecord(
                    resource_id=resource_id,
                    field_path="<resource>",
                    drift_type=DriftType.added,
                    desired_value=None,
                    actual_value=actual,
                    severity="medium",
                    description="Resource '{}' exists in actual state but not in desired state.".format(resource_id),
                )
            ]
        elif actual is None:
            # Resource declared but not found in actual -- removed/missing
            results[resource_id] = [
                DriftRecord(
                    resource_id=resource_id,
                    field_path="<resource>",
                    drift_type=DriftType.removed,
                    desired_value=desired,
                    actual_value=None,
                    severity="high",
                    description="Resource '{}' declared in desired state but not found in actual state.".format(resource_id),
                )
            ]
        else:
            results[resource_id] = detect_drift(desired, actual, resource_id, ignore_paths)

    return results


def drift_summary(records: list[DriftRecord]) -> dict[str, Any]:
    """Generate a summary dict from a list of DriftRecords.

    Returns:
        Dict with total, by_type, by_severity, and has_drift keys.
    """
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in records:
        by_type[r.drift_type.value] = by_type.get(r.drift_type.value, 0) + 1
        by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
    return {
        "total": len(records),
        "has_drift": len(records) > 0,
        "by_type": by_type,
        "by_severity": by_severity,
    }
