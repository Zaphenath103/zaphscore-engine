"""
ZSE Audit Log Service -- SOC2-grade immutable audit trail.

D-718: Append-only SOC2 audit log for scan trigger actions.
       Every scan submission, status change, and access event is recorded
       with actor identity, timestamp, IP, action type, and chain hash.
D-722: Immutable finding suppression log with chain-hash tamper detection.
       Suppression actions are written with full context (who, when, why, IP).

Design:
  - Records are INSERT-only: no UPDATE or DELETE ever issued.
  - sha256 chain hash links each record to the previous for tamper-evidence.
  - Fail-open: DB write failure logs at ERROR but does not block the action.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("zse.audit_log")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _chain_hash(previous_hash: Optional[str], record: dict) -> str:
    """sha256(previous_hash || canonical_json(record)) for tamper detection."""
    prev = previous_hash or ("0" * 64)
    payload = prev + json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditAction:
    SCAN_SUBMITTED = "scan.submitted"
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_VIEWED = "scan.viewed"
    SCAN_LISTED = "scan.listed"
    FINDING_SUPPRESSED = "finding.suppressed"
    FINDING_UNSUPPRESSED = "finding.unsuppressed"


async def record_audit_event(
    action: str,
    actor_id: Optional[str],
    actor_email: Optional[str],
    resource_type: str,
    resource_id: str,
    client_ip: str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """D-718: Write an immutable audit record for a scan action."""
    try:
        from app.models import database as db

        record = {
            "id": str(uuid.uuid4()),
            "action": action,
            "actor_id": actor_id,
            "actor_email": actor_email,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "client_ip": client_ip,
            "metadata": metadata or {},
            "created_at": _utcnow(),
        }

        previous_hash: Optional[str] = None
        try:
            prev_row = await db.get_latest_audit_record(resource_id)
            if prev_row:
                previous_hash = prev_row.get("chain_hash")
        except Exception:
            pass

        record["chain_hash"] = _chain_hash(previous_hash, record)
        await db.insert_audit_record(record)
        logger.debug(
            "Audit: %s on %s/%s by %s from %s",
            action, resource_type, resource_id, actor_id or "system", client_ip,
        )
    except Exception as exc:
        logger.error(
            "AUDIT LOG WRITE FAILED (action=%s resource=%s): %s -- "
            "investigate immediately to maintain SOC2 audit trail integrity",
            action, resource_id, exc,
        )


class SuppressionReason:
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    NOT_APPLICABLE = "not_applicable"
    MITIGATED = "mitigated"
    WONT_FIX = "wont_fix"


async def record_suppression(
    finding_id: str,
    scan_id: str,
    actor_id: str,
    actor_email: str,
    reason: str,
    justification: str,
    client_ip: str,
    expires_at: Optional[str] = None,
) -> str:
    """D-722: Write an immutable suppression record.

    Returns the suppression record ID.
    Raises ValueError for invalid reason or justification < 10 chars.
    """
    if len(justification.strip()) < 10:
        raise ValueError(
            "Suppression justification must be at least 10 characters. "
            "Undocumented suppressions are not permitted."
        )

    valid_reasons = {
        SuppressionReason.FALSE_POSITIVE,
        SuppressionReason.ACCEPTED_RISK,
        SuppressionReason.NOT_APPLICABLE,
        SuppressionReason.MITIGATED,
        SuppressionReason.WONT_FIX,
    }
    if reason not in valid_reasons:
        raise ValueError(f"Invalid suppression reason '{reason}'.")

    try:
        from app.models import database as db

        suppression_id = str(uuid.uuid4())
        record = {
            "id": suppression_id,
            "finding_id": finding_id,
            "scan_id": scan_id,
            "actor_id": actor_id,
            "actor_email": actor_email,
            "reason": reason,
            "justification": justification.strip(),
            "client_ip": client_ip,
            "created_at": _utcnow(),
            "expires_at": expires_at,
        }

        previous_hash: Optional[str] = None
        try:
            prev_row = await db.get_latest_suppression_record(finding_id)
            if prev_row:
                previous_hash = prev_row.get("chain_hash")
        except Exception:
            pass

        record["chain_hash"] = _chain_hash(previous_hash, record)
        await db.insert_suppression_record(record)

        await record_audit_event(
            action=AuditAction.FINDING_SUPPRESSED,
            actor_id=actor_id,
            actor_email=actor_email,
            resource_type="finding",
            resource_id=finding_id,
            client_ip=client_ip,
            metadata={
                "scan_id": scan_id,
                "reason": reason,
                "justification": justification.strip()[:200],
                "suppression_id": suppression_id,
                "expires_at": expires_at,
            },
        )

        logger.info(
            "Suppression recorded: finding=%s by=%s reason=%s",
            finding_id, actor_email, reason,
        )
        return suppression_id

    except (ValueError, TypeError):
        raise
    except Exception as exc:
        logger.error(
            "SUPPRESSION LOG WRITE FAILED (finding=%s actor=%s): %s",
            finding_id, actor_id, exc,
        )
        raise RuntimeError(f"Failed to record suppression: {exc}") from exc
