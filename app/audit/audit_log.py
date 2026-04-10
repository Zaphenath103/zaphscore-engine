"""
ZSE SOC2 Audit Log — D-718 + D-722 fix.

Provides an immutable, hash-chained audit trail for all scan trigger
actions and finding suppression records.  Closes the gap vs Snyk's
enterprise SOC2 audit log.

Design:
  - Events are appended to a JSONL file (one JSON object per line).
  - Each event includes a SHA-256 hash computed over the serialised event
    concatenated with the previous event hash (blockchain-style chaining).
  - Chain integrity can be verified with ``verify_chain(log_path)``.
  - ``SuppressionRecord`` tracks who suppressed a finding, why, and when
    it expires — satisfying SOC2 CC7.2 / CC7.3 requirements.

Usage::

    from app.audit.audit_log import AuditLogger, AuditEvent, log_suppression

    logger_inst = AuditLogger("/var/log/zse/audit.jsonl")
    logger_inst.log(AuditEvent(
        event_type="scan.triggered",
        actor="user@example.com",
        resource="github.com/owner/repo",
        metadata={"scan_id": "abc123"},
    ))
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# D-718: AuditEvent + AuditLogger
# ---------------------------------------------------------------------------

#: Sentinel hash for the first event in a chain (no predecessor).
GENESIS_HASH = "0" * 64


@dataclass
class AuditEvent:
    """An immutable audit event record.

    Attributes:
        event_type: Dot-separated action category, e.g. ``"scan.triggered"``,
            ``"finding.suppressed"``, ``"policy.updated"``.
        actor: Identity of the entity performing the action (email, user-id,
            service-account name, or ``"system"``).
        resource: The primary resource affected (repo URL, scan-id, etc.).
        timestamp: ISO-8601 UTC timestamp (auto-filled if omitted).
        metadata: Arbitrary additional key/value pairs for context.
        hash: SHA-256 hash of this event chained with the previous event hash.
            Auto-computed by :class:`AuditLogger` on write; leave blank.
    """

    event_type: str
    actor: str
    resource: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)
    hash: str = field(default="")  # computed at write time

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        return cls(
            event_type=data["event_type"],
            actor=data["actor"],
            resource=data["resource"],
            timestamp=data.get("timestamp", ""),
            metadata=data.get("metadata", {}),
            hash=data.get("hash", ""),
        )


def _compute_event_hash(event: AuditEvent, previous_hash: str) -> str:
    """Compute a SHA-256 hash over the event content + previous chain hash.

    The hash covers: event_type, actor, resource, timestamp, metadata
    (serialised deterministically) concatenated with the previous event hash.
    This creates an immutable chain — altering any event invalidates all
    subsequent hashes.
    """
    payload = json.dumps(
        {
            "event_type": event.event_type,
            "actor": event.actor,
            "resource": event.resource,
            "timestamp": event.timestamp,
            "metadata": event.metadata,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLogger:
    """Thread-safe append-only audit logger with hash-chained entries.

    Events are stored as JSONL (one JSON object per line) in *log_path*.
    The parent directory is created automatically if it does not exist.

    Args:
        log_path: Absolute path to the JSONL audit log file.
    """

    def __init__(self, log_path: str) -> None:
        self._log_path = log_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        """Read the hash of the last event from the log file."""
        if not os.path.isfile(self._log_path):
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                            last_hash = record.get("hash", GENESIS_HASH)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return last_hash

    def log(self, event: AuditEvent) -> AuditEvent:
        """Append an event to the audit log.

        Computes the chain hash and writes the event as a JSONL entry.
        Returns the event with the ``hash`` field populated.

        Args:
            event: The :class:`AuditEvent` to record.

        Returns:
            The same event with its ``hash`` field set.
        """
        with self._lock:
            event.hash = _compute_event_hash(event, self._last_hash)
            record = event.to_dict()
            try:
                with open(self._log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, separators=(",", ":")) + "\n")
                self._last_hash = event.hash
                logger.debug(
                    "Audit: %s by %s on %s [%s]",
                    event.event_type, event.actor, event.resource, event.hash[:12],
                )
            except OSError as exc:
                logger.error("Failed to write audit event: %s", exc)
        return event

    def read_all(self) -> list[AuditEvent]:
        """Read all events from the audit log file."""
        events: list[AuditEvent] = []
        if not os.path.isfile(self._log_path):
            return events
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            events.append(AuditEvent.from_dict(json.loads(line)))
                        except (json.JSONDecodeError, KeyError):
                            pass
        except OSError as exc:
            logger.error("Failed to read audit log: %s", exc)
        return events


def verify_chain(log_path: str) -> tuple[bool, list[str]]:
    """Verify the integrity of a hash-chained audit log.

    Reads every entry in *log_path* and recomputes the expected hash for
    each event given the previous event's hash.  Compares against the
    stored ``hash`` field.

    Args:
        log_path: Path to the JSONL audit log file.

    Returns:
        A 2-tuple of ``(ok, errors)`` where *ok* is ``True`` if the chain
        is intact and *errors* is a list of human-readable problem strings
        (empty when *ok* is True).
    """
    errors: list[str] = []

    if not os.path.isfile(log_path):
        return True, []  # empty log is trivially valid

    prev_hash = GENESIS_HASH
    line_num = 0

    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                line_num += 1
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    errors.append(f"Line {line_num}: invalid JSON — {exc}")
                    continue

                stored_hash = record.get("hash", "")
                event = AuditEvent.from_dict(record)
                event.hash = ""  # clear so we recompute clean
                expected_hash = _compute_event_hash(event, prev_hash)

                if stored_hash != expected_hash:
                    errors.append(
                        f"Line {line_num} ({record.get('event_type', '?')}): "
                        f"hash mismatch — stored={stored_hash[:16]}…, "
                        f"expected={expected_hash[:16]}…"
                    )
                prev_hash = stored_hash or expected_hash

    except OSError as exc:
        errors.append(f"Cannot read audit log: {exc}")

    ok = len(errors) == 0
    if ok:
        logger.info("Audit chain verified: %d events OK", line_num)
    else:
        logger.warning("Audit chain verification failed: %d errors in %d events", len(errors), line_num)

    return ok, errors


# ---------------------------------------------------------------------------
# D-722: SuppressionRecord + suppression log
# ---------------------------------------------------------------------------

@dataclass
class SuppressionRecord:
    """An immutable record of a finding suppression action.

    Attributes:
        finding_id: The unique ID of the suppressed finding.
        suppressed_by: Identity of the user/service that performed the suppression.
        reason: Required human-readable justification for the suppression.
        suppressed_at: ISO-8601 UTC timestamp of the suppression action.
        expires_at: ISO-8601 UTC timestamp when the suppression expires
            (``None`` for permanent suppressions).
        hash: SHA-256 hash chained from the previous record — auto-computed.
    """

    finding_id: str
    suppressed_by: str
    reason: str
    suppressed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: Optional[str] = None
    hash: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SuppressionRecord":
        return cls(
            finding_id=data["finding_id"],
            suppressed_by=data["suppressed_by"],
            reason=data["reason"],
            suppressed_at=data.get("suppressed_at", ""),
            expires_at=data.get("expires_at"),
            hash=data.get("hash", ""),
        )

    def is_active(self) -> bool:
        """Return True if this suppression is currently active (not expired)."""
        if self.expires_at is None:
            return True  # permanent
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.now(timezone.utc) < expires
        except ValueError:
            return False


def _compute_suppression_hash(record: SuppressionRecord, previous_hash: str) -> str:
    """Compute a SHA-256 chain hash for a suppression record."""
    payload = json.dumps(
        {
            "finding_id": record.finding_id,
            "suppressed_by": record.suppressed_by,
            "reason": record.reason,
            "suppressed_at": record.suppressed_at,
            "expires_at": record.expires_at,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SuppressionLogger:
    """Thread-safe append-only suppression log with hash-chained entries.

    Args:
        log_path: Absolute path to the JSONL suppression log file.
    """

    def __init__(self, log_path: str) -> None:
        self._log_path = log_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not os.path.isfile(self._log_path):
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                            last_hash = record.get("hash", GENESIS_HASH)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return last_hash

    def log_suppression(self, record: SuppressionRecord) -> SuppressionRecord:
        """Append a suppression record to the log.

        Args:
            record: The :class:`SuppressionRecord` to persist.

        Returns:
            The same record with its ``hash`` field set.
        """
        with self._lock:
            record.hash = _compute_suppression_hash(record, self._last_hash)
            data = record.to_dict()
            try:
                with open(self._log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(data, separators=(",", ":")) + "\n")
                self._last_hash = record.hash
                logger.info(
                    "Suppression logged: finding=%s by=%s expires=%s",
                    record.finding_id, record.suppressed_by, record.expires_at or "never",
                )
            except OSError as exc:
                logger.error("Failed to write suppression record: %s", exc)
        return record

    def get_active_suppressions(self) -> list[SuppressionRecord]:
        """Return all suppression records that are currently active (not expired).

        Returns:
            List of active :class:`SuppressionRecord` objects sorted by
            ``suppressed_at`` ascending.
        """
        all_records = self._read_all()
        active = [r for r in all_records if r.is_active()]
        active.sort(key=lambda r: r.suppressed_at)
        return active

    def _read_all(self) -> list[SuppressionRecord]:
        records: list[SuppressionRecord] = []
        if not os.path.isfile(self._log_path):
            return records
        try:
            with open(self._log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            records.append(SuppressionRecord.from_dict(json.loads(line)))
                        except (json.JSONDecodeError, KeyError):
                            pass
        except OSError as exc:
            logger.error("Failed to read suppression log: %s", exc)
        return records

    def is_suppressed(self, finding_id: str) -> bool:
        """Check if a specific finding is currently suppressed.

        Args:
            finding_id: The finding identifier to look up.

        Returns:
            ``True`` if there is an active suppression for this finding.
        """
        active = self.get_active_suppressions()
        return any(r.finding_id == finding_id for r in active)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def log_suppression(
    record: SuppressionRecord,
    log_path: str = "/var/log/zse/suppressions.jsonl",
) -> SuppressionRecord:
    """Convenience wrapper: append a suppression record to *log_path*.

    Creates a :class:`SuppressionLogger` for the given path each call.
    For high-throughput scenarios, prefer instantiating :class:`SuppressionLogger`
    once and reusing it.
    """
    sl = SuppressionLogger(log_path)
    return sl.log_suppression(record)


def get_active_suppressions(
    log_path: str = "/var/log/zse/suppressions.jsonl",
) -> list[SuppressionRecord]:
    """Convenience wrapper: return active suppressions from *log_path*."""
    sl = SuppressionLogger(log_path)
    return sl.get_active_suppressions()
