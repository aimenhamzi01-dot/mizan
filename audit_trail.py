"""Tamper-evident, hash-linked audit logging system for Mizan.

Maintains an immutable, append-only chronological log of security platform events.
Each entry is cryptographically linked to the previous entry using SHA-256 (blockchain/Merkle style),
enabling verification of historical integrity and detection of post-hoc modifications.

Sensitive information (passwords, tokens, API keys) is redacted prior to hashing and logging.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
from typing import Any

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(api[-_]?key|token|password|secret|bearer)\s*[:=]\s*["\']?([^"\'\s,;]+)'),
    re.compile(r'(?i)Bearer\s+[A-Za-z0-9_\-\.]{16,}'),
]


def redact_sensitive_data(value: Any) -> Any:
    """Recursively scrub credentials and keys from audit event details."""
    if isinstance(value, str):
        cleaned = value
        # Pattern 1
        cleaned = re.sub(
            r'(?i)(api[-_]?key|token|password|secret|bearer)\s*[:=]\s*["\']?([^"\'\s,;]+)',
            r'\1: [REDACTED]',
            cleaned,
        )
        # Pattern 2
        cleaned = re.sub(r'(?i)Bearer\s+[A-Za-z0-9_\-\.]{16,}', 'Bearer [REDACTED]', cleaned)
        return cleaned
    elif isinstance(value, dict):
        return {
            k: ("[REDACTED]" if any(s in k.lower() for s in ("token", "key", "password", "secret")) else redact_sensitive_data(v))
            for k, v in value.items()
        }
    elif isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    return value


class AuditRecord:
    """A single tamper-evident hash-linked audit record."""

    def __init__(
        self,
        event_id: int,
        occurred_at: str,
        actor: str,
        actor_user_id: str | None,
        workspace_id: str,
        event_type: str,
        target_ref: str,
        details: dict[str, Any],
        prev_hash: str,
        record_hash: str | None = None,
    ):
        self.event_id = event_id
        self.occurred_at = occurred_at
        self.actor = str(actor)[:120]
        self.actor_user_id = str(actor_user_id) if actor_user_id else None
        self.workspace_id = str(workspace_id)
        self.event_type = str(event_type)
        self.target_ref = str(target_ref)
        self.details = redact_sensitive_data(details)
        self.prev_hash = prev_hash or GENESIS_HASH
        self.record_hash = record_hash or self.compute_hash()

    def compute_hash(self) -> str:
        """Calculate canonical SHA-256 hash over prev_hash and event fields."""
        payload = {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "actor_user_id": self.actor_user_id,
            "workspace_id": self.workspace_id,
            "event_type": self.event_type,
            "target_ref": self.target_ref,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        return self.compute_hash() == self.record_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "actor_user_id": self.actor_user_id,
            "workspace_id": self.workspace_id,
            "event_type": self.event_type,
            "target_ref": self.target_ref,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "is_valid": self.verify_integrity(),
        }


class AuditTrail:
    """Manages an in-memory / persistent hash-linked audit chain."""

    def __init__(self):
        self._records: list[AuditRecord] = []

    @property
    def latest_hash(self) -> str:
        return self._records[-1].record_hash if self._records else GENESIS_HASH

    def log_event(
        self,
        event_type: str,
        actor: str,
        target_ref: str,
        details: dict[str, Any],
        workspace_id: str = "default",
        actor_user_id: str | None = None,
    ) -> AuditRecord:
        """Create and append a hash-linked audit record."""
        event_id = len(self._records) + 1
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        record = AuditRecord(
            event_id=event_id,
            occurred_at=now_iso,
            actor=actor,
            actor_user_id=actor_user_id,
            workspace_id=workspace_id,
            event_type=event_type,
            target_ref=target_ref,
            details=details,
            prev_hash=self.latest_hash,
        )
        self._records.append(record)
        return record

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the cryptographic integrity of the entire audit chain.

        Returns (is_valid, message).
        """
        if not self._records:
            return True, "Audit log is empty (genesis state)."

        prev = GENESIS_HASH
        for idx, rec in enumerate(self._records):
            if rec.prev_hash != prev:
                return False, f"Broken chain link at record {rec.event_id} (expected prev_hash {prev}, got {rec.prev_hash})."
            if not rec.verify_integrity():
                return False, f"Tampered record at event {rec.event_id} (hash mismatch)."
            prev = rec.record_hash

        return True, f"Verified chain integrity: {len(self._records)} tamper-evident records valid."

    def list_events(self, workspace_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        records = self._records
        if workspace_id is not None:
            records = [r for r in records if r.workspace_id == workspace_id]
        return [r.to_dict() for r in reversed(records[-limit:])]
