"""Build a bounded, human-attested Phantom handoff manifest.

This module is intentionally data-only: it does not validate whether a target
is in scope, resolve a host, open a target, call Phantom, run a scan, or persist
credentials. The receiving operator must independently verify authorization.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from phantom_signing import attach_signature

TASK_FORMAT = "mizan-phantom-task-v1"
ALLOWED_TYPES = {"web", "mobile", "hardware", "code"}
ALLOWED_SCOPES = {"xss", "sqli", "ssrf", "idor", "logic", "auth", "rce", "crypto", "secrets", "misconfiguration"}
MAX_SCOPE_ITEMS = 12
MAX_TARGET_CHARS = 512


def create_manifest(payload: dict, *, requester: str, workspace_id: str) -> dict:
    """Validate bounded manifest structure, not target authorization or scope membership."""
    if not isinstance(payload, dict):
        raise ValueError("Task request must be a JSON object.")
    if payload.get("authorized_scope") is not True:
        raise ValueError("Confirm that you are authorized to test this target and selected scope.")
    target_type = payload.get("target_type", "web")
    if not isinstance(target_type, str) or target_type not in ALLOWED_TYPES:
        raise ValueError("Unsupported Phantom target type.")
    target = payload.get("target")
    if not isinstance(target, str):
        raise ValueError("Target must be text.")
    target = target.strip()
    if not target or len(target) > MAX_TARGET_CHARS:
        raise ValueError("Target must contain 1–512 characters.")
    raw_scope = payload.get("scope", [])
    if not isinstance(raw_scope, list) or not raw_scope or len(raw_scope) > MAX_SCOPE_ITEMS:
        raise ValueError("Choose between 1 and 12 bounded scan categories.")
    scope = []
    for item in raw_scope:
        if not isinstance(item, str) or item.strip().lower() not in ALLOWED_SCOPES:
            raise ValueError("Scope contains an unsupported category.")
        normalized = item.strip().lower()
        if normalized not in scope:
            scope.append(normalized)
    now = datetime.now(timezone.utc)
    manifest = {
        "format": TASK_FORMAT,
        "task_id": str(uuid.uuid4()),
        "created_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=2)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "requested_by": requester[:120],
        "workspace_id": workspace_id,
        "authorization": {
            "attested_by_user": True,
            "attested_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "statement": "Requester attests they are authorized to test the specified target and scope. This is not independently verified.",
        },
        "target": target,
        "target_type": target_type,
        "scope": scope,
        "execution": {
            "mode": "manual-handoff-only",
            "automatic_execution": False,
            "network_access_by_mizan": False,
            "max_duration_minutes": 20,
            "result_format": "phantom-scan-result-v1",
        },
    }
    return attach_signature(manifest)
