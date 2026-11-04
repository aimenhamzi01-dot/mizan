"""Database persistence for Mizan's unified security intelligence platform.

Manages SQLite tables for:
- Targets & Scope definitions
- Assessments
- Discovered Assets
- Security Findings & Risk Scores
- Cryptographic Evidence Items
- Tamper-Evident Audit Records
- Benchmark Executions

All records are strictly workspace-isolated and maintain backward compatibility.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import review_store
from audit_trail import GENESIS_HASH, AuditRecord, AuditTrail, redact_sensitive_data
from security_scope import ScopeError, TargetScope


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _connect():
    return review_store._connect()


def _columns(conn, table: str) -> set[str]:
    return review_store._columns(conn, table)


def init_security_db() -> None:
    """Initialize security platform tables in SQLite while strictly preserving review_store schema."""
    review_store.init_db()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")

        # 1. Targets table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS security_targets ("
            "id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), "
            "name TEXT NOT NULL, authorized_domains_json TEXT NOT NULL, "
            "authorized_ips_json TEXT NOT NULL, permitted_ports_json TEXT NOT NULL, "
            "permitted_protocols_json TEXT NOT NULL, excluded_assets_json TEXT NOT NULL, "
            "expires_at TEXT, authorization_notes TEXT NOT NULL DEFAULT '', "
            "created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT '')"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_ws ON security_targets(workspace_id, created_at DESC)")

        # 2. Assessments table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS assessments ("
            "id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), "
            "target_id TEXT NOT NULL REFERENCES security_targets(id) ON DELETE CASCADE, "
            "name TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('created', 'in_progress', 'completed', 'cancelled', 'failed')), "
            "started_at TEXT NOT NULL, completed_at TEXT, created_by TEXT NOT NULL DEFAULT '', "
            "summary_json TEXT NOT NULL DEFAULT '{}')"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_ws ON assessments(workspace_id, started_at DESC)")

        # 3. Discovered Assets table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS discovered_assets ("
            "id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, "
            "workspace_id TEXT NOT NULL REFERENCES workspaces(id), "
            "asset_type TEXT NOT NULL, identifier TEXT NOT NULL, "
            "provenance TEXT NOT NULL, in_scope INTEGER NOT NULL DEFAULT 1, "
            "discovered_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}')"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_ass ON discovered_assets(assessment_id, discovered_at DESC)")

        # 4. Security Findings table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS security_findings ("
            "id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, "
            "workspace_id TEXT NOT NULL REFERENCES workspaces(id), "
            "title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, "
            "confidence TEXT NOT NULL, cwe TEXT NOT NULL DEFAULT 'CWE-0', "
            "description TEXT NOT NULL, status TEXT NOT NULL, "
            "risk_score REAL NOT NULL DEFAULT 0.0, "
            "technical_evidence_text TEXT NOT NULL DEFAULT '', "
            "ai_reasoning_json TEXT, human_review_json TEXT, "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_ass ON security_findings(assessment_id, severity, confidence)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_ws ON security_findings(workspace_id, updated_at DESC)")

        # 5. Evidence Registry table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_registry ("
            "id TEXT PRIMARY KEY, finding_id TEXT, "
            "assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, "
            "workspace_id TEXT NOT NULL REFERENCES workspaces(id), "
            "evidence_type TEXT NOT NULL, original_source TEXT NOT NULL, "
            "collection_method TEXT NOT NULL, raw_content TEXT NOT NULL, "
            "normalized_content TEXT NOT NULL, sha256_hash TEXT NOT NULL, "
            "verification_status TEXT NOT NULL, confidence_score REAL NOT NULL, "
            "collected_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}')"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_registry(finding_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence_registry(sha256_hash)")

        # 6. Tamper-evident Audit Events table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_events ("
            "event_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "workspace_id TEXT NOT NULL, occurred_at TEXT NOT NULL, "
            "actor TEXT NOT NULL, actor_user_id TEXT, event_type TEXT NOT NULL, "
            "target_ref TEXT NOT NULL, details_json TEXT NOT NULL, "
            "prev_hash TEXT NOT NULL, record_hash TEXT NOT NULL)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ws ON audit_events(workspace_id, event_id DESC)")

        # 7. Benchmark runs table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS benchmark_runs ("
            "id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, "
            "executed_at TEXT NOT NULL, status TEXT NOT NULL, "
            "execution_time_ms REAL NOT NULL, total_cases INTEGER NOT NULL, "
            "result_json TEXT NOT NULL)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bench_ws ON benchmark_runs(workspace_id, executed_at DESC)")


# --- Target Management ---

def create_target(
    name: str,
    authorized_domains: list[str],
    authorized_ips: list[str] | None = None,
    permitted_ports: list[int] | None = None,
    permitted_protocols: list[str] | None = None,
    excluded_assets: list[str] | None = None,
    expires_at: str | None = None,
    authorization_notes: str = "",
    workspace_id: str = "default",
    created_by: str = "analyst",
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    # Validate scope creation parameters
    scope = TargetScope(
        name=name,
        authorized_domains=authorized_domains,
        authorized_ips=authorized_ips,
        permitted_ports=permitted_ports,
        permitted_protocols=permitted_protocols,
        excluded_assets=excluded_assets,
        expires_at=expires_at,
        authorization_notes=authorization_notes,
        workspace_id=workspace_id,
    )
    init_security_db()
    target_id = f"tgt-{uuid.uuid4().hex[:12]}"
    now = _now()

    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO security_targets (id, workspace_id, name, authorized_domains_json, "
            "authorized_ips_json, permitted_ports_json, permitted_protocols_json, "
            "excluded_assets_json, expires_at, authorization_notes, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target_id,
                workspace_id,
                scope.name,
                json.dumps(scope.authorized_domains),
                json.dumps(scope.authorized_ips),
                json.dumps(list(scope.permitted_ports)),
                json.dumps(list(scope.permitted_protocols)),
                json.dumps(scope.excluded_assets),
                scope.expires_at,
                scope.authorization_notes,
                now,
                created_by,
            ),
        )

    log_audit_event(
        event_type="target_created",
        actor=created_by,
        target_ref=target_id,
        details={"name": scope.name, "domains": scope.authorized_domains},
        workspace_id=workspace_id,
        actor_user_id=actor_user_id,
    )
    return get_target(target_id, workspace_id=workspace_id)


def get_target(target_id: str, workspace_id: str | None = None) -> dict[str, Any]:
    init_security_db()
    sql = "SELECT * FROM security_targets WHERE id = ?"
    args = [target_id]
    if workspace_id is not None:
        sql += " AND workspace_id = ?"
        args.append(workspace_id)

    with _connect() as conn:
        row = conn.execute(sql, args).fetchone()
        if not row:
            raise review_store.NotFound("Target not found.")

        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "name": row["name"],
            "authorized_domains": json.loads(row["authorized_domains_json"]),
            "authorized_ips": json.loads(row["authorized_ips_json"]),
            "permitted_ports": json.loads(row["permitted_ports_json"]),
            "permitted_protocols": json.loads(row["permitted_protocols_json"]),
            "excluded_assets": json.loads(row["excluded_assets_json"]),
            "expires_at": row["expires_at"],
            "authorization_notes": row["authorization_notes"],
            "created_at": row["created_at"],
            "created_by": row["created_by"],
        }


def list_targets(workspace_id: str | None = None) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT * FROM security_targets"
    args = []
    if workspace_id is not None:
        sql += " WHERE workspace_id = ?"
        args.append(workspace_id)
    sql += " ORDER BY created_at DESC"

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "workspace_id": r["workspace_id"],
                "name": r["name"],
                "authorized_domains": json.loads(r["authorized_domains_json"]),
                "authorized_ips": json.loads(r["authorized_ips_json"]),
                "permitted_ports": json.loads(r["permitted_ports_json"]),
                "permitted_protocols": json.loads(r["permitted_protocols_json"]),
                "excluded_assets": json.loads(r["excluded_assets_json"]),
                "expires_at": r["expires_at"],
                "authorization_notes": r["authorization_notes"],
                "created_at": r["created_at"],
                "created_by": r["created_by"],
            }
            for r in rows
        ]


def get_target_scope_instance(target_id: str, workspace_id: str | None = None) -> TargetScope:
    tgt = get_target(target_id, workspace_id)
    return TargetScope(
        name=tgt["name"],
        authorized_domains=tgt["authorized_domains"],
        authorized_ips=tgt["authorized_ips"],
        permitted_ports=tgt["permitted_ports"],
        permitted_protocols=tgt["permitted_protocols"],
        excluded_assets=tgt["excluded_assets"],
        expires_at=tgt["expires_at"],
        authorization_notes=tgt["authorization_notes"],
        workspace_id=tgt["workspace_id"],
    )


# --- Assessment Management ---

def create_assessment(
    target_id: str,
    name: str,
    workspace_id: str = "default",
    created_by: str = "analyst",
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    # Ensure target exists and matches scope
    target = get_target(target_id, workspace_id)
    init_security_db()

    assessment_id = f"asm-{uuid.uuid4().hex[:12]}"
    now = _now()

    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO assessments (id, workspace_id, target_id, name, status, started_at, created_by, summary_json) "
            "VALUES (?, ?, ?, ?, 'created', ?, ?, '{}')",
            (assessment_id, workspace_id, target_id, name.strip() or f"Assessment of {target['name']}", now, created_by),
        )

    log_audit_event(
        event_type="assessment_created",
        actor=created_by,
        target_ref=assessment_id,
        details={"target_id": target_id, "name": name},
        workspace_id=workspace_id,
        actor_user_id=actor_user_id,
    )
    return get_assessment(assessment_id, workspace_id)


def get_assessment(assessment_id: str, workspace_id: str | None = None) -> dict[str, Any]:
    init_security_db()
    sql = "SELECT * FROM assessments WHERE id = ?"
    args = [assessment_id]
    if workspace_id is not None:
        sql += " AND workspace_id = ?"
        args.append(workspace_id)

    with _connect() as conn:
        row = conn.execute(sql, args).fetchone()
        if not row:
            raise review_store.NotFound("Assessment not found.")

        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "target_id": row["target_id"],
            "name": row["name"],
            "status": row["status"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "created_by": row["created_by"],
            "summary": json.loads(row["summary_json"]),
        }


def list_assessments(workspace_id: str | None = None) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT * FROM assessments"
    args = []
    if workspace_id is not None:
        sql += " WHERE workspace_id = ?"
        args.append(workspace_id)
    sql += " ORDER BY started_at DESC"

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "workspace_id": r["workspace_id"],
                "target_id": r["target_id"],
                "name": r["name"],
                "status": r["status"],
                "started_at": r["started_at"],
                "completed_at": r["completed_at"],
                "created_by": r["created_by"],
                "summary": json.loads(r["summary_json"]),
            }
            for r in rows
        ]


def update_assessment_status(
    assessment_id: str,
    status: str,
    summary: dict[str, Any] | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    init_security_db()
    now = _now()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if not row:
            raise review_store.NotFound("Assessment not found.")
        if workspace_id is not None and row["workspace_id"] != workspace_id:
            raise review_store.NotFound("Assessment not found.")

        sum_json = json.dumps(summary or {})
        conn.execute(
            "UPDATE assessments SET status = ?, completed_at = ?, summary_json = ? WHERE id = ?",
            (status, now if status in ("completed", "cancelled", "failed") else None, sum_json, assessment_id),
        )
    return get_assessment(assessment_id, workspace_id)


# --- Discovered Assets ---

def save_discovered_asset(
    assessment_id: str,
    asset_type: str,
    identifier: str,
    provenance: str,
    in_scope: bool = True,
    metadata: dict[str, Any] | None = None,
    workspace_id: str = "default",
) -> dict[str, Any]:
    init_security_db()
    asset_id = f"ast-{uuid.uuid4().hex[:12]}"
    now = _now()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO discovered_assets (id, assessment_id, workspace_id, asset_type, identifier, "
            "provenance, in_scope, discovered_at, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (asset_id, assessment_id, workspace_id, asset_type, identifier, provenance, 1 if in_scope else 0, now, json.dumps(metadata or {})),
        )
    return {
        "id": asset_id,
        "assessment_id": assessment_id,
        "asset_type": asset_type,
        "identifier": identifier,
        "provenance": provenance,
        "in_scope": in_scope,
        "discovered_at": now,
        "metadata": metadata or {},
    }


def list_discovered_assets(assessment_id: str | None = None, workspace_id: str | None = None) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT * FROM discovered_assets"
    where, args = [], []
    if workspace_id is not None:
        where.append("workspace_id = ?")
        args.append(workspace_id)
    if assessment_id is not None:
        where.append("assessment_id = ?")
        args.append(assessment_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY discovered_at DESC"

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "assessment_id": r["assessment_id"],
                "asset_type": r["asset_type"],
                "identifier": r["identifier"],
                "provenance": r["provenance"],
                "in_scope": bool(r["in_scope"]),
                "discovered_at": r["discovered_at"],
                "metadata": json.loads(r["metadata_json"]),
            }
            for r in rows
        ]


# --- Security Findings ---

def save_finding(
    assessment_id: str,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    description: str,
    cwe: str = "CWE-0",
    risk_score: float = 0.0,
    technical_evidence: str = "",
    status: str = "pending_human_review",
    ai_reasoning: dict[str, Any] | None = None,
    human_review: dict[str, Any] | None = None,
    workspace_id: str = "default",
    finding_id: str | None = None,
) -> dict[str, Any]:
    init_security_db()
    f_id = finding_id or f"fnd-{uuid.uuid4().hex[:12]}"
    now = _now()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO security_findings (id, assessment_id, workspace_id, title, category, "
            "severity, confidence, cwe, description, status, risk_score, technical_evidence_text, "
            "ai_reasoning_json, human_review_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "severity=excluded.severity, confidence=excluded.confidence, status=excluded.status, "
            "risk_score=excluded.risk_score, technical_evidence_text=excluded.technical_evidence_text, "
            "ai_reasoning_json=excluded.ai_reasoning_json, human_review_json=excluded.human_review_json, "
            "updated_at=excluded.updated_at",
            (
                f_id, assessment_id, workspace_id, title, category, severity, confidence, cwe,
                description, status, risk_score, technical_evidence,
                json.dumps(ai_reasoning) if ai_reasoning else None,
                json.dumps(human_review) if human_review else None,
                now, now,
            ),
        )
    return get_finding(f_id, workspace_id)


def get_finding(finding_id: str, workspace_id: str | None = None) -> dict[str, Any]:
    init_security_db()
    sql = "SELECT * FROM security_findings WHERE id = ?"
    args = [finding_id]
    if workspace_id is not None:
        sql += " AND workspace_id = ?"
        args.append(workspace_id)
    with _connect() as conn:
        r = conn.execute(sql, args).fetchone()
        if not r:
            raise review_store.NotFound("Finding not found.")
        return {
            "id": r["id"],
            "assessment_id": r["assessment_id"],
            "workspace_id": r["workspace_id"],
            "title": r["title"],
            "category": r["category"],
            "severity": r["severity"],
            "confidence": r["confidence"],
            "cwe": r["cwe"],
            "description": r["description"],
            "status": r["status"],
            "risk_score": r["risk_score"],
            "evidence": r["technical_evidence_text"],
            "ai_reasoning": json.loads(r["ai_reasoning_json"]) if r["ai_reasoning_json"] else None,
            "human_review": json.loads(r["human_review_json"]) if r["human_review_json"] else None,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }


def list_findings(
    assessment_id: str | None = None,
    workspace_id: str | None = None,
    severity: str = "",
    status: str = "",
) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT * FROM security_findings"
    where, args = [], []
    if workspace_id is not None:
        where.append("workspace_id = ?")
        args.append(workspace_id)
    if assessment_id is not None:
        where.append("assessment_id = ?")
        args.append(assessment_id)
    if severity:
        where.append("severity = ?")
        args.append(severity)
    if status:
        where.append("status = ?")
        args.append(status)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC"

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "assessment_id": r["assessment_id"],
                "workspace_id": r["workspace_id"],
                "title": r["title"],
                "category": r["category"],
                "severity": r["severity"],
                "confidence": r["confidence"],
                "cwe": r["cwe"],
                "description": r["description"],
                "status": r["status"],
                "risk_score": r["risk_score"],
                "evidence": r["technical_evidence_text"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]


# --- Evidence Items ---

def save_evidence_item(
    assessment_id: str,
    finding_id: str,
    evidence_type: str,
    original_source: str,
    collection_method: str,
    raw_content: str,
    normalized_content: str,
    sha256_hash: str,
    verification_status: str = "unverified",
    confidence_score: float = 0.5,
    metadata: dict[str, Any] | None = None,
    workspace_id: str = "default",
    evidence_id: str | None = None,
) -> dict[str, Any]:
    init_security_db()
    evi_id = evidence_id or f"evi-{uuid.uuid4().hex[:12]}"
    now = _now()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO evidence_registry (id, finding_id, assessment_id, workspace_id, "
            "evidence_type, original_source, collection_method, raw_content, normalized_content, "
            "sha256_hash, verification_status, confidence_score, collected_at, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evi_id, finding_id, assessment_id, workspace_id, evidence_type, original_source,
                collection_method, raw_content, normalized_content, sha256_hash,
                verification_status, confidence_score, now, json.dumps(metadata or {}),
            ),
        )
    return {
        "id": evi_id,
        "finding_id": finding_id,
        "assessment_id": assessment_id,
        "evidence_type": evidence_type,
        "original_source": original_source,
        "collection_method": collection_method,
        "sha256_hash": sha256_hash,
        "verification_status": verification_status,
        "confidence_score": confidence_score,
        "collected_at": now,
        "metadata": metadata or {},
    }


def list_evidence(
    assessment_id: str | None = None,
    finding_id: str | None = None,
    workspace_id: str | None = None,
) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT * FROM evidence_registry"
    where, args = [], []
    if workspace_id is not None:
        where.append("workspace_id = ?")
        args.append(workspace_id)
    if assessment_id is not None:
        where.append("assessment_id = ?")
        args.append(assessment_id)
    if finding_id is not None:
        where.append("finding_id = ?")
        args.append(finding_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY collected_at DESC"

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "evidence_id": r["id"],
                "finding_id": r["finding_id"],
                "assessment_id": r["assessment_id"],
                "evidence_type": r["evidence_type"],
                "original_source": r["original_source"],
                "collection_method": r["collection_method"],
                "raw_content": r["raw_content"],
                "normalized_content": r["normalized_content"],
                "sha256_hash": r["sha256_hash"],
                "verification_status": r["verification_status"],
                "confidence_score": r["confidence_score"],
                "collected_at": r["collected_at"],
                "metadata": json.loads(r["metadata_json"]),
            }
            for r in rows
        ]


# --- Tamper-Evident Audit Storage ---

def get_latest_audit_hash() -> str:
    init_security_db()
    with _connect() as conn:
        row = conn.execute("SELECT record_hash FROM audit_events ORDER BY event_id DESC LIMIT 1").fetchone()
        return row["record_hash"] if row else GENESIS_HASH


def log_audit_event(
    event_type: str,
    actor: str,
    target_ref: str,
    details: dict[str, Any],
    workspace_id: str = "default",
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    init_security_db()
    prev_hash = get_latest_audit_hash()
    now = _now()
    clean_details = redact_sensitive_data(details)

    # Compute record hash
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()
        event_id = row["n"] + 1

        rec = AuditRecord(
            event_id=event_id,
            occurred_at=now,
            actor=actor,
            actor_user_id=actor_user_id,
            workspace_id=workspace_id,
            event_type=event_type,
            target_ref=target_ref,
            details=clean_details,
            prev_hash=prev_hash,
        )

        conn.execute(
            "INSERT INTO audit_events (workspace_id, occurred_at, actor, actor_user_id, "
            "event_type, target_ref, details_json, prev_hash, record_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                workspace_id, now, rec.actor, rec.actor_user_id, rec.event_type,
                rec.target_ref, json.dumps(rec.details), rec.prev_hash, rec.record_hash,
            ),
        )
    return rec.to_dict()


def list_audit_events(workspace_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT * FROM audit_events"
    args = []
    if workspace_id is not None:
        sql += " WHERE workspace_id = ?"
        args.append(workspace_id)
    sql += " ORDER BY event_id DESC LIMIT ?"
    args.append(limit)

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [
            {
                "event_id": r["event_id"],
                "occurred_at": r["occurred_at"],
                "actor": r["actor"],
                "actor_user_id": r["actor_user_id"],
                "workspace_id": r["workspace_id"],
                "event_type": r["event_type"],
                "target_ref": r["target_ref"],
                "details": json.loads(r["details_json"]),
                "prev_hash": r["prev_hash"],
                "record_hash": r["record_hash"],
            }
            for r in rows
        ]


def verify_database_audit_chain() -> tuple[bool, str]:
    """Verify entire stored audit chain."""
    init_security_db()
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY event_id ASC").fetchall()
        if not rows:
            return True, "Audit log is empty."

        prev = GENESIS_HASH
        for r in rows:
            rec = AuditRecord(
                event_id=r["event_id"],
                occurred_at=r["occurred_at"],
                actor=r["actor"],
                actor_user_id=r["actor_user_id"],
                workspace_id=r["workspace_id"],
                event_type=r["event_type"],
                target_ref=r["target_ref"],
                details=json.loads(r["details_json"]),
                prev_hash=r["prev_hash"],
                record_hash=r["record_hash"],
            )
            if rec.prev_hash != prev:
                return False, f"Broken chain link at event {rec.event_id}"
            if not rec.verify_integrity():
                return False, f"Tampered record at event {rec.event_id}"
            prev = rec.record_hash

        return True, f"Verified {len(rows)} hash-linked audit records successfully."


# --- Benchmark Runs ---

def save_benchmark_run(run_result: dict[str, Any], workspace_id: str = "default") -> None:
    init_security_db()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO benchmark_runs (id, workspace_id, executed_at, status, execution_time_ms, total_cases, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run_result["run_id"],
                workspace_id,
                run_result["executed_at"],
                run_result["status"],
                run_result["execution_time_ms"],
                run_result["total_test_cases"],
                json.dumps(run_result),
            ),
        )


def list_benchmark_runs(workspace_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    init_security_db()
    sql = "SELECT result_json FROM benchmark_runs"
    args = []
    if workspace_id is not None:
        sql += " WHERE workspace_id = ?"
        args.append(workspace_id)
    sql += " ORDER BY executed_at DESC LIMIT ?"
    args.append(limit)

    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
        return [json.loads(r["result_json"]) for r in rows]
