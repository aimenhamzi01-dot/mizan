"""Local persistence for Mizan's human-reviewed triage workbench.

Submitted reports and source snippets are stored as text only. This module never
imports, parses, imports, or executes submitted code and makes no network calls.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DECISIONS = {"accept", "need-info", "duplicate", "reject"}
STATUSES = {"received", "analyzed", "reviewed"}
MAX_REPORT_CHARS = 20_000
MAX_CODE_CHARS = 40_000
MAX_REVIEWER_CHARS = 120
MAX_NOTE_CHARS = 4_000


class StoreError(Exception):
    """Base class for expected local-store errors."""


class NotFound(StoreError):
    """A requested report does not exist."""


class InvalidState(StoreError):
    """An operation is not allowed in the report's current review state."""


def database_path() -> Path:
    configured = os.environ.get("MIZAN_DB_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parent / "data" / "mizan.sqlite3"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class _ClosingConnection:
    """Context wrapper that commits/rolls back and always closes SQLite."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def __enter__(self):
        return self.connection.__enter__()

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return self.connection.__exit__(exc_type, exc_value, traceback)
        finally:
            self.connection.close()


def _connect() -> _ClosingConnection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not os.environ.get("MIZAN_DB_PATH", "").strip():
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            raise StoreError("Could not restrict permissions on the local data directory.")
    conn = sqlite3.connect(str(path), timeout=5.0)
    try:
        os.chmod(path, 0o600)
    except OSError:
        conn.close()
        raise StoreError("Could not restrict permissions on the local database file.")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA secure_delete = ON")
    return _ClosingConnection(conn)


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def init_db() -> None:
    """Create the local schema if it does not exist; safe to call repeatedly."""
    with _connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                language TEXT NOT NULL CHECK (language IN ('en', 'ar')),
                report TEXT NOT NULL,
                code TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK (status IN ('received', 'analyzed', 'reviewed')),
                analysis_json TEXT,
                suggested_decision TEXT CHECK (
                    suggested_decision IS NULL OR
                    suggested_decision IN ('accept', 'need-info', 'duplicate', 'reject')
                ),
                review_decision TEXT CHECK (
                    review_decision IS NULL OR
                    review_decision IN ('accept', 'need-info', 'duplicate', 'reject')
                ),
                reviewer TEXT NOT NULL DEFAULT '',
                review_note TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_reports_updated ON reports(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
            CREATE TABLE IF NOT EXISTS report_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK (
                    event_type IN ('report_received', 'analysis_completed', 'human_review_recorded')
                ),
                actor TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_report ON report_events(report_id, event_id);
            """
        )


def _append_event(conn, report_id: str, event_type: str, actor: str, details: dict) -> None:
    conn.execute(
        "INSERT INTO report_events(report_id, occurred_at, event_type, actor, details_json) "
        "VALUES (?, ?, ?, ?, ?)",
        (report_id, _now(), event_type, actor[:MAX_REVIEWER_CHARS], _json(details)),
    )


def _row_to_report(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "language": row["language"],
        "report": row["report"],
        "code": row["code"],
        "status": row["status"],
        "analysis": json.loads(row["analysis_json"]) if row["analysis_json"] else None,
        "suggested_decision": row["suggested_decision"],
        "review_decision": row["review_decision"],
        "reviewer": row["reviewer"],
        "review_note": row["review_note"],
    }


def create_report(report: str, code: str = "", language: str = "en") -> dict:
    """Store an inbound report as text with status=received; do not analyze it."""
    report = report.strip() if isinstance(report, str) else ""
    code = code.strip() if isinstance(code, str) else ""
    if not report:
        raise ValueError("Report text is required.")
    if len(report) > MAX_REPORT_CHARS:
        raise ValueError("Report is too long (max %d characters)." % MAX_REPORT_CHARS)
    if len(code) > MAX_CODE_CHARS:
        raise ValueError("Code context is too long (max %d characters)." % MAX_CODE_CHARS)
    if language not in ("en", "ar"):
        language = "en"

    report_id = str(uuid.uuid4())
    now = _now()
    init_db()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO reports(id, created_at, updated_at, language, report, code, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'received')",
            (report_id, now, now, language, report, code),
        )
        _append_event(conn, report_id, "report_received", "local-user", {"status": "received"})
    return get_report(report_id)


def save_analysis(report_id: str, analysis: dict, actor: str = "meta-model") -> dict:
    """Save a normalized model recommendation; it never sets a human decision."""
    if not isinstance(analysis, dict):
        raise ValueError("Analysis must be a JSON object.")
    decision = analysis.get("decision")
    if decision not in DECISIONS:
        raise ValueError("Analysis contains an invalid suggested decision.")
    analysis_json = _json(analysis)
    now = _now()
    init_db()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            raise NotFound("Report not found.")
        if row["status"] == "reviewed":
            raise InvalidState("A reviewed report cannot be re-analyzed; create a new report instead.")
        conn.execute(
            "UPDATE reports SET status='analyzed', analysis_json=?, suggested_decision=?, updated_at=? "
            "WHERE id=?",
            (analysis_json, decision, now, report_id),
        )
        _append_event(conn, report_id, "analysis_completed", actor, {"suggested_decision": decision})
    return get_report(report_id)


def record_review(
    report_id: str,
    decision: str,
    reviewer: str = "",
    note: str = "",
) -> dict:
    """Record an explicit human decision separately from the model suggestion."""
    if decision not in DECISIONS:
        raise ValueError("Decision must be one of: %s." % ", ".join(sorted(DECISIONS)))
    reviewer = reviewer.strip() if isinstance(reviewer, str) else ""
    note = note.strip() if isinstance(note, str) else ""
    if len(reviewer) > MAX_REVIEWER_CHARS:
        raise ValueError("Reviewer label is too long.")
    if len(note) > MAX_NOTE_CHARS:
        raise ValueError("Review note is too long.")

    now = _now()
    init_db()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            raise NotFound("Report not found.")
        if row["status"] != "analyzed" and row["status"] != "reviewed":
            raise InvalidState("Run triage before recording a human review.")
        previous = conn.execute(
            "SELECT review_decision FROM reports WHERE id = ?", (report_id,)
        ).fetchone()["review_decision"]
        conn.execute(
            "UPDATE reports SET status='reviewed', review_decision=?, reviewer=?, review_note=?, updated_at=? "
            "WHERE id=?",
            (decision, reviewer, note, now, report_id),
        )
        _append_event(
            conn,
            report_id,
            "human_review_recorded",
            reviewer or "local-reviewer",
            {"previous_decision": previous, "review_decision": decision, "note": note},
        )
    return get_report(report_id)


def get_report(report_id: str) -> dict:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        raise NotFound("Report not found.")
    return _row_to_report(row)


def list_reports(status: str = "", query: str = "", limit: int = 50, offset: int = 0) -> list:
    """Return bounded summaries; full report/code are available only via get_report."""
    init_db()
    if status and status not in STATUSES:
        raise ValueError("Invalid report status.")
    try:
        limit = max(1, min(int(limit), 100))
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        raise ValueError("Limit and offset must be integers.")
    query = query.strip()[:200] if isinstance(query, str) else ""
    where, args = [], []
    if status:
        where.append("status = ?")
        args.append(status)
    if query:
        where.append("instr(lower(report), lower(?)) > 0")
        args.append(query)
    sql = "SELECT id, created_at, updated_at, language, report, status, suggested_decision, review_decision " \
          "FROM reports"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC, id LIMIT ? OFFSET ?"
    args.extend((limit, offset))
    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "language": row["language"],
            "summary": row["report"][:180],
            "status": row["status"],
            "suggested_decision": row["suggested_decision"],
            "review_decision": row["review_decision"],
        }
        for row in rows
    ]


def report_history(report_id: str) -> list:
    init_db()
    with _connect() as conn:
        exists = conn.execute("SELECT 1 FROM reports WHERE id = ?", (report_id,)).fetchone()
        if exists is None:
            raise NotFound("Report not found.")
        rows = conn.execute(
            "SELECT event_id, occurred_at, event_type, actor, details_json "
            "FROM report_events WHERE report_id = ? ORDER BY event_id",
            (report_id,),
        ).fetchall()
    return [
        {
            "event_id": row["event_id"],
            "occurred_at": row["occurred_at"],
            "event_type": row["event_type"],
            "actor": row["actor"],
            "details": json.loads(row["details_json"]),
        }
        for row in rows
    ]


def metrics() -> dict:
    """Aggregate workflow counts only; no report content is returned."""
    init_db()
    with _connect() as conn:
        status_rows = conn.execute("SELECT status, COUNT(*) AS n FROM reports GROUP BY status").fetchall()
        decision_rows = conn.execute(
            "SELECT suggested_decision, COUNT(*) AS n FROM reports "
            "WHERE suggested_decision IS NOT NULL GROUP BY suggested_decision"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    return {
        "total_reports": total,
        "by_status": {row["status"]: row["n"] for row in status_rows},
        "by_suggested_decision": {row["suggested_decision"]: row["n"] for row in decision_rows},
    }


def delete_report(report_id: str) -> bool:
    """Remove a report and its application-level history from the local database."""
    init_db()
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        if cursor.rowcount == 0:
            raise NotFound("Report not found.")
    return True
