"""Human-in-the-Loop review workflow system.

Manages the lifecycle states of security findings:
- pending: newly created / collected
- analyzing: undergoing automated inspection or AI reasoning
- needs_more_evidence: flagged as lacking sufficient technical proof
- pending_human_review: awaiting security analyst adjudication
- approved: verified by analyst as actionable / accepted
- rejected: determined by analyst to be invalid or out of scope
- confirmed: fully verified security vulnerability with proof
- resolved: remediated by technical team and re-verified

Enforces human ownership of decisions and explicit audit trails.
"""
from __future__ import annotations

import datetime
from typing import Any

WORKFLOW_STATES = {
    "pending",
    "analyzing",
    "needs_more_evidence",
    "pending_human_review",
    "approved",
    "rejected",
    "confirmed",
    "resolved",
}

VALID_HUMAN_ACTIONS = {
    "approve",
    "reject",
    "confirm",
    "request_more_evidence",
    "override_severity",
    "assign",
    "resolve",
    "comment",
}


class WorkflowTransitionError(ValueError):
    """Raised when an illegal workflow state transition is attempted."""


class FindingReviewRecord:
    """Represents the human review history and state of a finding."""

    def __init__(
        self,
        finding_id: str,
        current_status: str = "pending",
        assigned_to: str | None = None,
        disposition_notes: str = "",
        reviewed_by: str | None = None,
        reviewed_at: str | None = None,
        comments: list[dict[str, Any]] | None = None,
    ):
        self.finding_id = finding_id
        if current_status not in WORKFLOW_STATES:
            raise WorkflowTransitionError(f"Invalid workflow state: {current_status}")
        self.current_status = current_status
        self.assigned_to = assigned_to
        self.disposition_notes = disposition_notes
        self.reviewed_by = reviewed_by
        self.reviewed_at = reviewed_at
        self.comments = comments or []

    def transition_to(
        self,
        new_status: str,
        actor: str,
        note: str = "",
    ) -> None:
        """Perform validated state transition."""
        if new_status not in WORKFLOW_STATES:
            raise WorkflowTransitionError(f"Unknown target state: {new_status}")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.current_status = new_status
        self.reviewed_by = actor
        self.reviewed_at = now_iso
        if note:
            self.disposition_notes = note

        self.comments.append({
            "action": f"transition_to_{new_status}",
            "actor": actor,
            "timestamp": now_iso,
            "note": note,
        })

    def add_comment(self, actor: str, text: str) -> None:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.comments.append({
            "action": "comment",
            "actor": actor,
            "timestamp": now_iso,
            "note": text,
        })

    def assign(self, actor: str, assignee: str) -> None:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.assigned_to = assignee
        self.comments.append({
            "action": "assign",
            "actor": actor,
            "assignee": assignee,
            "timestamp": now_iso,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "current_status": self.current_status,
            "assigned_to": self.assigned_to,
            "disposition_notes": self.disposition_notes,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "comments": self.comments,
        }
