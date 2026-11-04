"""Evidence Intelligence Engine for Mizan.

Centralized evidence management with cryptographic integrity, provenance tracking,
normalization, duplicate detection, and finding verification.

Key principles:
- Evidence must originate from observable technical data (HTTP responses, TLS certs, DNS, source code).
- AI explanation is never treated as independent proof.
- Every evidence item has a SHA-256 cryptographic digest.
- No vulnerability is marked 'confirmed' without sufficient verifiable evidence.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any

VALID_EVIDENCE_TYPES = {
    "http_response",
    "http_header",
    "tls_certificate",
    "dns_record",
    "source_code_snippet",
    "static_analysis_finding",
    "scanner_observation",
}

VERIFICATION_STATUSES = {
    "verified",          # Cryptographically and technically validated
    "unverified",        # Missing or failed matching against observable target data
    "contradictory",     # Source data actively contradicts finding claim
    "insufficient",      # Fragmentary or incomplete observation
}


class EvidenceItem:
    """Represents a single verifiable unit of technical security evidence."""

    def __init__(
        self,
        evidence_id: str | None,
        assessment_id: str,
        asset_id: str,
        finding_id: str,
        evidence_type: str,
        original_source: str,
        collection_method: str,
        raw_content: str,
        normalized_content: str | None = None,
        verification_status: str = "unverified",
        confidence_score: float = 0.5,
        collected_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.evidence_id = evidence_id or f"evi-{uuid.uuid4().hex[:12]}"
        self.assessment_id = assessment_id
        self.asset_id = asset_id
        self.finding_id = finding_id

        if evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence type: {evidence_type}")
        self.evidence_type = evidence_type

        self.original_source = str(original_source)[:512]
        self.collection_method = str(collection_method)[:128]
        self.raw_content = str(raw_content)

        # Normalized representation for consistent comparison
        self.normalized_content = (
            str(normalized_content) if normalized_content is not None
            else self._normalize_content(self.raw_content)
        )

        # Cryptographic SHA-256 digest of normalized content
        self.sha256_hash = hashlib.sha256(self.normalized_content.encode("utf-8")).hexdigest()

        if verification_status not in VERIFICATION_STATUSES:
            raise ValueError(f"Invalid verification status: {verification_status}")
        self.verification_status = verification_status

        self.confidence_score = max(0.0, min(1.0, float(confidence_score)))
        self.collected_at = collected_at or datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.metadata = metadata or {}

    @staticmethod
    def _normalize_content(content: str) -> str:
        """Strip trailing spaces and normalize newlines for stable hashing."""
        lines = [line.rstrip() for line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
        return "\n".join(lines).strip()

    def verify_integrity(self) -> bool:
        """Verify that current normalized content matches the stored SHA-256 digest."""
        computed = hashlib.sha256(self.normalized_content.encode("utf-8")).hexdigest()
        return computed == self.sha256_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "assessment_id": self.assessment_id,
            "asset_id": self.asset_id,
            "finding_id": self.finding_id,
            "evidence_type": self.evidence_type,
            "original_source": self.original_source,
            "collection_method": self.collection_method,
            "raw_content": self.raw_content,
            "normalized_content": self.normalized_content,
            "sha256_hash": self.sha256_hash,
            "verification_status": self.verification_status,
            "confidence_score": round(self.confidence_score, 3),
            "collected_at": self.collected_at,
            "metadata": self.metadata,
            "integrity_valid": self.verify_integrity(),
        }


class EvidenceRegistry:
    """Manages collection, deduplication, contradiction tracking, and verification of evidence."""

    def __init__(self):
        self._items: dict[str, EvidenceItem] = {}
        self._hash_index: dict[str, str] = {}  # sha256 -> evidence_id

    def add_evidence(self, item: EvidenceItem) -> EvidenceItem:
        """Register an evidence item with duplicate detection."""
        if not item.verify_integrity():
            raise ValueError("Evidence item integrity check failed upon registration.")

        existing_id = self._hash_index.get(item.sha256_hash)
        if existing_id and existing_id in self._items:
            # Duplicate technical evidence detected, link metadata
            existing_item = self._items[existing_id]
            existing_item.metadata.setdefault("duplicates_count", 0)
            existing_item.metadata["duplicates_count"] += 1
            return existing_item

        self._items[item.evidence_id] = item
        self._hash_index[item.sha256_hash] = item.evidence_id
        return item

    def get_evidence(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def list_evidence_for_finding(self, finding_id: str) -> list[EvidenceItem]:
        return [item for item in self._items.values() if item.finding_id == finding_id]

    def list_evidence_for_assessment(self, assessment_id: str) -> list[EvidenceItem]:
        return [item for item in self._items.values() if item.assessment_id == assessment_id]

    def evaluate_finding_support(self, finding_id: str) -> dict[str, Any]:
        """Evaluate whether a finding is backed by verified technical evidence.

        Determines if a finding has confirmed status, needs more info, or is contradicted.
        """
        items = self.list_evidence_for_finding(finding_id)
        if not items:
            return {
                "support_level": "insufficient_evidence",
                "recommended_status": "needs_more_evidence",
                "verified_count": 0,
                "contradictory_count": 0,
                "items": [],
            }

        verified = [it for it in items if it.verification_status == "verified" and it.verify_integrity()]
        contradictory = [it for it in items if it.verification_status == "contradictory"]

        if contradictory:
            return {
                "support_level": "contradicted",
                "recommended_status": "rejected",
                "verified_count": len(verified),
                "contradictory_count": len(contradictory),
                "reason": "Observable evidence contradicts the claimed vulnerability.",
                "items": [it.to_dict() for it in items],
            }

        if len(verified) >= 1 and any(it.confidence_score >= 0.8 for it in verified):
            return {
                "support_level": "confirmed",
                "recommended_status": "confirmed",
                "verified_count": len(verified),
                "contradictory_count": 0,
                "reason": "Backed by verifiable technical observations with high confidence.",
                "items": [it.to_dict() for it in items],
            }

        return {
            "support_level": "partial",
            "recommended_status": "likely",
            "verified_count": len(verified),
            "contradictory_count": 0,
            "reason": "Partial technical evidence available; requires analyst confirmation.",
            "items": [it.to_dict() for it in items],
        }
