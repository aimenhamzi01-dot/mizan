"""Multi-dimensional Risk Assessment Engine for Mizan.

Maintains technical severity and evidence confidence as distinct, non-conflated dimensions:
- Technical Severity: none, low, medium, high, critical
- Evidence Confidence: confirmed, likely, potential, false_positive, needs_more_evidence

Considers CVSS-compatible metrics:
- Exploitability (network, local, adjacent)
- Exposure / Reachability (public, internal, restricted)
- Asset Importance / Criticality (low, medium, high, mission_critical)
- Attack Prerequisites & Privileges Required (none, low, high)
- Evidence backing confidence

Supports explicit analyst overrides with mandatory documented justification and audit records.
"""
from __future__ import annotations

import datetime
from typing import Any

SEVERITY_LEVELS = {"none": 0.0, "low": 2.5, "medium": 5.5, "high": 8.0, "critical": 9.8}
CONFIDENCE_LEVELS = {
    "confirmed": 1.0,
    "likely": 0.75,
    "potential": 0.5,
    "needs_more_evidence": 0.25,
    "false_positive": 0.0,
}

EXPOSURE_WEIGHTS = {"public": 1.0, "restricted": 0.7, "internal": 0.4}
ASSET_IMPORTANCE_WEIGHTS = {"mission_critical": 1.2, "high": 1.0, "medium": 0.8, "low": 0.5}


class RiskScore:
    """Encapsulates calculated risk metrics with explanation and analyst overrides."""

    def __init__(
        self,
        base_severity: str,
        confidence: str,
        overall_score: float,
        risk_level: str,
        rationale: str,
        factors: dict[str, Any],
        overridden: bool = False,
        override_reason: str = "",
        overridden_by: str = "",
        overridden_at: str | None = None,
    ):
        self.base_severity = base_severity
        self.confidence = confidence
        self.overall_score = round(max(0.0, min(10.0, overall_score)), 1)
        self.risk_level = risk_level
        self.rationale = rationale
        self.factors = factors
        self.overridden = overridden
        self.override_reason = override_reason
        self.overridden_by = overridden_by
        self.overridden_at = overridden_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_severity": self.base_severity,
            "confidence": self.confidence,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "rationale": self.rationale,
            "factors": self.factors,
            "overridden": self.overridden,
            "override_reason": self.override_reason,
            "overridden_by": self.overridden_by,
            "overridden_at": self.overridden_at,
        }


def calculate_risk(
    base_severity: str,
    confidence: str,
    exposure: str = "public",
    asset_importance: str = "high",
    attack_vector: str = "network",
    privileges_required: str = "none",
) -> RiskScore:
    """Calculate multi-dimensional risk score.

    Ensures that high technical severity with weak evidence does NOT produce
    a critical overall rating without human confirmation.
    """
    sev_key = base_severity.lower() if base_severity.lower() in SEVERITY_LEVELS else "none"
    conf_key = confidence.lower() if confidence.lower() in CONFIDENCE_LEVELS else "needs_more_evidence"
    exp_key = exposure.lower() if exposure.lower() in EXPOSURE_WEIGHTS else "public"
    imp_key = asset_importance.lower() if asset_importance.lower() in ASSET_IMPORTANCE_WEIGHTS else "high"

    base_val = SEVERITY_LEVELS[sev_key]
    conf_factor = CONFIDENCE_LEVELS[conf_key]
    exp_factor = EXPOSURE_WEIGHTS[exp_key]
    imp_factor = ASSET_IMPORTANCE_WEIGHTS[imp_key]

    # Attack vector modifier
    av_factor = 1.0 if attack_vector.lower() == "network" else 0.7

    # Privileges modifier
    pr_factor = 1.0 if privileges_required.lower() == "none" else 0.85

    # Core risk computation:
    # If confidence is needs_more_evidence or false_positive, risk score is damped
    # to avoid false panic while retaining visibility.
    if conf_key == "false_positive":
        calculated = 0.0
    elif conf_key == "needs_more_evidence":
        # Capped score until verifiable evidence is collected
        calculated = min(4.0, base_val * 0.4 * exp_factor)
    else:
        calculated = base_val * conf_factor * exp_factor * imp_factor * av_factor * pr_factor

    score = round(max(0.0, min(10.0, calculated)), 1)

    if score >= 9.0 and conf_key == "confirmed":
        risk_level = "critical"
    elif score >= 7.0:
        risk_level = "high"
    elif score >= 4.0:
        risk_level = "medium"
    elif score > 0.0:
        risk_level = "low"
    else:
        risk_level = "none"

    rationale_parts = [
        f"Technical severity rated as '{sev_key.upper()}' (base {base_val}).",
        f"Evidence confidence evaluated as '{conf_key.replace('_', ' ').title()}' (factor {conf_factor}).",
        f"Exposure is '{exp_key}' (factor {exp_factor}), on '{imp_key}' importance asset.",
    ]
    if conf_key in ("needs_more_evidence", "potential"):
        rationale_parts.append("Risk score is bounded because technical evidence is not yet confirmed.")

    return RiskScore(
        base_severity=sev_key,
        confidence=conf_key,
        overall_score=score,
        risk_level=risk_level,
        rationale=" ".join(rationale_parts),
        factors={
            "base_severity": sev_key,
            "confidence": conf_key,
            "exposure": exp_key,
            "asset_importance": imp_key,
            "attack_vector": attack_vector,
            "privileges_required": privileges_required,
        },
    )


def apply_analyst_override(
    current_risk: RiskScore,
    new_severity: str,
    new_confidence: str,
    reason: str,
    analyst_username: str,
) -> RiskScore:
    """Apply an analyst override to risk classification with mandatory justification."""
    reason = str(reason).strip()
    if not reason or len(reason) < 10:
        raise ValueError("A substantive override reason (minimum 10 characters) is required.")

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    recalculated = calculate_risk(
        base_severity=new_severity,
        confidence=new_confidence,
        exposure=current_risk.factors.get("exposure", "public"),
        asset_importance=current_risk.factors.get("asset_importance", "high"),
        attack_vector=current_risk.factors.get("attack_vector", "network"),
        privileges_required=current_risk.factors.get("privileges_required", "none"),
    )

    recalculated.overridden = True
    recalculated.override_reason = reason
    recalculated.overridden_by = analyst_username
    recalculated.overridden_at = now_iso
    recalculated.rationale += f" [Analyst Override by {analyst_username}: {reason}]"

    return recalculated
