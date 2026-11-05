"""Adversarial Prompt Injection Evaluator and Evidence State Engine.

Formalizes:
1. Adversarial prompt injection evaluation across 12 distinct attack families.
2. Distinct evidence states:
   - OBSERVED: Technical excerpt observed in input or probe.
   - REPRODUCIBLE: Step-by-step reproduction payload verified.
   - VALIDATED: Cryptographically matched against source/traffic and non-contradicted.
   - HUMAN_CONFIRMED: Signed disposition by authenticated human analyst.
"""
from __future__ import annotations

import re
from typing import Any
import prompt_defense
import triage

# 12 Adversarial Attack Families
ATTACK_FAMILIES = [
    "instruction_override",
    "system_prompt_extraction",
    "fake_developer_instruction",
    "authority_impersonation",
    "evidence_fabrication",
    "forced_acceptance",
    "severity_manipulation",
    "output_schema_manipulation",
    "nested_delimiter_escape",
    "multilingual_injection",
    "encoded_instruction",
    "mixed_content_coercion",
]

EVIDENCE_STATES = {"OBSERVED", "REPRODUCIBLE", "VALIDATED", "HUMAN_CONFIRMED", "UNSUPPORTED"}


class EvidenceStateEvaluator:
    """Evaluates evidence state transitions and citation validity."""

    @staticmethod
    def evaluate_citation(source_text: str, quoted_excerpt: str) -> dict[str, Any]:
        """Check exact quote presence and determine preliminary state."""
        if not quoted_excerpt or not isinstance(quoted_excerpt, str):
            return {"matched": False, "state": "UNSUPPORTED", "occurrences": 0}

        count = source_text.count(quoted_excerpt)
        if count == 0:
            return {"matched": False, "state": "UNSUPPORTED", "occurrences": 0}

        return {
            "matched": True,
            "state": "OBSERVED",
            "occurrences": count,
            "ambiguous": count > 1,
        }

    @staticmethod
    def promote_evidence_state(current_state: str, action: str) -> str:
        """Enforce strict evidence state lifecycle.

        OBSERVED -> REPRODUCIBLE -> VALIDATED -> HUMAN_CONFIRMED
        """
        transitions = {
            ("OBSERVED", "reproduce"): "REPRODUCIBLE",
            ("REPRODUCIBLE", "validate"): "VALIDATED",
            ("VALIDATED", "confirm_human"): "HUMAN_CONFIRMED",
        }
        return transitions.get((current_state, action), current_state)


def evaluate_adversarial_suite(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Run adversarial prompt injection evaluation across test cases."""
    results = []
    attacks_tested = 0
    attacks_caught = 0
    false_positives = 0

    for c in cases:
        report_text = c.get("report", "")
        ground_truth_injection = c.get("ground_truth", {}).get("contains_prompt_injection", False)

        # Inspect using prompt defense
        inspection = prompt_defense.inspect_text_for_injection(report_text)
        detected = inspection.is_suspicious

        if ground_truth_injection:
            attacks_tested += 1
            if detected:
                attacks_caught += 1
        else:
            if detected:
                false_positives += 1

        results.append({
            "case_id": c["case_id"],
            "title": c["title"],
            "category": c["category"],
            "ground_truth_injection": ground_truth_injection,
            "detected_injection": detected,
            "risk_score": inspection.risk_score,
            "detected_patterns": inspection.detected_patterns,
            "defense_passed": (detected == ground_truth_injection),
        })

    recall = round(attacks_caught / attacks_tested, 4) if attacks_tested > 0 else 1.0
    precision = round(attacks_caught / (attacks_caught + false_positives), 4) if (attacks_caught + false_positives) > 0 else 1.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return {
        "attacks_tested": attacks_tested,
        "attacks_caught": attacks_caught,
        "false_positives": false_positives,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "cases_evaluated": len(cases),
        "results": results,
    }
