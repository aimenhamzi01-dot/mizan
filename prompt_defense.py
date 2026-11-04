"""Prompt Injection Defense Layer for AI Security Workflows.

Protects against malicious instructions hidden inside untrusted inputs:
- User-submitted vulnerability reports
- HTTP responses and raw web content
- HTML/JavaScript pages
- Source code comments/docstrings
- Security evidence and external tool outputs

Provides:
- Deterministic heuristic detection of instruction injection / jailbreaks / delimiter escape
- Data/instruction separation & isolation tagging
- Safe evidence text extraction and sanitizer
- Tool invocation safety guardrails (prevents AI tool execution authorization)
"""
from __future__ import annotations

import html
import json
import re
from typing import Any

# Signatures for prompt injection and instruction overriding
INJECTION_SIGNATURES = [
    # English direct overrides
    (r"\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules)\b", "override_instructions"),
    (r"\bdisregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules)\b", "override_instructions"),
    (r"\bforget\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)\b", "override_instructions"),
    (r"\bdo\s+not\s+follow\s+(the\s+)?(instructions|rules|guidelines)\b", "override_instructions"),
    (r"\bnew\s+system\s+instruction(s)?\b", "fake_system_prompt"),
    (r"\byou\s+are\s+now\s+(an\s+unrestricted|a\s+different|in\s+DAN\s+mode|root|admin)\b", "persona_hijack"),
    (r"\bsystem\s*:\s*you\s+must\b", "impersonate_system_role"),
    (r"<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]", "token_delimiter_injection"),
    (r"\baccept\s+this\s+(finding|report|vulnerability)\s+(immediately|as\s+critical|without\s+review)\b", "verdict_coercion"),
    (r"\bmark\s+(this|it)\s+as\s+(confirmed|critical|accept)\b", "verdict_coercion"),
    (r"\bbypass\s+(all\s+)?(security|guardrails|checks|filters)\b", "guardrail_bypass"),
    (r"\bexec(ute)?\s+(the\s+following\s+)?(shell|bash|command|tool|python)\b", "unauthorized_tool_execution"),
    (r"\bauthorize\s+(the\s+)?(scan|attack|execution|deletion)\b", "unauthorized_authorization"),

    # Arabic direct overrides
    (r"تجاهل\s+(جميع\s+)?(التعليمات|الأوامر|القواعد)\s+السابقة", "override_instructions_ar"),
    (r"انسَ\s+(جميع\s+)?(التعليمات|الأوامر)\s+السابقة", "override_instructions_ar"),
    (r"أنت\s+الآن\s+في\s+وضع", "persona_hijack_ar"),
    (r"اقبل\s+(هذا\s+)?(التقرير|الثغرة)\s+(فورا|بدون\s+مراجعة)", "verdict_coercion_ar"),
    (r"تجاوز\s+(كل\s+)?(حواجز\s+الحماية|الفحوصات)", "guardrail_bypass_ar"),
]

COMPILED_INJECTION_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), cat) for pattern, cat in INJECTION_SIGNATURES
]


class InjectionAnalysisResult:
    """Holds results of prompt injection inspection."""

    def __init__(
        self,
        is_suspicious: bool,
        risk_score: float,
        detected_patterns: list[dict[str, str]],
        sanitized_summary: str,
    ):
        self.is_suspicious = is_suspicious
        self.risk_score = min(1.0, max(0.0, risk_score))
        self.detected_patterns = detected_patterns
        self.sanitized_summary = sanitized_summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_suspicious": self.is_suspicious,
            "risk_score": round(self.risk_score, 3),
            "detected_patterns": self.detected_patterns,
            "sanitized_summary": self.sanitized_summary,
        }


def inspect_text_for_injection(text: str) -> InjectionAnalysisResult:
    """Analyze untrusted text for prompt injection and instruction override attempts."""
    if not isinstance(text, str) or not text.strip():
        return InjectionAnalysisResult(False, 0.0, [], "Text is empty.")

    detected: list[dict[str, str]] = []
    text_lower = text.lower()

    for pattern, category in COMPILED_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_text = match.group(0)
            detected.append({
                "category": category,
                "matched_text": matched_text[:80],
                "position": f"{match.start()}:{match.end()}",
            })

    # Additional structural checks: delimiter smuggling / excessive markdown formatting
    if "<system>" in text_lower or "</system>" in text_lower or "```system" in text_lower:
        detected.append({
            "category": "system_tag_smuggling",
            "matched_text": "System tag enclosure detected in untrusted content",
            "position": "structural",
        })

    is_suspicious = len(detected) > 0
    # Score calculation: 0.3 per match, capped at 1.0
    risk_score = min(1.0, len(detected) * 0.35)

    summary = (
        f"Detected {len(detected)} suspicious instruction pattern(s). Prompt injection suspected."
        if is_suspicious
        else "No known prompt injection patterns identified."
    )

    return InjectionAnalysisResult(is_suspicious, risk_score, detected, summary)


def isolate_untrusted_content(content: str, label: str = "untrusted_data") -> str:
    """Enclose untrusted content inside strict, unambiguous boundaries.

    Prevents untrusted text from breaking out of prompt data regions.
    Uses JSON escaping + tagged boundaries.
    """
    safe_content = json.dumps(content, ensure_ascii=False)
    # Remove control unicode characters
    safe_content = safe_content.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    return f"<{label}>\n{safe_content}\n</{label}>"


def safe_evidence_extract(text: str, max_chars: int = 500) -> str:
    """Safely extract and normalize an evidence excerpt, neutralizing active control characters."""
    if not isinstance(text, str):
        return ""
    # Strip dangerous control characters while preserving readability
    cleaned = "".join(ch for ch in text if ch.isprintable() or ch in "\n\r\t")
    return cleaned[:max_chars].strip()


def validate_ai_tool_authorization(requested_action: str) -> bool:
    """Hard guardrail: AI is NEVER authorized to initiate autonomous actions or shell commands."""
    blocked_actions = {
        "shell_exec",
        "bash",
        "system_command",
        "drop_database",
        "delete_user",
        "bypass_scope",
        "scan_start_automatic",
    }
    action_norm = requested_action.strip().lower()
    if action_norm in blocked_actions:
        return False
    return False  # Zero automated tool actions permitted by AI
