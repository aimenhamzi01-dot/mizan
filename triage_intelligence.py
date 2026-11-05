"""Deterministic, explainable intelligence helpers for Mizan Phase 2B.

This module never calls a model, executes submitted code, or changes the human
review decision. It turns normalized model output and bounded case context into
review aids: duplicate candidates, classification, prioritization, missing-
evidence requests, contradictions, and an explanation with limitations.
"""
from __future__ import annotations

import json
import re
from difflib import SequenceMatcher

_WORD_RE = re.compile(r"[\w./:-]{2,}", re.UNICODE)
_URL_RE = re.compile(r"(?:https?://[^\s\]'\"]+|/[\w./{}:$-]+)", re.UNICODE)

_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "into", "when", "then", "can",
    "are", "was", "were", "has", "have", "not", "may", "any", "via", "http", "https",
    "api", "request", "report", "issue", "vulnerability", "possible", "user", "مستخدم",
    "في", "من", "على", "إلى", "هذا", "هذه", "تقرير", "ثغرة", "قد", "يمكن",
}

_TYPE_PATTERNS = {
    "sqli": ("sql injection", "sqli", "حقن sql", "select *", "union select"),
    "xss": ("cross-site scripting", "stored xss", "reflected xss", " xss", "xss ", "حقن javascript"),
    "idor": ("idor", "insecure direct object", "another user", "مستخدم آخر", "ليست مملوكة"),
    "ssrf": ("ssrf", "server-side request forgery", "internal metadata"),
    "path-traversal": ("path traversal", "directory traversal", "../", "تجاوز المسار"),
    "rce": ("remote code execution", "command execution", "arbitrary command", "تنفيذ أوامر"),
    "auth-bypass": ("authentication bypass", "authorization bypass", "تجاوز المصادقة", "تجاوز التفويض"),
    "csrf": ("csrf", "cross-site request forgery"),
}

_ROOT_CAUSE_PATTERNS = {
    "missing-authorization": ("no ownership", "missing authorization", "access control", "authorization check", "authorization failure", "object authorization", "another user", "not owned", "مستخدم آخر", "ليست مملوكة", "صلاحيات", "ملكية"),
    "unsafe-query": ("string concatenation", "raw sql", "unsanitized", "parameterized", "استعلام"),
    "unsafe-path-normalization": ("path normalization", "url normalization", "canonicalization", "تطبيع المسار"),
    "unsafe-output-encoding": ("output encoding", "escape", "unescaped", "ترميز المخرجات"),
    "unsafe-command-invocation": ("shell", "subprocess", "command", "أمر"),
    "missing-csrf-protection": ("csrf token", "anti-forgery", "رمز csrf"),
}

_SEVERITY_WEIGHT = {"none": 0, "low": 20, "medium": 45, "high": 70, "critical": 90}


def _text(*values) -> str:
    return " ".join(value for value in values if isinstance(value, str)).lower()


def _tokens(text: str) -> list[str]:
    """Return unique terms in a stable order for normalization and similarity."""
    return sorted({item for item in _WORD_RE.findall(text.lower()) if item not in _STOPWORDS and len(item) > 2})


def _jaccard(left, right) -> float:
    left_set, right_set = set(left), set(right)
    union = left_set | right_set
    return len(left_set & right_set) / len(union) if union else 0.0


def _matches(text: str, patterns: tuple[str, ...]) -> list[str]:
    return sorted(pattern for pattern in patterns if pattern.lower() in text)


def extract_signals(report: str, code: str = "") -> dict:
    """Extract conservative lexical signals; these are hints, not proof."""
    text = _text(report, code)
    types = sorted(name for name, patterns in _TYPE_PATTERNS.items() if _matches(text, patterns))
    roots = sorted(name for name, patterns in _ROOT_CAUSE_PATTERNS.items() if _matches(text, patterns))
    assets = sorted(set(_URL_RE.findall(report or "")))
    report_text = _text(report)
    code_text = _text(code)
    return {
        "tokens": _tokens(text),
        "report_tokens": _tokens(report_text),
        "code_tokens": _tokens(code_text),
        "report_normalized": " ".join(_tokens(report_text)),
        "code_normalized": " ".join(_tokens(code_text)),
        "vulnerability_types": types,
        "root_causes": roots,
        "assets": sorted(assets)[:20],
    }


def _similarity(current: dict, other: dict) -> tuple[float, list[str], dict]:
    reasons = []
    report_text_score = SequenceMatcher(None, current["report_normalized"], other["report_normalized"]).ratio()
    vocabulary_score = _jaccard(current["report_tokens"], other["report_tokens"])
    code_score = SequenceMatcher(None, current["code_normalized"], other["code_normalized"]).ratio() if current["code_normalized"] and other["code_normalized"] else 0.0
    type_overlap = sorted(set(current["vulnerability_types"]) & set(other["vulnerability_types"]))
    root_overlap = sorted(set(current["root_causes"]) & set(other["root_causes"]))
    asset_overlap = sorted(set(current["assets"]) & set(other["assets"]))
    signals = {
        "report_text": round(report_text_score, 4),
        "technical_vocabulary": round(vocabulary_score, 4),
        "vulnerability_type": 1.0 if type_overlap else 0.0,
        "affected_asset": 1.0 if asset_overlap else 0.0,
        "root_cause": 1.0 if root_overlap else 0.0,
        "relevant_code": round(code_score, 4),
    }
    if report_text_score >= 0.65:
        reasons.append("report text similarity: %.2f" % report_text_score)
    if vocabulary_score >= 0.35:
        reasons.append("technical vocabulary similarity: %.2f" % vocabulary_score)
    if type_overlap:
        reasons.append("shared vulnerability type: " + ", ".join(type_overlap))
    if root_overlap:
        reasons.append("shared root-cause signal: " + ", ".join(root_overlap))
    if asset_overlap:
        reasons.append("shared affected asset: " + ", ".join(asset_overlap[:3]))
    if code_score >= 0.60:
        reasons.append("relevant code similarity: %.2f" % code_score)
    score = (
        0.25 * report_text_score + 0.20 * vocabulary_score +
        0.20 * signals["vulnerability_type"] + 0.15 * signals["affected_asset"] +
        0.10 * signals["root_cause"] + 0.10 * code_score
    )
    # A shared endpoint or generic shared code alone is not enough. Code
    # similarity needs corroborating technical context from type, root cause,
    # vocabulary, or report text.
    code_context = code_score >= 0.60 and bool(
        type_overlap or root_overlap or report_text_score >= 0.45 or vocabulary_score >= 0.35
    )
    eligible = bool(type_overlap or root_overlap or code_context or (report_text_score >= 0.82 and vocabulary_score >= 0.55))
    return min(1.0, score), reasons, {"signals": signals, "eligible": eligible}


def duplicate_candidates(report: str, code: str, existing_reports: list[dict] | None = None, *, limit: int = 5) -> list[dict]:
    """Return possible duplicates only; never decide the duplicate disposition."""
    current = extract_signals(report, code)
    candidates = []
    for item in (existing_reports or [])[:100]:
        if not isinstance(item, dict):
            continue
        other_report = item.get("report", item.get("summary", ""))
        other_code = item.get("code", "")
        if not isinstance(other_report, str) or len(other_report) > 20_000:
            continue
        other = extract_signals(other_report, other_code if isinstance(other_code, str) else "")
        score, reasons, details = _similarity(current, other)
        if score >= 0.30 and reasons and details["eligible"]:
            candidates.append({
                "report_id": str(item.get("id", ""))[:120],
                "similarity": round(score, 4),
                "reasons": reasons,
                "confidence": "high" if score >= 0.78 else "medium",
                "signals": details["signals"],
                "human_confirmation_required": True,
            })
    candidates.sort(key=lambda item: (
        -item["similarity"], item["report_id"],
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    ))
    return candidates[:limit]


def classify(analysis: dict) -> dict:
    """Map advisory fields to a review label without changing the disposition."""
    verification = analysis.get("code_verification")
    citation = analysis.get("citation_integrity")
    decision = analysis.get("decision")
    severity = analysis.get("severity")
    noise = analysis.get("noise")
    reasoning = _text(analysis.get("decision_reasoning"), analysis.get("claimed_impact"), *analysis.get("missing_context", []))
    if verification == "contradicted":
        label = "technically-contradicted"
    elif any(term in reasoning for term in ("out of scope", "out-of-scope", "not in scope", "خارج النطاق")):
        label = "out-of-scope"
    elif noise == "scanner-dump":
        label = "informative"
    elif verification == "unverifiable" or citation != "verified" or decision == "need-info":
        label = "insufficient-evidence"
    elif severity == "none":
        label = "informative"
    elif verification == "supported" and citation == "verified" and decision == "accept":
        label = "supported-finding"
    else:
        label = "potential-finding"
    return {
        "label": label,
        "basis": [
            "code_verification=" + str(verification),
            "citation_integrity=" + str(citation),
            "suggested_decision=" + str(decision),
            "administrative_rejection_is_not_false_positive=true",
        ],
        "is_final_decision": False,
    }


def missing_evidence(analysis: dict, report: str, code: str) -> list[dict]:
    """Generate concrete, bounded requests based on observable gaps."""
    requests = []
    verification = analysis.get("code_verification")
    if verification == "unverifiable" and not code.strip():
        requests.append({"key": "relevant-code", "request": "Provide the smallest relevant source/configuration excerpt, with secrets removed."})
    if verification in {"unverifiable", "contradicted"}:
        requests.append({"key": "runtime-evidence", "request": "Provide a redacted response, log, or reproducible observation showing whether the claimed behavior occurs."})
    text = _text(report, code)
    if any(word in text for word in ("unauthenticated", "anonymous", "بدون مصادقة")):
        requests.append({"key": "authorization-state", "request": "State the authentication and authorization state used during reproduction."})
    if any(word in text for word in ("rce", "remote code execution", "command execution", "تنفيذ أوامر")):
        requests.append({"key": "execution-conditions", "request": "Provide the exact configuration and process privileges required for the claimed execution impact."})
    if not extract_signals(report, code)["assets"]:
        requests.append({"key": "affected-asset", "request": "Identify the affected route, component, or asset without sharing credentials or private data."})
    if analysis.get("citation_integrity") != "verified":
        requests.append({"key": "source-linked-evidence", "request": "Replace unsupported quotations with exact excerpts from the supplied report or code."})
    unique = {}
    for item in requests:
        unique[item["key"]] = item
    return list(unique.values())[:8]


def contradictions(analysis: dict, report: str, code: str) -> list[dict]:
    """Surface inconsistencies; never resolve them silently."""
    items = []
    if analysis.get("code_verification") == "contradicted":
        items.append({"type": "code-vs-claim", "severity": "high", "detail": "The model marked the supplied code as contradicting the report claim."})
    if analysis.get("severity") in {"high", "critical"} and analysis.get("code_verification") != "supported":
        items.append({"type": "severity-vs-verification", "severity": "high", "detail": "A high severity assignment lacks supported code verification."})
    if analysis.get("decision") == "accept" and analysis.get("code_verification") != "supported":
        items.append({"type": "decision-vs-verification", "severity": "high", "detail": "An accept recommendation conflicts with code verification that is not supported."})
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), list) else []
    if any(item.get("relation") == "contradicts" for item in evidence if isinstance(item, dict)):
        items.append({"type": "evidence-relation", "severity": "medium", "detail": "At least one cited evidence item is explicitly marked as contradicting the claim."})
    if analysis.get("noise") == "scanner-dump" and analysis.get("decision") == "accept":
        items.append({"type": "scanner-vs-decision", "severity": "medium", "detail": "A scanner-dump classification conflicts with an accept recommendation."})
    if analysis.get("severity") in {"high", "critical"} and analysis.get("citation_integrity") != "verified":
        items.append({"type": "severity-vs-evidence", "severity": "medium", "detail": "High impact is suggested while source-linked evidence is not verified."})
    return items


def prioritize(analysis: dict, missing: list[dict], contradictions_found: list[dict]) -> dict:
    severity = _SEVERITY_WEIGHT.get(analysis.get("severity"), 0)
    evidence = 25 if analysis.get("citation_integrity") == "verified" else 8
    verification = {"supported": 20, "unverifiable": 5, "contradicted": 0}.get(analysis.get("code_verification"), 0)
    confidence = verification
    exploitability = 15 if any(word in _text(analysis.get("claim"), analysis.get("claimed_impact")) for word in ("rce", "remote code", "account takeover", "exfiltration", "تنفيذ", "استيلاء")) else 5
    score = min(100, severity * 0.45 + evidence + verification + exploitability)
    if contradictions_found:
        score = max(0, score - 12)
    if missing:
        score = max(0, score - min(12, len(missing) * 2))
    if analysis.get("noise") == "scanner-dump":
        score = min(score, 35)
    band = "critical" if score >= 80 else "high" if score >= 60 else "normal" if score >= 35 else "low"
    return {
        "score": round(score, 2),
        "band": band,
        "factors": {
            "severity": severity,
            "evidence_quality": evidence,
            "verification": verification,
            "confidence": confidence,
            "exploitability": exploitability,
            "missing_evidence_penalty": min(12, len(missing) * 2),
            "contradiction_penalty": 12 if contradictions_found else 0,
            "scanner_cap": 35 if analysis.get("noise") == "scanner-dump" else None,
        },
        "human_review_required": True,
    }


def duplicate_status(candidates: list[dict]) -> dict:
    """Summarize duplicate analysis without changing technical classification."""
    strongest = candidates[0] if candidates else None
    return {
        "status": "possible-duplicate" if strongest else "no-duplicate-candidate",
        "candidate_count": len(candidates),
        "strongest_candidate": strongest,
        "similarity_score": strongest["similarity"] if strongest else 0.0,
        "matching_signals": strongest.get("signals", {}) if strongest else {},
        "human_confirmation_required": bool(strongest),
    }


def enrich(analysis: dict, report: str, code: str = "", existing_reports: list[dict] | None = None) -> dict:
    """Attach Phase 2B review aids to a normalized analysis."""
    result = dict(analysis)
    missing = missing_evidence(result, report, code)
    contradictions_found = contradictions(result, report, code)
    candidates = duplicate_candidates(report, code, existing_reports)
    result["triage_intelligence"] = {
        "schema_version": "phase-2b.1-v1",
        "classification": classify(result),
        "duplicate_candidates": candidates,
        "duplicate": duplicate_status(candidates),
        "prioritization": prioritize(result, missing, contradictions_found),
        "missing_evidence": missing,
        "contradictions": contradictions_found,
        "explainability": {
            "reasoning": result.get("decision_reasoning", ""),
            "supporting_evidence": [
                {"source": item.get("source"), "quote": item.get("quote"), "verified": item.get("verified")}
                for item in result.get("evidence", []) if isinstance(item, dict)
            ],
            "uncertainty": result.get("missing_context", []) + [item["request"] for item in missing],
            "limitations": [
                "Similarity is a review signal, not proof of duplication.",
                "Literal citation matching does not establish truth or exploitability.",
                "Priority is a queue aid, not a severity or human disposition.",
                "A human reviewer must resolve contradictions and make the final decision.",
            ],
        },
    }
    return result
