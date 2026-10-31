"""Core logic: triage reports, verify source excerpts, and optionally challenge the result."""
import hashlib
import json
import re
import time

import meta_client
from prompts import (
    CHALLENGE_SYSTEM,
    CHALLENGE_USER,
    CODE_BLOCK_TEMPLATE,
    TRIAGE_SYSTEM,
    TRIAGE_USER,
)

LANG_NAMES = {"ar": "Arabic", "en": "English"}
MAX_REPORT = 20000
MAX_CODE = 40000
TRIAGE_PROMPT_VERSION = "evidence-triage-v1"
CHALLENGE_PROMPT_VERSION = "second-pass-challenge-v1"

NOISE = {"specific", "generic", "scanner-dump"}
VERIFY = {"supported", "unverifiable", "contradicted"}
SEVERITY = {"none", "low", "medium", "high", "critical"}
DECISION = {"accept", "need-info", "duplicate", "reject"}
EVIDENCE_SOURCES = {"report", "code"}
EVIDENCE_RELATIONS = {"supports", "contradicts", "context-needed"}
CHALLENGE_STATUSES = {"clear", "flagged", "inconclusive"}
MAX_EVIDENCE_ITEMS = 8
MAX_EVIDENCE_QUOTE = 500


def lang_name(code):
    return LANG_NAMES.get(code, "English")


def extract_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in reply")
    return json.loads(text[start : end + 1])


def _list_of_str(v, limit, item_limit):
    if not isinstance(v, list):
        return []
    return [str(x)[:item_limit] for x in v][:limit]


def _occurrence_summary(text, quote):
    if not quote:
        return None, 0
    first = text.find(quote)
    count = 0
    pos = 0
    while True:
        pos = text.find(quote, pos)
        if pos < 0:
            break
        count += 1
        pos += 1
    return first if first >= 0 else None, count


def _verified_evidence(data, report, code):
    raw = data.get("evidence")
    if not isinstance(raw, list):
        return [], False

    result = []
    structurally_valid = bool(raw) and len(raw) <= MAX_EVIDENCE_ITEMS
    for item in raw[:MAX_EVIDENCE_ITEMS]:
        if not isinstance(item, dict):
            structurally_valid = False
            continue
        source = item.get("source")
        relation = item.get("relation")
        raw_quote = item.get("quote")
        explanation = item.get("explanation")
        source_valid = isinstance(source, str) and source in EVIDENCE_SOURCES
        relation_valid = isinstance(relation, str) and relation in EVIDENCE_RELATIONS
        quote_valid = isinstance(raw_quote, str) and 0 < len(raw_quote) <= MAX_EVIDENCE_QUOTE
        if not (source_valid and relation_valid and quote_valid):
            structurally_valid = False
        quote = raw_quote[:MAX_EVIDENCE_QUOTE] if isinstance(raw_quote, str) else ""
        source_text = report if source == "report" else code if source == "code" else ""
        start, match_count = _occurrence_summary(source_text, quote) if quote_valid else (None, 0)
        verified = bool(quote_valid and quote.strip() and match_count)
        if not verified:
            structurally_valid = False
        result.append({
            "source": source if source_valid else "unknown",
            "quote": quote,
            "relation": relation if relation_valid else "context-needed",
            "explanation": str(explanation or "")[:400],
            "verified": verified,
            "start": start,
            "end": start + len(quote) if start is not None else None,
            "match_count": match_count,
            "ambiguous": match_count > 1,
        })
    integrity = structurally_valid and bool(result) and all(item["verified"] for item in result)
    return result, integrity


def normalize(data, report="", code=""):
    if not isinstance(data, dict):
        data = {}
    report = report if isinstance(report, str) else ""
    code = code if isinstance(code, str) else ""
    noise_value = data.get("noise")
    verify_value = data.get("code_verification")
    severity_value = data.get("severity")
    decision_value = data.get("decision")
    noise = noise_value if isinstance(noise_value, str) and noise_value in NOISE else "generic"
    verify = verify_value if isinstance(verify_value, str) and verify_value in VERIFY else "unverifiable"
    severity = severity_value if isinstance(severity_value, str) and severity_value in SEVERITY else "none"
    decision = decision_value if isinstance(decision_value, str) and decision_value in DECISION else "need-info"
    evidence, citations_verified = _verified_evidence(data, report, code)

    # Hard guardrails stay server-side. A literal text match is only citation
    # integrity; it does not establish semantic relevance or report truth.
    if verify == "contradicted" and decision == "accept":
        decision = "reject"
    if noise == "scanner-dump" and decision == "accept":
        decision = "need-info"
    decision_reasoning = str(data.get("decision_reasoning", ""))[:500]
    if not citations_verified:
        decision = "need-info"
        caveat = " Mizan could not verify every evidence quote against its stated source; the recommendation was downgraded."
        decision_reasoning = (decision_reasoning + caveat).strip()[:500]

    return {
        "claim": str(data.get("claim", ""))[:600],
        "component": str(data.get("component", ""))[:200],
        "claimed_impact": str(data.get("claimed_impact", ""))[:400],
        "repro_steps": _list_of_str(data.get("repro_steps"), 20, 300),
        "injection_attempts": _list_of_str(data.get("injection_attempts"), 10, 200),
        "noise": noise,
        "code_verification": verify,
        "code_evidence": str(data.get("code_evidence", ""))[:800],
        "evidence": evidence,
        "citation_integrity": "verified" if citations_verified else "unverified",
        "missing_context": _list_of_str(data.get("missing_context"), 12, 300),
        "severity": severity,
        "severity_reasoning": str(data.get("severity_reasoning", ""))[:500],
        "decision": decision,
        "decision_reasoning": decision_reasoning,
        "draft_reply": str(data.get("draft_reply", ""))[:1200],
    }


def _response_parts(response):
    if isinstance(response, dict) and isinstance(response.get("content"), str):
        model = response.get("model") if isinstance(response.get("model"), str) else "unknown"
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        return response["content"], model[:120], usage
    if isinstance(response, str):
        return response, "unknown", {}
    raise ValueError("unexpected model response")


def _prompt_metadata(system_prompt, user_template, version, model, elapsed_ms, usage):
    prompt_hash = hashlib.sha256((system_prompt + "\0" + user_template).encode("utf-8")).hexdigest()
    safe_usage = {
        key: value for key, value in usage.items()
        if key in {"prompt_tokens", "completion_tokens", "total_tokens"}
        and type(value) is int and 0 <= value <= 100_000_000
    }
    return {
        "model": model,
        "prompt_version": version,
        "prompt_sha256": prompt_hash,
        "elapsed_ms": max(0, min(int(elapsed_ms), 600_000)),
        "usage": safe_usage,
    }


def _add_usage(total, addition):
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = addition.get(key) if isinstance(addition, dict) else None
        if type(value) is int and 0 <= value <= 100_000_000:
            total[key] = min(100_000_000, total.get(key, 0) + value)


def _json_quote(value):
    return json.dumps(value, ensure_ascii=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _challenge_messages(report, code, analysis, language):
    report_value = _json_quote(report)
    code_value = _json_quote(code)
    analysis_value = _json_quote(analysis)
    replacements = {"report": report_value, "code": code_value, "analysis": analysis_value}
    user_msg = re.sub(
        r"\{(report|code|analysis)\}",
        lambda match: replacements[match.group(1)],
        CHALLENGE_USER,
    )
    system_msg = CHALLENGE_SYSTEM.replace("{language}", language)
    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]


def _run_challenge(report, code, language, analysis, api_key):
    messages = _challenge_messages(report, code, analysis, language)
    started = time.monotonic()
    try:
        response = meta_client.chat(
            messages, api_key=api_key, max_tokens=1800, temperature=0.1, return_metadata=True
        )
        reply, model, usage = _response_parts(response)
        data = extract_json(reply)
        if not isinstance(data, dict):
            raise ValueError("challenge result was not an object")
        status = data.get("status")
        raw_issues = data.get("issues")
        summary = str(data.get("summary", ""))[:500]
        if status not in CHALLENGE_STATUSES or not isinstance(raw_issues, list) or len(raw_issues) > MAX_EVIDENCE_ITEMS:
            return {
                "status": "invalid-response", "summary": "The second-pass response could not be validated.",
                "issues": [], "citation_integrity": "unverified",
                "analysis_meta": _prompt_metadata(
                    CHALLENGE_SYSTEM.replace("{language}", language), CHALLENGE_USER,
                    CHALLENGE_PROMPT_VERSION, model, (time.monotonic() - started) * 1000, usage,
                ),
            }
        if status == "clear" and raw_issues:
            status = "invalid-response"
            issues, integrity = [], False
        elif status in {"flagged", "inconclusive"} and raw_issues:
            issues, integrity = _verified_evidence({"evidence": raw_issues}, report, code)
            if not integrity:
                status = "invalid-evidence"
        elif status == "flagged":
            status, issues, integrity = "invalid-evidence", [], False
        else:
            issues, integrity = [], True
        citation_state = "verified" if issues and integrity else "unverified" if issues or status == "invalid-evidence" else "not-applicable"
        return {
            "status": status,
            "summary": summary,
            "issues": issues,
            "citation_integrity": citation_state,
            "analysis_meta": _prompt_metadata(
                CHALLENGE_SYSTEM.replace("{language}", language), CHALLENGE_USER,
                CHALLENGE_PROMPT_VERSION, model, (time.monotonic() - started) * 1000, usage,
            ),
        }
    except Exception:
        # Do not leak upstream errors or report text. The first analysis remains visible.
        return {
            "status": "unavailable",
            "summary": "The second-pass challenge could not be completed; review the first analysis cautiously.",
            "issues": [],
            "citation_integrity": "not-applicable",
            "analysis_meta": _prompt_metadata(
                CHALLENGE_SYSTEM.replace("{language}", language), CHALLENGE_USER,
                CHALLENGE_PROMPT_VERSION, "unknown", (time.monotonic() - started) * 1000, {},
            ),
        }


def triage(report, code=None, lang="en", *, api_key=None, challenge_pass=False):
    report = (report or "").strip()
    if not report:
        raise ValueError("Paste the report text first.")
    if len(report) > MAX_REPORT:
        raise ValueError("Report is too long (max %d characters)." % MAX_REPORT)

    code = (code or "").strip()
    if len(code) > MAX_CODE:
        raise ValueError("Code context is too long (max %d characters)." % MAX_CODE)
    if not isinstance(challenge_pass, bool):
        raise ValueError("Challenge pass must be a boolean.")

    language = lang_name(lang)
    # JSON-quote untrusted values so embedded newlines cannot forge the visible
    # delimiters. One-pass substitution prevents braces in submitted text from
    # being mistaken for remaining template fields.
    report_value = json.dumps(report, ensure_ascii=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    code_value = json.dumps(code, ensure_ascii=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    code_block = CODE_BLOCK_TEMPLATE.replace("{code}", code_value, 1) if code else ""
    replacements = {"report": report_value, "code_block": code_block, "language": language}
    user_msg = re.sub(
        r"\{(report|code_block|language)\}",
        lambda match: replacements[match.group(1)],
        TRIAGE_USER,
    )
    system_msg = TRIAGE_SYSTEM.replace("{language}", language)
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]

    last_err = None
    final_model, usage_total = "unknown", {}
    started = time.monotonic()
    for _ in range(2):
        response = meta_client.chat(
            messages, api_key=api_key, max_tokens=3500, temperature=0.1, return_metadata=True
        )
        reply = None
        try:
            reply, final_model, call_usage = _response_parts(response)
            _add_usage(usage_total, call_usage)
            normalized = normalize(extract_json(reply), report, code)
            normalized["analysis_meta"] = _prompt_metadata(
                system_msg, TRIAGE_USER, TRIAGE_PROMPT_VERSION, final_model,
                (time.monotonic() - started) * 1000, usage_total,
            )
            if challenge_pass:
                challenge = _run_challenge(report, code, language, normalized, api_key)
                normalized["challenge_pass"] = challenge
                if challenge["status"] in {"flagged", "inconclusive", "invalid-evidence", "invalid-response"}:
                    normalized["primary_decision"] = normalized["decision"]
                    normalized["decision"] = "need-info"
                    note = " The optional second-pass challenge raised a concern or could not reach a clear conclusion; human review is required."
                    normalized["decision_reasoning"] = (normalized["decision_reasoning"] + note).strip()[:500]
            return normalized
        except (ValueError, json.JSONDecodeError) as e:
            last_err = e
            if not isinstance(reply, str):
                reply = str(response)[:4000]
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": "That was not valid JSON. Reply with the JSON object only."})
    raise meta_client.MetaAPIError("Could not read the model's answer: %s" % last_err, 502)
