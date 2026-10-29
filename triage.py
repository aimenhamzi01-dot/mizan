"""Core logic: run a report through Muse Spark and verify cited source excerpts."""
import json
import re

import meta_client
from prompts import CODE_BLOCK_TEMPLATE, TRIAGE_SYSTEM, TRIAGE_USER

LANG_NAMES = {"ar": "Arabic", "en": "English"}
MAX_REPORT = 20000
MAX_CODE = 40000

NOISE = {"specific", "generic", "scanner-dump"}
VERIFY = {"supported", "unverifiable", "contradicted"}
SEVERITY = {"none", "low", "medium", "high", "critical"}
DECISION = {"accept", "need-info", "duplicate", "reject"}
EVIDENCE_SOURCES = {"report", "code"}
EVIDENCE_RELATIONS = {"supports", "contradicts", "context-needed"}
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
        verified = bool(quote_valid and quote.strip() and source_text and quote in source_text)
        if not verified:
            structurally_valid = False
        result.append({
            "source": source if source_valid else "unknown",
            "quote": quote,
            "relation": relation if relation_valid else "context-needed",
            "explanation": str(explanation or "")[:400],
            "verified": verified,
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


def triage(report, code=None, lang="en", *, api_key=None):
    report = (report or "").strip()
    if not report:
        raise ValueError("Paste the report text first.")
    if len(report) > MAX_REPORT:
        raise ValueError("Report is too long (max %d characters)." % MAX_REPORT)

    code = (code or "").strip()
    if len(code) > MAX_CODE:
        raise ValueError("Code context is too long (max %d characters)." % MAX_CODE)

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
    messages = [
        {"role": "system", "content": TRIAGE_SYSTEM.replace("{language}", language)},
        {"role": "user", "content": user_msg},
    ]

    last_err = None
    for _ in range(2):
        reply = meta_client.chat(messages, api_key=api_key, max_tokens=3500, temperature=0.1)
        try:
            return normalize(extract_json(reply), report, code)
        except (ValueError, json.JSONDecodeError) as e:
            last_err = e
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": "That was not valid JSON. Reply with the JSON object only."})
    raise meta_client.MetaAPIError("Could not read the model's answer: %s" % last_err, 502)
