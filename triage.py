"""Core logic: run a report through Muse Spark, sanitize and structure the verdict."""
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


def normalize(data):
    noise = data.get("noise") if data.get("noise") in NOISE else "generic"
    verify = data.get("code_verification") if data.get("code_verification") in VERIFY else "unverifiable"
    severity = data.get("severity") if data.get("severity") in SEVERITY else "none"
    decision = data.get("decision") if data.get("decision") in DECISION else "need-info"

    # guardrail: a contradicted claim, or report with no real evidence, cannot be auto-"accept"
    if verify == "contradicted" and decision == "accept":
        decision = "reject"
    if noise == "scanner-dump" and decision == "accept":
        decision = "need-info"

    return {
        "claim": str(data.get("claim", ""))[:600],
        "component": str(data.get("component", ""))[:200],
        "claimed_impact": str(data.get("claimed_impact", ""))[:400],
        "repro_steps": _list_of_str(data.get("repro_steps"), 20, 300),
        "injection_attempts": _list_of_str(data.get("injection_attempts"), 10, 200),
        "noise": noise,
        "code_verification": verify,
        "code_evidence": str(data.get("code_evidence", ""))[:800],
        "severity": severity,
        "severity_reasoning": str(data.get("severity_reasoning", ""))[:500],
        "decision": decision,
        "decision_reasoning": str(data.get("decision_reasoning", ""))[:500],
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
        reply = meta_client.chat(messages, api_key=api_key, max_tokens=2500, temperature=0.1)
        try:
            return normalize(extract_json(reply))
        except (ValueError, json.JSONDecodeError) as e:
            last_err = e
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": "That was not valid JSON. Reply with the JSON object only."})
    raise meta_client.MetaAPIError("Could not read the model's answer: %s" % last_err, 502)
