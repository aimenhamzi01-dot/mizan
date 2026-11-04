"""Convert a user-selected Phantom ScanResult into a local Mizan draft.

This module is deliberately a pure data mapper: it never contacts Phantom or a
scan target, executes source code, invokes a model, or persists a case.
"""
import json
import math

from review_store import MAX_CODE_CHARS, MAX_REPORT_CHARS


IMPORT_FORMAT = "phantom-scan-result-v1"
ALLOWED_TARGET_TYPES = {"web", "mobile", "hardware", "code"}
MAX_FINDINGS = 25
MAX_STATIC_FINDINGS = 50
MAX_LIST_ITEMS = 50
MAX_FIELD_CHARS = 6_000


def _text(obj, key, *, required=False, limit=MAX_FIELD_CHARS):
    value = obj.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError("Phantom field '%s' must be text." % key)
    if len(value) > limit:
        raise ValueError("Phantom field '%s' exceeds the import size limit." % key)
    value = value.strip()
    if required and not value:
        raise ValueError("Phantom field '%s' is required." % key)
    return value


def _string_list(obj, key, *, max_items=MAX_LIST_ITEMS):
    value = obj.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > max_items:
        raise ValueError("Phantom field '%s' must be a bounded list." % key)
    items = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("Phantom field '%s' must contain only text." % key)
        if len(item) > MAX_FIELD_CHARS:
            raise ValueError("An item in Phantom field '%s' exceeds the import size limit." % key)
        items.append(item)
    return items


def _optional_number(obj, key):
    value = obj.get(key)
    if value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Phantom field '%s' must be a finite number." % key)
    return value


def _optional_positive_int(obj, key):
    value = obj.get(key)
    if value is None:
        return None
    if type(value) is not int or value < 1 or value > 10_000_000:
        raise ValueError("Phantom field '%s' must be a positive line number." % key)
    return value


def _provenance(recon):
    """Keep compact, inspectable source metadata without treating it as proof."""
    source_bytes = recon.get("source_bytes")
    if source_bytes is None:
        source_bytes = 0
    if type(source_bytes) is not int or source_bytes < 0 or source_bytes > 2_000_000:
        raise ValueError("Phantom field 'source_bytes' must be a bounded non-negative integer.")
    allowed = {
        "analysis_status": _text(recon, "analysis_status", limit=64),
        "analysis_engine": _text(recon, "analysis_engine", limit=128),
        "analysis_config": _text(recon, "analysis_config", limit=256),
        "source_sha256": _text(recon, "source_sha256", limit=128),
        "source_bytes": source_bytes,
        "lines_of_code": _optional_positive_int(recon, "lines_of_code") or 0,
    }
    return {key: value for key, value in allowed.items() if value not in ("", None)}


def _finding(value, index):
    if not isinstance(value, dict):
        raise ValueError("Phantom vulnerability %d must be an object." % index)
    verified = value.get("verified")
    if verified is not None and type(verified) is not bool:
        raise ValueError("Phantom vulnerability %d has an invalid verification flag." % index)
    return {
        "id": _text(value, "id", limit=256),
        "title": _text(value, "title", limit=1_000),
        "severity": _text(value, "severity", limit=100),
        "cvss_score": _optional_number(value, "cvss_score"),
        "cvss_vector": _text(value, "cvss_vector", limit=500),
        "description": _text(value, "description"),
        "endpoint": _text(value, "endpoint", limit=1_000),
        "impact": _text(value, "impact"),
        "attack_vector": _text(value, "attack_vector", limit=1_000),
        "cwe": _text(value, "cwe", limit=256),
        "cve_refs": _string_list(value, "cve_refs", max_items=20),
        "phantom_verified_flag_claim": verified,
        "source_line_claim": _optional_positive_int(value, "source_line"),
        "source_snippet_claim": _text(value, "source_snippet"),
    }


def _static_finding(value, index):
    if not isinstance(value, dict):
        raise ValueError("Phantom static finding %d must be an object." % index)
    return {
        "rule_id": _text(value, "rule_id", limit=500),
        "message": _text(value, "message"),
        "severity": _text(value, "severity", limit=100),
        "line_start_claim": _optional_positive_int(value, "line_start"),
        "line_end_claim": _optional_positive_int(value, "line_end"),
        "code_snippet_claim": _text(value, "code_snippet"),
        "cwe": _text(value, "cwe", limit=256),
        "owasp": _text(value, "owasp", limit=500),
        "confidence_claim": _text(value, "confidence", limit=100),
    }


def _result_object(result):
    if not isinstance(result, dict):
        raise ValueError("Phantom result must be a JSON object.")
    # Also accept a small envelope such as {"result": <ScanResult>}.
    if "target" not in result and isinstance(result.get("result"), dict):
        result = result["result"]
    return result


def phantom_result_to_preview(result, *, language="en", user_code=""):
    """Return a report/code/language payload for the existing Mizan save form.

    The function imports only a small whitelist of Phantom fields. In particular,
    it does not copy recon/network metadata, bounty estimates, or program matches.
    Phantom-reported source snippets remain in the report as unverified claims;
    they are not promoted into Mizan's researcher-supplied code field.
    """
    result = _result_object(result)
    target = _text(result, "target", required=True, limit=512)
    target_type = _text(result, "target_type", required=True, limit=32)
    if target_type not in ALLOWED_TARGET_TYPES:
        raise ValueError("Phantom target_type is not supported.")

    vulnerabilities = result.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > MAX_FINDINGS:
        raise ValueError("Phantom vulnerabilities must be a list of at most %d items." % MAX_FINDINGS)
    mapped_vulnerabilities = [_finding(item, i + 1) for i, item in enumerate(vulnerabilities)]

    recon = result.get("recon") or {}
    if not isinstance(recon, dict):
        raise ValueError("Phantom recon field must be an object.")
    static_findings = recon.get("static_findings", [])
    if not isinstance(static_findings, list) or len(static_findings) > MAX_STATIC_FINDINGS:
        raise ValueError("Phantom static_findings must be a bounded list.")
    mapped_static_findings = [_static_finding(item, i + 1) for i, item in enumerate(static_findings)]

    tech_stack = _string_list(result, "tech_stack")
    scan = {
        "scan_id": _text(result, "scan_id", limit=128),
        "timestamp": _text(result, "timestamp", limit=128),
        "target_as_reported": target,
        "target_type_as_reported": target_type,
        "risk_rating_claim": _text(result, "risk_rating", limit=100),
        "tech_stack_claim": tech_stack,
        "analysis_provenance": _provenance(recon),
    }
    imported = {
        "format": IMPORT_FORMAT,
        "provenance_warning": (
            "Imported from a user-selected Phantom result. Finding details, scanner flags, "
            "source excerpts, severity, remediation, and proof-of-concept are unverified claims. "
            "Mizan did not run a scan, contact the target, fetch source, execute code, or call a model."
        ),
        "scan": scan,
        "executive_summary_claim": _text(result, "executive_summary"),
        "technical_details_claim": _text(result, "technical_details"),
        "vulnerabilities": mapped_vulnerabilities,
        "static_findings": mapped_static_findings,
        "proof_of_concept_claim": _text(result, "proof_of_concept"),
        "remediation_claim": _text(result, "remediation"),
        "intentionally_omitted": [
            "network reconnaissance details",
            "estimated bounty",
            "recommended programs",
            "submission guide",
        ],
    }

    target_label = " ".join(target.split())[:120]
    report = (
        "PHANTOM SCAN IMPORT — UNVERIFIED — " + target_label + "\n\n"
        "Review this imported draft before saving. Importing only prepares local text; it does not "
        "start a scan, contact a target, run code, or call Muse Spark. The ordinary explicit Meta "
        "egress confirmation is still required for later analysis.\n\n"
        + json.dumps(imported, ensure_ascii=False, indent=2, allow_nan=False)
    )
    if len(report) > MAX_REPORT_CHARS:
        raise ValueError("The mapped Phantom result exceeds Mizan's report size limit; reduce it before importing.")
    if not isinstance(user_code, str):
        raise ValueError("Researcher-supplied code must be text.")
    user_code = user_code.strip()
    if len(user_code) > MAX_CODE_CHARS:
        raise ValueError("Researcher-supplied code exceeds Mizan's size limit.")
    language = language if language in ("en", "ar") else "en"
    return {"report": report, "code": user_code, "lang": language}
