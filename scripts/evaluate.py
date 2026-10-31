#!/usr/bin/env python3
"""Evaluate Mizan against a small, synthetic, bilingual triage fixture set.

Default mode validates only the local fixture file and makes no model calls.
Live evaluation requires explicit --live and --confirm-egress flags. Only the
bundled synthetic cases are sent; raw case text is never included in the output.
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import meta_client
import triage

FIXTURE_PATH = ROOT / "tests" / "fixtures" / "evaluation_cases.json"
DECISIONS = {"accept", "need-info", "duplicate", "reject"}
CODE_VERIFICATIONS = {"supported", "unverifiable", "contradicted"}


def load_cases(path=FIXTURE_PATH):
    cases = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("The evaluation fixture must be a non-empty JSON array.")
    ids = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each evaluation fixture must be an object.")
        required = {"id", "language", "report", "code", "expected_decision", "expected_code_verification", "expected_injection"}
        if not required.issubset(case):
            raise ValueError("An evaluation fixture is missing required fields.")
        if not isinstance(case["id"], str) or not case["id"] or case["id"] in ids:
            raise ValueError("Fixture ids must be unique non-empty strings.")
        ids.add(case["id"])
        if case["language"] not in {"en", "ar"}:
            raise ValueError("Fixture language must be en or ar.")
        if not isinstance(case["report"], str) or not case["report"].strip() or len(case["report"]) > triage.MAX_REPORT:
            raise ValueError("Fixture report is empty or too large.")
        if not isinstance(case["code"], str) or len(case["code"]) > triage.MAX_CODE:
            raise ValueError("Fixture code is invalid or too large.")
        if case["expected_decision"] not in DECISIONS:
            raise ValueError("Fixture has an invalid expected decision.")
        if case["expected_code_verification"] not in CODE_VERIFICATIONS:
            raise ValueError("Fixture has an invalid expected code-verification label.")
        if type(case["expected_injection"]) is not bool:
            raise ValueError("Fixture expected_injection must be boolean.")
    return cases


def _rate(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def score_results(cases, results):
    by_id = {item.get("case_id"): item for item in results if isinstance(item, dict)}
    successful = [(case, by_id[case["id"]]) for case in cases
                  if case["id"] in by_id and by_id[case["id"]].get("status") == "ok"]
    decision_correct = sum(result.get("decision") == case["expected_decision"] for case, result in successful)
    false_accepts = sum(result.get("decision") == "accept" and case["expected_decision"] != "accept"
                        for case, result in successful)
    non_accept_cases = sum(case["expected_decision"] != "accept" for case in cases)
    code_correct = sum(result.get("code_verification") == case["expected_code_verification"]
                       for case, result in successful)
    injection_cases = [(case, result) for case, result in successful if case["expected_injection"]]
    injection_detected = sum(bool(result.get("injection_detected")) for _, result in injection_cases)
    verified_citations = sum(result.get("citation_integrity") == "verified" for _, result in successful)
    return {
        "fixture_cases": len(cases),
        "successful_model_runs": len(successful),
        "decision_accuracy": _rate(decision_correct, len(successful)),
        "false_accept_rate_on_non_accept_fixtures": _rate(false_accepts, non_accept_cases),
        "code_verification_accuracy": _rate(code_correct, len(successful)),
        "injection_detection_recall": _rate(injection_detected, len(injection_cases)),
        "citation_integrity_rate": _rate(verified_citations, len(successful)),
        "human_review_required_for_semantic_scoring": True,
    }


def run_live(cases, include_challenge=False):
    results = []
    for case in cases:
        started = time.monotonic()
        try:
            output = triage.triage(
                case["report"], case["code"], case["language"], challenge_pass=include_challenge
            )
            results.append({
                "case_id": case["id"],
                "status": "ok",
                "decision": output.get("decision"),
                "code_verification": output.get("code_verification"),
                "injection_detected": bool(output.get("injection_attempts")),
                "citation_integrity": output.get("citation_integrity"),
                "challenge_status": (output.get("challenge_pass") or {}).get("status"),
                "analysis_meta": output.get("analysis_meta", {}),
                "elapsed_ms": max(0, round((time.monotonic() - started) * 1000)),
            })
        except Exception as exc:
            # Do not print provider details, keys, or fixture text.
            results.append({
                "case_id": case["id"],
                "status": "failed",
                "error_type": type(exc).__name__,
                "elapsed_ms": max(0, round((time.monotonic() - started) * 1000)),
            })
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="send the bundled synthetic fixtures to the configured Meta API")
    parser.add_argument("--confirm-egress", action="store_true", help="confirm sending these synthetic cases to the configured model endpoint")
    parser.add_argument("--include-challenge", action="store_true", help="run the optional second-pass challenge for each case")
    parser.add_argument("--confirm-extra-calls", action="store_true", help="confirm the additional API requests and possible cost")
    parser.add_argument("--limit", type=int, help="evaluate only the first N fixtures (useful to control API usage)")
    parser.add_argument("--output", type=Path, help="write the content-free result JSON to this path instead of stdout")
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.limit is not None:
        if args.limit < 1:
            parser.error("--limit must be at least 1")
        cases = cases[:args.limit]
    if not args.live:
        if args.include_challenge or args.confirm_extra_calls:
            parser.error("--include-challenge requires --live")
        result = {
            "mode": "offline-fixture-validation",
            "fixture_cases": len(cases),
            "model_calls": 0,
            "note": "Fixture validation is not a semantic model-accuracy evaluation.",
        }
    else:
        if not args.confirm_egress:
            parser.error("--live requires --confirm-egress")
        if args.include_challenge and not args.confirm_extra_calls:
            parser.error("--include-challenge requires --confirm-extra-calls")
        if not meta_client.has_key():
            parser.error("Set a personal Meta API key in MODEL_API_KEY, META_API_KEY, or META_MODEL_API_KEY first.")
        runs = run_live(cases, include_challenge=args.include_challenge)
        result = {
            "mode": "live-synthetic-evaluation",
            "model_calls_expected_minimum": len(cases) * (2 if args.include_challenge else 1),
            "metrics": score_results(cases, runs),
            "runs": runs,
            "limitations": [
                "Fixtures are synthetic and small; the results are not a production accuracy claim.",
                "Exact citation matching does not establish semantic relevance or truth.",
                "Semantic adjudication still requires human review.",
            ],
        }
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if not args.live or result["metrics"]["successful_model_runs"] == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
