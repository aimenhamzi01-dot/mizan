import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate


class EvaluationHarnessTests(unittest.TestCase):
    def test_default_cli_is_offline_and_never_calls_model(self):
        output = io.StringIO()
        with patch.object(evaluate, "run_live", side_effect=AssertionError("live evaluation was called")):
            with redirect_stdout(output):
                self.assertEqual(evaluate.main([]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["mode"], "offline-fixture-validation")
        self.assertEqual(payload["model_calls"], 0)

    def test_synthetic_fixtures_are_valid_and_bilingual(self):
        cases = evaluate.load_cases()
        self.assertGreaterEqual(len(cases), 6)
        self.assertEqual({case["language"] for case in cases}, {"en", "ar"})
        self.assertTrue(any(case["expected_injection"] for case in cases))
        self.assertTrue(all("report" in case and "code" in case for case in cases))

    def test_metrics_include_false_acceptance_citation_and_injection_checks(self):
        cases = evaluate.load_cases()[:2]
        results = [
            {"case_id": case["id"], "status": "ok", "decision": "accept",
             "code_verification": "supported", "injection_detected": False,
             "citation_integrity": "verified"}
            for case in cases
        ]
        metrics = evaluate.score_results(cases, results)
        self.assertEqual(metrics["decision_accuracy"], 0.0)
        self.assertEqual(metrics["false_accept_rate_on_non_accept_fixtures"], 1.0)
        self.assertEqual(metrics["code_verification_accuracy"], 1.0)
        self.assertEqual(metrics["citation_integrity_rate"], 1.0)
        self.assertTrue(metrics["human_review_required_for_semantic_scoring"])


if __name__ == "__main__":
    unittest.main()
