import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import review_store


VALID_ANALYSIS = {
    "claim": "Possible object-level authorization failure.",
    "component": "GET /api/messages/{message_id}",
    "claimed_impact": "Potential message disclosure.",
    "repro_steps": [],
    "injection_attempts": [],
    "noise": "specific",
    "code_verification": "supported",
    "code_evidence": "No participant check is shown in the supplied function.",
    "severity": "high",
    "severity_reasoning": "Potential confidentiality impact.",
    "decision": "need-info",
    "decision_reasoning": "Review surrounding authorization context.",
    "draft_reply": "Please provide the route and access-control context.",
}


class ReviewStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {"MIZAN_DB_PATH": str(Path(self.temp_dir.name) / "test.sqlite3")},
        )
        self.env.start()
        review_store.init_db()

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def create(self):
        return review_store.create_report(
            "IDOR claim: message lookup by id may miss participant authorization.",
            "def get_message(request, message_id): return Message.objects.get(id=message_id)",
            "en",
        )

    def test_new_report_is_received_without_any_automatic_decision(self):
        case = self.create()
        self.assertEqual(case["status"], "received")
        self.assertIsNone(case["analysis"])
        self.assertIsNone(case["suggested_decision"])
        self.assertIsNone(case["review_decision"])
        self.assertEqual([e["event_type"] for e in review_store.report_history(case["id"])], ["report_received"])

    def test_database_file_permissions_are_owner_only(self):
        self.create()
        self.assertEqual(review_store.database_path().stat().st_mode & 0o777, 0o600)

    def test_report_and_code_length_limits_are_enforced(self):
        with self.assertRaises(ValueError):
            review_store.create_report(" ")
        with self.assertRaises(ValueError):
            review_store.create_report("x" * (review_store.MAX_REPORT_CHARS + 1))
        with self.assertRaises(ValueError):
            review_store.create_report("report", "x" * (review_store.MAX_CODE_CHARS + 1))

    def test_analysis_is_only_a_suggestion(self):
        case = self.create()
        analyzed = review_store.save_analysis(case["id"], VALID_ANALYSIS)
        self.assertEqual(analyzed["status"], "analyzed")
        self.assertEqual(analyzed["suggested_decision"], "need-info")
        self.assertIsNone(analyzed["review_decision"])
        self.assertEqual([e["event_type"] for e in review_store.report_history(case["id"])], [
            "report_received", "analysis_completed"
        ])

    def test_human_review_requires_an_analysis(self):
        case = self.create()
        with self.assertRaises(review_store.InvalidState):
            review_store.record_review(case["id"], "accept", "Reviewer A")

    def test_human_can_override_suggestion_and_event_is_recorded(self):
        case = self.create()
        review_store.save_analysis(case["id"], VALID_ANALYSIS)
        reviewed = review_store.record_review(
            case["id"], "reject", reviewer="Reviewer A", note="Needs complete route context first."
        )
        self.assertEqual(reviewed["suggested_decision"], "need-info")
        self.assertEqual(reviewed["review_decision"], "reject")
        self.assertEqual(reviewed["status"], "reviewed")
        history = review_store.report_history(case["id"])
        self.assertEqual(history[-1]["event_type"], "human_review_recorded")
        self.assertEqual(history[-1]["details"]["previous_decision"], None)
        self.assertEqual(history[-1]["details"]["review_decision"], "reject")

    def test_review_can_be_revised_without_overwriting_event_history(self):
        case = self.create()
        review_store.save_analysis(case["id"], VALID_ANALYSIS)
        review_store.record_review(case["id"], "need-info", "Reviewer A", "Request access-control context.")
        revised = review_store.record_review(case["id"], "accept", "Reviewer B", "Confirmed in full source.")
        self.assertEqual(revised["review_decision"], "accept")
        history = review_store.report_history(case["id"])
        self.assertEqual(len(history), 4)
        self.assertEqual(history[-1]["details"]["previous_decision"], "need-info")

    def test_reviewed_case_cannot_be_reanalyzed(self):
        case = self.create()
        review_store.save_analysis(case["id"], VALID_ANALYSIS)
        review_store.record_review(case["id"], "need-info")
        with self.assertRaises(review_store.InvalidState):
            review_store.save_analysis(case["id"], VALID_ANALYSIS)

    def test_invalid_decision_and_oversized_review_fields_are_rejected(self):
        case = self.create()
        review_store.save_analysis(case["id"], VALID_ANALYSIS)
        with self.assertRaises(ValueError):
            review_store.record_review(case["id"], "auto-exploit")
        with self.assertRaises(ValueError):
            review_store.record_review(case["id"], "accept", reviewer="r" * 121)
        with self.assertRaises(ValueError):
            review_store.record_review(case["id"], "accept", note="n" * 4001)

    def test_list_search_status_and_pagination_return_bounded_summaries(self):
        first = self.create()
        review_store.save_analysis(first["id"], VALID_ANALYSIS)
        second = review_store.create_report("A separate scanner report", language="en")
        results = review_store.list_reports(status="received", query="scanner", limit=500, offset=0)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], second["id"])
        self.assertNotIn("code", results[0])
        self.assertNotIn("report", results[0])
        self.assertEqual(len(review_store.list_reports(limit=1)), 1)
        with self.assertRaises(ValueError):
            review_store.list_reports(status="bogus")

    def test_metrics_are_aggregated_and_exclude_report_contents(self):
        case = self.create()
        review_store.save_analysis(case["id"], VALID_ANALYSIS)
        counts = review_store.metrics()
        self.assertEqual(counts["total_reports"], 1)
        self.assertEqual(counts["by_status"], {"analyzed": 1})
        self.assertEqual(counts["by_suggested_decision"], {"need-info": 1})
        self.assertNotIn("report", counts)

    def test_delete_removes_report_and_audit_events(self):
        case = self.create()
        review_store.save_analysis(case["id"], VALID_ANALYSIS)
        review_store.delete_report(case["id"])
        with self.assertRaises(review_store.NotFound):
            review_store.get_report(case["id"])
        with self.assertRaises(review_store.NotFound):
            review_store.report_history(case["id"])

    def test_missing_report_returns_not_found(self):
        with self.assertRaises(review_store.NotFound):
            review_store.get_report("not-a-real-case")


if __name__ == "__main__":
    unittest.main(verbosity=2)
