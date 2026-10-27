import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import meta_client
import server


GOOD = {
    "claim": "Possible message IDOR.",
    "component": "GET /api/messages/{message_id}",
    "claimed_impact": "Potential private-message disclosure.",
    "repro_steps": [],
    "injection_attempts": [],
    "noise": "specific",
    "code_verification": "supported",
    "code_evidence": "The supplied function has no participant check.",
    "severity": "high",
    "severity_reasoning": "Potential confidentiality impact.",
    "decision": "need-info",
    "decision_reasoning": "Review the surrounding access-control path.",
    "draft_reply": "Please provide the route and authorization context.",
}


class WorkbenchAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"MIZAN_DB_PATH": str(Path(self.temp_dir.name) / "api.sqlite3")})
        self.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def request(self, path, body=None, method="GET", content_type="application/json", extra_headers=None):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        headers.update(extra_headers or {})
        req = Request("http://127.0.0.1:%d%s" % (self.port, path), data=data, headers=headers, method=method)
        try:
            with urlopen(req) as response:
                return response.status, response.headers, response.read()
        except HTTPError as error:
            return error.code, error.headers, error.read()

    def create_case(self, report="IDOR report from Account A", code="def get_message(request, message_id): pass"):
        status, _, body = self.request(
            "/api/reports", {"report": report, "code": code, "lang": "en"}, method="POST"
        )
        self.assertEqual(status, 201)
        return json.loads(body)["report"]

    def test_health_and_metrics_are_local_and_content_free(self):
        status, _, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["storage"], "local-sqlite")
        status, _, body = self.request("/api/metrics")
        self.assertEqual(status, 200)
        metrics = json.loads(body)
        self.assertNotIn("report", metrics)
        self.assertNotIn("code", metrics)

    def test_report_is_saved_without_calling_model_and_human_decision_is_empty(self):
        with patch.object(meta_client, "chat", side_effect=AssertionError("model call must not happen")):
            case = self.create_case()
        self.assertEqual(case["status"], "received")
        self.assertIsNone(case["analysis"])
        self.assertIsNone(case["review_decision"])
        status, _, body = self.request("/api/reports")
        self.assertEqual(status, 200)
        summary = json.loads(body)["reports"][0]
        self.assertNotIn("report", summary)
        self.assertNotIn("code", summary)
        self.assertEqual(summary["id"], case["id"])

    def test_analysis_uses_mocked_model_and_does_not_become_final_decision(self):
        report_text = "IDOR: load by id and expose message body"
        source = "def get_message(request, mid): return Message.objects.get(id=mid)"
        case = self.create_case(report_text, source)
        captured = {}

        def fake_chat(messages, **kwargs):
            captured["messages"] = messages
            return json.dumps(GOOD)

        with patch.object(meta_client, "chat", side_effect=AssertionError("missing consent must not call model")):
            status, _, _ = self.request("/api/reports/%s/analyze" % case["id"], {}, method="POST")
        self.assertEqual(status, 400)
        with patch.object(meta_client, "chat", side_effect=fake_chat):
            status, _, body = self.request(
                "/api/reports/%s/analyze" % case["id"], {"confirm_egress": True}, method="POST"
            )
        self.assertEqual(status, 200)
        result = json.loads(body)["report"]
        self.assertEqual(result["suggested_decision"], "need-info")
        self.assertIsNone(result["review_decision"])
        system_message, user_message = [message["content"] for message in captured["messages"]]
        self.assertNotIn(report_text, system_message)
        self.assertNotIn(source, system_message)
        self.assertIn(report_text, user_message)
        self.assertIn(source, user_message)
        self.assertIn("read-only", user_message.lower())

    def test_review_requires_explicit_human_action_and_is_audited(self):
        case = self.create_case()
        status, _, _ = self.request(
            "/api/reports/%s/review" % case["id"],
            {"decision": "accept", "reviewer": "Reviewer", "note": "Checked."},
            method="POST",
        )
        self.assertEqual(status, 409)
        with patch.object(meta_client, "chat", return_value=json.dumps(GOOD)):
            status, _, _ = self.request(
                "/api/reports/%s/analyze" % case["id"], {"confirm_egress": True}, method="POST"
            )
        self.assertEqual(status, 200)
        status, _, body = self.request(
            "/api/reports/%s/review" % case["id"],
            {"decision": "accept", "reviewer": "Reviewer A", "note": "Reviewed code."},
            method="POST",
        )
        self.assertEqual(status, 200)
        report = json.loads(body)["report"]
        self.assertEqual(report["suggested_decision"], "need-info")
        self.assertEqual(report["review_decision"], "accept")
        self.assertEqual(report["status"], "reviewed")
        status, _, history_body = self.request("/api/reports/%s/history" % case["id"])
        self.assertEqual(status, 200)
        events = json.loads(history_body)["events"]
        self.assertEqual(events[-1]["event_type"], "human_review_recorded")
        self.assertEqual(events[-1]["details"]["review_decision"], "accept")
        with patch.object(meta_client, "chat", side_effect=AssertionError("reviewed case must not be sent again")):
            status, _, _ = self.request(
                "/api/reports/%s/analyze" % case["id"], {"confirm_egress": True}, method="POST"
            )
        self.assertEqual(status, 409)

    def test_provider_error_body_is_not_returned_to_browser(self):
        case = self.create_case()
        secret_detail = "upstream echoed report body and fake-key-12345"
        with patch.object(meta_client, "chat", side_effect=meta_client.MetaAPIError(secret_detail, 502)):
            status, _, body = self.request(
                "/api/reports/%s/analyze" % case["id"], {"confirm_egress": True}, method="POST"
            )
        self.assertEqual(status, 502)
        self.assertNotIn(b"fake-key-12345", body)
        self.assertNotIn(b"upstream echoed", body)

    def test_non_object_json_and_wrong_content_type_are_rejected_cleanly(self):
        status, _, body = self.request("/api/reports", b"[]", method="POST")
        self.assertEqual(status, 400)
        self.assertNotIn(b"Traceback", body)
        status, _, _ = self.request("/api/reports", b"{}", method="POST", content_type="text/plain")
        self.assertEqual(status, 415)

    def test_security_headers_are_present_and_page_has_no_remote_font_dependency(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))
        self.assertNotIn(b"fonts.googleapis.com", body)
        self.assertNotIn(b"fonts.gstatic.com", body)
        self.assertNotIn(b".innerHTML", body)
        self.assertIn(b"textContent", body)

    def test_foreign_host_and_origin_are_rejected(self):
        status, _, _ = self.request("/api/health", extra_headers={"Host": "attacker.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("/api/metrics", extra_headers={"Origin": "https://attacker.example"})
        self.assertEqual(status, 403)

    def test_same_origin_browser_post_is_allowed(self):
        origin = "http://127.0.0.1:%d" % self.port
        status, _, body = self.request(
            "/api/reports",
            {"report": "Local same-origin submission", "code": "", "lang": "en"},
            method="POST",
            extra_headers={"Origin": origin},
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["report"]["status"], "received")

    def test_delete_purges_case_and_history(self):
        case = self.create_case()
        status, _, body = self.request("/api/reports/%s" % case["id"], method="DELETE")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["deleted"])
        status, _, _ = self.request("/api/reports/%s" % case["id"])
        self.assertEqual(status, 404)
        status, _, _ = self.request("/api/reports/%s/history" % case["id"])
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
