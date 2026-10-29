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
import auth_store
import review_store
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
        cls.auth_token = "mizan-test-judge-token-0123456789abcdef"
        cls.auth_env = patch.dict(os.environ, {
            "MIZAN_JUDGE_TOKEN": cls.auth_token,
            "MODEL_API_KEY": "mizan-test-owner-key-never-real",
        })
        cls.auth_env.start()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            "MIZAN_DB_PATH": str(Path(self.temp_dir.name) / "api.sqlite3"),
            "MIZAN_ENCRYPTION_KEY": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        })
        self.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.auth_env.stop()

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def request(self, path, body=None, method="GET", content_type="application/json", extra_headers=None, auth=True, token=None):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        if auth:
            headers["Authorization"] = "Bearer " + (token or self.auth_token)
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

    def create_workspace(self, name):
        status, _, body = self.request("/api/admin/workspaces", {"name": name}, method="POST")
        self.assertEqual(status, 201)
        return json.loads(body)["workspace"]

    def create_user(self, username, role, workspace_id="default"):
        status, _, body = self.request(
            "/api/admin/users", {"username": username, "role": role, "workspace_id": workspace_id}, method="POST"
        )
        self.assertEqual(status, 201)
        return json.loads(body)

    def test_health_and_metrics_are_local_and_content_free(self):
        status, _, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["storage"], "local-sqlite")
        status, _, body = self.request("/api/metrics")
        self.assertEqual(status, 200)
        metrics = json.loads(body)
        self.assertNotIn("report", metrics)
        self.assertNotIn("code", metrics)

    def test_container_healthcheck_is_public_and_minimal(self):
        status, _, body = self.request("/healthz", auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        status, _, _ = self.request(
            "/healthz", auth=False, extra_headers={"Host": "attacker.example"}
        )
        self.assertEqual(status, 403)

    def test_api_requires_valid_bearer_token_and_does_not_create_unauthorized_case(self):
        status, headers, body = self.request("/api/health", auth=False)
        self.assertEqual(status, 401)
        self.assertIn("Bearer", headers.get("WWW-Authenticate", ""))
        self.assertNotIn(b"test-judge-token", body)
        status, _, _ = self.request(
            "/api/health", extra_headers={"Authorization": "Bearer incorrect-token-value"}
        )
        self.assertEqual(status, 401)
        status, _, _ = self.request(
            "/api/reports",
            {"report": "must not persist without auth", "code": "", "lang": "en"},
            method="POST",
            auth=False,
        )
        self.assertEqual(status, 401)
        status, _, body = self.request("/api/reports")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["reports"], [])

    def test_api_fails_closed_when_judge_token_is_missing_or_too_short(self):
        with patch.dict(os.environ):
            os.environ.pop("MIZAN_JUDGE_TOKEN", None)
            status, _, _ = self.request("/api/health", auth=False)
            self.assertEqual(status, 503)
        with patch.dict(os.environ, {"MIZAN_JUDGE_TOKEN": "short"}):
            status, _, _ = self.request("/api/health", auth=False)
            self.assertEqual(status, 503)

    def test_static_login_gate_is_available_before_api_authentication(self):
        status, _, body = self.request("/", auth=False)
        self.assertEqual(status, 200)
        self.assertIn(b"authGate", body)
        self.assertIn(b"Authorization", body)
        self.assertNotIn(b"localStorage", body)
        self.assertNotIn(b"sessionStorage", body)

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
        with patch.object(meta_client, "chat", side_effect=meta_client.MetaAPIError(secret_detail, 401)):
            status, _, body = self.request(
                "/api/reports/%s/analyze" % case["id"], {"confirm_egress": True}, method="POST"
            )
        self.assertEqual(status, 502)
        self.assertNotIn(b"fake-key-12345", body)
        self.assertNotIn(b"upstream echoed", body)

    def test_malformed_admin_user_payloads_have_client_error_statuses(self):
        status, _, body = self.request(
            "/api/admin/users",
            {"username": "bad.role", "role": ["admin"], "workspace_id": "default"},
            method="POST",
        )
        self.assertEqual(status, 400)
        self.assertNotIn(b"Traceback", body)
        status, _, _ = self.request(
            "/api/admin/users",
            {"username": "missing.workspace", "role": "viewer", "workspace_id": "missing"},
            method="POST",
        )
        self.assertEqual(status, 404)
        self.create_user("duplicate.name", "viewer")
        status, _, _ = self.request(
            "/api/admin/users",
            {"username": "duplicate.name", "role": "viewer", "workspace_id": "default"},
            method="POST",
        )
        self.assertEqual(status, 409)

    def test_user_revocation_storage_error_is_returned_as_sanitized_json(self):
        user = self.create_user("revoke.error", "viewer")
        with patch.object(auth_store, "revoke_user", side_effect=RuntimeError("private database detail")):
            status, _, body = self.request(
                "/api/admin/users/%s" % user["user"]["id"], method="DELETE"
            )
        self.assertEqual(status, 500)
        self.assertIn(b"Internal server error", body)
        self.assertNotIn(b"private database detail", body)

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

    def test_workspace_boundaries_hide_lists_metrics_details_and_history(self):
        first = self.create_workspace("Team Alpha")
        second = self.create_workspace("Team Beta")
        alpha = self.create_user("alpha.analyst", "analyst", first["id"])
        beta = self.create_user("beta.viewer", "viewer", second["id"])
        status, _, body = self.request(
            "/api/reports", {"report": "Alpha private report", "code": "private code", "lang": "en"},
            method="POST", token=alpha["token"],
        )
        self.assertEqual(status, 201)
        case_id = json.loads(body)["report"]["id"]
        status, _, body = self.request("/api/reports", token=beta["token"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["reports"], [])
        status, _, body = self.request("/api/metrics", token=beta["token"])
        self.assertEqual(json.loads(body)["total_reports"], 0)
        status, _, _ = self.request("/api/reports/%s" % case_id, token=beta["token"])
        self.assertEqual(status, 404)
        status, _, _ = self.request("/api/reports/%s/history" % case_id, token=beta["token"])
        self.assertEqual(status, 404)
        status, _, body = self.request("/api/reports", token=alpha["token"])
        self.assertEqual(len(json.loads(body)["reports"]), 1)
        status, _, body = self.request("/api/reports", token=self.auth_token)
        self.assertGreaterEqual(len(json.loads(body)["reports"]), 1)

    def test_role_matrix_and_workspace_admin_scope_are_enforced_server_side(self):
        first = self.create_workspace("Team Alpha")
        second = self.create_workspace("Team Beta")
        admin = self.create_user("alpha.admin", "admin", first["id"])
        analyst = self.create_user("alpha.analyst", "analyst", first["id"])
        reviewer = self.create_user("alpha.reviewer", "reviewer", first["id"])
        viewer = self.create_user("alpha.viewer", "viewer", first["id"])
        status, _, _ = self.request(
            "/api/admin/users", {"username": "escape.user", "role": "viewer", "workspace_id": second["id"]},
            method="POST", token=admin["token"],
        )
        self.assertEqual(status, 404)
        status, _, _ = self.request(
            "/api/admin/users", {"username": "overprivileged", "role": "admin", "workspace_id": first["id"]},
            method="POST", token=admin["token"],
        )
        self.assertEqual(status, 403)
        status, _, _ = self.request(
            "/api/reports", {"report": "not permitted", "code": "", "lang": "en"},
            method="POST", token=reviewer["token"],
        )
        self.assertEqual(status, 403)
        status, _, _ = self.request(
            "/api/reports", {"report": "not permitted", "code": "", "lang": "en"},
            method="POST", token=viewer["token"],
        )
        self.assertEqual(status, 403)
        case = self.create_case("Role test case")
        status, _, _ = self.request(
            "/api/reports/%s/review" % case["id"], {"decision": "accept", "note": ""},
            method="POST", token=analyst["token"],
        )
        self.assertEqual(status, 403)
        status, _, _ = self.request("/api/reports/%s" % case["id"], method="DELETE", token=reviewer["token"])
        self.assertEqual(status, 403)

    def test_revoked_personal_token_is_rejected_immediately(self):
        user = self.create_user("revoke.me", "viewer")
        status, _, _ = self.request("/api/me", token=user["token"])
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/admin/users/%s" % user["user"]["id"], method="DELETE")
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/me", token=user["token"])
        self.assertEqual(status, 401)

    def test_admin_can_rotate_a_user_token_once_and_old_token_stops_working(self):
        user = self.create_user("rotate.me", "viewer")
        status, _, body = self.request(
            "/api/admin/users/%s/rotate-token" % user["user"]["id"], {}, method="POST"
        )
        self.assertEqual(status, 200)
        rotated = json.loads(body)["token"]
        self.assertNotEqual(rotated, user["token"])
        self.assertIn(rotated.encode(), body)
        status, _, _ = self.request("/api/me", token=user["token"])
        self.assertEqual(status, 401)
        status, _, profile = self.request("/api/me", token=rotated)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(profile)["username"], "rotate.me")

    def test_authenticated_reviewer_identity_cannot_be_spoofed_in_request_body(self):
        analyst = self.create_user("case.analyst", "analyst")
        reviewer = self.create_user("verified.reviewer", "reviewer")
        status, _, body = self.request(
            "/api/reports", {"report": "Identity audit test", "code": "", "lang": "en"},
            method="POST", token=analyst["token"],
        )
        case_id = json.loads(body)["report"]["id"]
        status, _, _ = self.request(
            "/api/me/model-key", {"api_key": "identity-test-key-not-real"}, method="PUT", token=analyst["token"]
        )
        self.assertEqual(status, 200)
        with patch.object(meta_client, "chat", return_value=json.dumps(GOOD)):
            status, _, _ = self.request(
                "/api/reports/%s/analyze" % case_id, {"confirm_egress": True}, method="POST",
                token=analyst["token"],
            )
        self.assertEqual(status, 200)
        status, _, body = self.request(
            "/api/reports/%s/review" % case_id,
            {"decision": "accept", "reviewer": "Forged Administrator", "note": "Reviewed."},
            method="POST", token=reviewer["token"],
        )
        self.assertEqual(status, 200)
        result = json.loads(body)["report"]
        self.assertEqual(result["reviewer"], "verified.reviewer")
        status, _, body = self.request("/api/reports/%s/history" % case_id, token=reviewer["token"])
        event = json.loads(body)["events"][-1]
        self.assertEqual(event["actor"], "verified.reviewer")
        self.assertEqual(event["actor_user_id"], reviewer["user"]["id"])

    def test_each_researcher_uses_own_encrypted_model_key_and_missing_key_blocks_egress(self):
        analyst = self.create_user("key.owner", "analyst")
        no_key = self.create_user("no.key", "analyst")
        personal_key = "meta-personal-key-not-real-123"
        status, _, body = self.request(
            "/api/me/model-key", {"api_key": personal_key}, method="PUT", token=analyst["token"]
        )
        self.assertEqual(status, 200)
        self.assertNotIn(personal_key.encode(), body)
        status, _, profile = self.request("/api/me", token=analyst["token"])
        self.assertTrue(json.loads(profile)["has_model_key"])
        status, _, profile = self.request("/api/me", token=no_key["token"])
        self.assertFalse(json.loads(profile)["has_model_key"])
        status, _, body = self.request(
            "/api/reports", {"report": "Per-user key test", "code": "", "lang": "en"},
            method="POST", token=analyst["token"],
        )
        case_id = json.loads(body)["report"]["id"]
        captured = {}

        def fake_chat(messages, **kwargs):
            captured["api_key"] = kwargs.get("api_key")
            return json.dumps(GOOD)

        with patch.object(meta_client, "chat", side_effect=fake_chat):
            status, _, _ = self.request(
                "/api/reports/%s/analyze" % case_id, {"confirm_egress": True}, method="POST",
                token=analyst["token"],
            )
        self.assertEqual(status, 200)
        self.assertEqual(captured["api_key"], personal_key)
        status, _, body = self.request(
            "/api/triage", {"report": "no key", "confirm_egress": True}, method="POST", token=no_key["token"]
        )
        self.assertEqual(status, 409)
        self.assertIn(b"Meta API key", body)
        with review_store._connect() as conn:
            stored = conn.execute("SELECT ciphertext FROM user_api_keys WHERE user_id=?", (analyst["user"]["id"],)).fetchone()[0]
        self.assertNotIn(personal_key.encode(), bytes(stored))


if __name__ == "__main__":
    unittest.main(verbosity=2)
