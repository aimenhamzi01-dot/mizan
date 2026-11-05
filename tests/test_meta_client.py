import io
import json
import os
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import meta_client


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        return self.body if size is None or size < 0 else self.body[:size]


def response_text(text="{\"ok\":true}"):
    return FakeResponse(json.dumps({"choices": [{"message": {"content": text}}]}).encode("utf-8"))


class MetaClientTests(unittest.TestCase):
    def test_request_shape_and_config_are_sent_only_to_configured_base(self):
        env = {
            "MODEL_API_KEY": "test-key-not-real",
            "META_API_BASE": "https://api.meta.ai/v1",
            "META_MODEL": "muse-spark-1.3",
            "META_REASONING_EFFORT": "medium",
        }
        messages = [{"role": "system", "content": "test system"}, {"role": "user", "content": "test data"}]
        response_format = {"type": "json_schema", "json_schema": {"name": "test", "strict": True, "schema": {"type": "object"}}}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=response_text("model answer")
        ) as opener:
            self.assertEqual(meta_client.chat(messages, response_format=response_format), "model answer")
        request = opener.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(request.full_url, "https://api.meta.ai/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key-not-real")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(payload["model"], "muse-spark-1.3")
        self.assertEqual(payload["messages"], messages)
        self.assertEqual(payload["response_format"], response_format)
        self.assertEqual(payload["max_completion_tokens"], 3000)
        self.assertEqual(payload["reasoning_effort"], "medium")
        self.assertNotIn("temperature", payload)
        self.assertEqual(opener.call_args.kwargs["timeout"], 120)

    def test_high_reasoning_is_the_default_and_can_be_overridden_per_installation(self):
        env = {"MODEL_API_KEY": "test-key", "META_MODEL": "muse-spark-1.3"}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=response_text("answer")
        ) as opener:
            result = meta_client.chat([], return_metadata=True)
        payload = json.loads(opener.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(payload["reasoning_effort"], "high")
        self.assertEqual(result["reasoning_effort"], "high")

        env["META_REASONING_EFFORT"] = "medium"
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=response_text("answer")
        ) as opener:
            meta_client.chat([])
        self.assertEqual(json.loads(opener.call_args.args[0].data.decode("utf-8"))["reasoning_effort"], "medium")

    def test_challenge_models_exclude_primary_and_deduplicate(self):
        env = {"META_CHALLENGE_MODELS": "muse-spark-1.2,muse-spark-1.1,muse-spark-1.1"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(meta_client.get_challenge_models("muse-spark-1.2"), ["muse-spark-1.1"])
            self.assertEqual(meta_client.get_challenge_models("muse-spark-1.3"), ["muse-spark-1.2", "muse-spark-1.1"])

    def test_chat_uses_filtered_challenge_candidates_in_request(self):
        env = {"MODEL_API_KEY": "test-key", "META_MODEL": "muse-spark-1.3"}
        challenge_models = ["muse-spark-1.2", "muse-spark-1.1"]
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=response_text("answer")
        ) as opener:
            meta_client.chat([], model_candidates=challenge_models)
        payload = json.loads(opener.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(payload["model"], "muse-spark-1.2")
        self.assertEqual(payload["reasoning_effort"], "high")

    def test_max_reasoning_is_supported_only_for_spark_1_3_and_wonder(self):
        with patch.dict(os.environ, {"META_REASONING_EFFORT": "max"}, clear=True):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.get_reasoning_effort("muse-spark-1.2")
        self.assertEqual(caught.exception.status, 400)
        with patch.dict(os.environ, {"META_REASONING_EFFORT": "max"}, clear=True):
            self.assertEqual(meta_client.get_reasoning_effort("muse-spark-1.3"), "max")
            self.assertEqual(meta_client.get_reasoning_effort("muse-wonder-1.0"), "max")
            with patch("meta_client._open_request", return_value=response_text("answer")) as opener:
                meta_client.chat([], api_key="test-key", model_candidates=["muse-wonder-1.0"])
        payload = json.loads(opener.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(payload["model"], "muse-wonder-1.0")
        self.assertEqual(payload["reasoning_effort"], "max")

    def test_response_metadata_is_opt_in_and_usage_is_allowlisted(self):
        body = json.dumps({
            "model": "muse-spark-resolved",
            "choices": [{"message": {"content": "model answer"}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17, "private": "omit"},
        }).encode("utf-8")
        env = {"MODEL_API_KEY": "test-key", "META_MODEL": "muse-spark-1.3"}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=FakeResponse(body)
        ):
            result = meta_client.chat([], return_metadata=True)
        self.assertEqual(result["content"], "model answer")
        self.assertEqual(result["model"], "muse-spark-resolved")
        self.assertEqual(result["usage"], {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17})

    def test_metadata_uses_requested_model_when_provider_omits_it(self):
        body = json.dumps({"choices": [{"message": {"content": "model answer"}}]}).encode("utf-8")
        env = {"MODEL_API_KEY": "test-key", "META_MODEL": "muse-spark-1.3"}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=FakeResponse(body)
        ):
            result = meta_client.chat([], return_metadata=True)
        self.assertEqual(result["model"], "muse-spark-1.3")
        self.assertEqual(result["usage"], {})

    def test_unavailable_model_falls_back_without_exposing_provider_body(self):
        error = urllib.error.HTTPError(
            "https://api.meta.ai/v1/chat/completions",
            404,
            "not found",
            {},
            io.BytesIO(b"unknown model private-provider-detail"),
        )
        calls = []

        def fake_open(request, timeout):
            calls.append(json.loads(request.data.decode("utf-8"))["model"])
            if len(calls) == 1:
                raise error
            return response_text("fallback answer")

        env = {
            "MODEL_API_KEY": "test-key",
            "META_API_BASE": "https://api.meta.ai/v1",
            "META_MODEL": "first-model,second-model",
        }
        with patch.dict(os.environ, env, clear=True), patch("meta_client._open_request", side_effect=fake_open):
            self.assertEqual(meta_client.chat([]), "fallback answer")
        self.assertEqual(calls, ["first-model", "second-model"])

    def test_http_error_body_is_not_in_exception(self):
        error = urllib.error.HTTPError(
            "https://api.meta.ai/v1/chat/completions",
            401,
            "unauthorized",
            {},
            io.BytesIO(b"fake-key-should-not-leak report-secret-123"),
        )
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "https://api.meta.ai/v1", "META_MODEL": "muse-spark-1.3"}
        with patch.dict(os.environ, env, clear=True), patch("meta_client._open_request", side_effect=error):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 401)
        self.assertNotIn("fake-key-should-not-leak", str(caught.exception))
        self.assertNotIn("report-secret-123", str(caught.exception))

    def test_network_error_reason_is_not_exposed(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "https://api.meta.ai/v1"}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", side_effect=urllib.error.URLError("secret host detail")
        ):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 502)
        self.assertNotIn("secret host detail", str(caught.exception))

    def test_redirect_is_not_followed_to_another_origin(self):
        captured_authorizations = []

        class CaptureHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                captured_authorizations.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"choices":[{"message":{"content":"redirected"}}]}')

            def log_message(self, *args):
                pass

        capture = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        capture_thread = threading.Thread(target=capture.serve_forever, daemon=True)
        capture_thread.start()

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/v1/chat/completions" % capture.server_port)
                self.end_headers()

            def log_message(self, *args):
                pass

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        redirect_thread.start()
        env = {
            "MODEL_API_KEY": "test-key-must-not-forward",
            "META_API_BASE": "http://127.0.0.1:%d/v1" % redirect.server_port,
            "META_MODEL": "muse-spark-1.3",
        }
        try:
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(meta_client.MetaAPIError) as caught:
                    meta_client.chat([])
            self.assertEqual(caught.exception.status, 502)
            self.assertIn("redirected", str(caught.exception))
            self.assertEqual(captured_authorizations, [])
        finally:
            redirect.shutdown()
            redirect.server_close()
            capture.shutdown()
            capture.server_close()

    def test_remote_http_endpoint_is_rejected_before_network_access(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "http://provider.example/v1"}
        with patch.dict(os.environ, env, clear=True), patch("meta_client._open_request") as opener:
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("HTTPS", str(caught.exception))
        opener.assert_not_called()

    def test_loopback_http_endpoint_is_allowed_for_local_development(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "http://localhost:9000/v1"}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client._open_request", return_value=response_text("local answer")
        ) as opener:
            self.assertEqual(meta_client.chat([]), "local answer")
        self.assertEqual(opener.call_args.args[0].full_url, "http://localhost:9000/v1/chat/completions")

    def test_timeouts_are_reported_safely_and_usage_uncertainty_is_clear(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "https://api.meta.ai/v1"}
        failures = [TimeoutError("private timeout detail"), urllib.error.URLError(TimeoutError("private timeout detail"))]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch.dict(os.environ, env, clear=True), patch(
                    "meta_client._open_request", side_effect=failure
                ):
                    with self.assertRaises(meta_client.MetaAPIError) as caught:
                        meta_client.chat([])
                self.assertEqual(caught.exception.status, 504)
                self.assertIn("usage may be uncertain", str(caught.exception))
                self.assertNotIn("private timeout detail", str(caught.exception))

    def test_oversized_response_is_rejected(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "https://api.meta.ai/v1"}
        oversized = FakeResponse(b"x" * (meta_client.MAX_RESPONSE_BYTES + 1))
        with patch.dict(os.environ, env, clear=True), patch("meta_client._open_request", return_value=oversized):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 502)
        self.assertIn("size limit", str(caught.exception))

    def test_missing_key_fails_before_any_network_call(self):
        with patch.dict(os.environ, {}, clear=True), patch("meta_client._open_request") as opener:
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 401)
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
