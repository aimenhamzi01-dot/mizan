import io
import json
import os
import unittest
from unittest.mock import patch
import urllib.error

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
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client.urllib.request.urlopen", return_value=response_text("model answer")
        ) as urlopen:
            self.assertEqual(meta_client.chat(messages), "model answer")
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(request.full_url, "https://api.meta.ai/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key-not-real")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(payload["model"], "muse-spark-1.3")
        self.assertEqual(payload["messages"], messages)
        self.assertEqual(payload["reasoning_effort"], "medium")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 120)

    def test_unavailable_model_falls_back_without_exposing_provider_body(self):
        error = urllib.error.HTTPError(
            "https://api.meta.ai/v1/chat/completions",
            404,
            "not found",
            {},
            io.BytesIO(b"unknown model private-provider-detail"),
        )
        calls = []

        def fake_urlopen(request, timeout):
            calls.append(json.loads(request.data.decode("utf-8"))["model"])
            if len(calls) == 1:
                raise error
            return response_text("fallback answer")

        env = {
            "MODEL_API_KEY": "test-key",
            "META_API_BASE": "https://api.meta.ai/v1",
            "META_MODEL": "first-model,second-model",
        }
        with patch.dict(os.environ, env, clear=True), patch("meta_client.urllib.request.urlopen", side_effect=fake_urlopen):
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
        with patch.dict(os.environ, env, clear=True), patch("meta_client.urllib.request.urlopen", side_effect=error):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 401)
        self.assertNotIn("fake-key-should-not-leak", str(caught.exception))
        self.assertNotIn("report-secret-123", str(caught.exception))

    def test_network_error_reason_is_not_exposed(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "https://api.meta.ai/v1"}
        with patch.dict(os.environ, env, clear=True), patch(
            "meta_client.urllib.request.urlopen", side_effect=urllib.error.URLError("secret host detail")
        ):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 502)
        self.assertNotIn("secret host detail", str(caught.exception))

    def test_oversized_response_is_rejected(self):
        env = {"MODEL_API_KEY": "test-key", "META_API_BASE": "https://api.meta.ai/v1"}
        oversized = FakeResponse(b"x" * (meta_client.MAX_RESPONSE_BYTES + 1))
        with patch.dict(os.environ, env, clear=True), patch("meta_client.urllib.request.urlopen", return_value=oversized):
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 502)
        self.assertIn("size limit", str(caught.exception))

    def test_missing_key_fails_before_any_network_call(self):
        with patch.dict(os.environ, {}, clear=True), patch("meta_client.urllib.request.urlopen") as urlopen:
            with self.assertRaises(meta_client.MetaAPIError) as caught:
                meta_client.chat([])
        self.assertEqual(caught.exception.status, 401)
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
