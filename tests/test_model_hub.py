import os
import unittest
from unittest.mock import patch

import model_hub


class ModelHubTests(unittest.TestCase):
    def test_registry_covers_required_meta_families_and_default(self):
        with patch.dict(os.environ, {"META_MODEL": "", "MIZAN_ENABLED_MODELS": ""}, clear=False):
            registry = model_hub.public_registry()
        rows = {row["hub_id"]: row for row in registry["models"]}
        self.assertEqual(registry["default_model"], "muse-spark-1.3")
        self.assertEqual(len(rows), 13)
        expected = {
            "Muse Spark", "Muse Wonder", "Muse Wonder Full", "Muse Image",
            "Muse Voice Transcribe", "SAM 3.1 / Object Multiplex", "Muse Glimmer",
            "Muse Spark Open", "Llama and other Meta open-weight LLMs",
        }
        self.assertTrue(expected.issubset({row["family"] for row in rows.values()}))
        self.assertTrue(rows["muse-spark-1.3"]["selectable"])
        self.assertFalse(rows["muse-wonder-1.0"]["selectable"])

    def test_wonder_requires_explicit_opt_in(self):
        with patch.dict(os.environ, {"META_MODEL": "muse-spark-1.3", "MIZAN_ENABLED_MODELS": ""}):
            self.assertNotIn("muse-wonder-1.0", model_hub.enabled_model_ids())
        with patch.dict(os.environ, {
            "META_MODEL": "muse-spark-1.3", "MIZAN_ENABLED_MODELS": "muse-wonder-1.0",
        }):
            self.assertIn("muse-wonder-1.0", model_hub.enabled_model_ids())
            selected = model_hub.resolve_model("muse-wonder-1.0")
            self.assertEqual(selected["integration"], "experimental-opt-in")

    def test_pending_family_adapters_cannot_make_network_requests(self):
        for model_id in ("muse-image-1.0", "muse-voice-transcribe-1.0", "sam-3.1", "muse-glimmer-30b", "muse-spark-open", "llama-open-weight"):
            with self.subTest(model_id=model_id):
                with self.assertRaises(model_hub.ModelHubError):
                    model_hub.resolve_model(model_id)

    def test_enabled_model_is_routed_as_a_single_candidate(self):
        with patch.object(model_hub.meta_client, "chat", return_value='{"ok":true}') as chat:
            result, record = model_hub.route_chat("muse-spark-1.2", model_hub.TASK_SECURITY_TRIAGE, [])
        self.assertEqual(result, '{"ok":true}')
        self.assertEqual(record["model_id"], "muse-spark-1.2")
        chat.assert_called_once_with([], model_candidates=["muse-spark-1.2"])

    def test_registry_has_no_provider_prices_or_private_credentials(self):
        payload = model_hub.public_registry(has_meta_key=True)
        self.assertTrue(all(row["price_estimate"] is None for row in payload["models"]))
        secret_fields = {"api_key", "endpoint", "base_url", "api_base"}
        self.assertTrue(all(not (secret_fields & set(row)) for row in payload["models"]))
        self.assertTrue(secret_fields.isdisjoint(payload["local_runtime"]))
        self.assertIn("not estimated", payload["usage_tracking"])


if __name__ == "__main__":
    unittest.main()
