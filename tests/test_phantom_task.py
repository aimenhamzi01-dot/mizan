import unittest

import phantom_task


class PhantomTaskTests(unittest.TestCase):
    def payload(self, **changes):
        value = {
            "target": "https://scope.example.org/app",
            "target_type": "web",
            "scope": ["XSS", "idor"],
            "authorized_scope": True,
        }
        value.update(changes)
        return value

    def test_manifest_is_explicit_manual_data_handoff(self):
        result = phantom_task.create_manifest(self.payload(), requester="analyst", workspace_id="ws-1")
        self.assertEqual(result["format"], "mizan-phantom-task-v1")
        self.assertEqual(result["target"], "https://scope.example.org/app")
        self.assertEqual(result["scope"], ["xss", "idor"])
        self.assertTrue(result["authorization"]["attested_by_user"])
        self.assertIn("not independently verified", result["authorization"]["statement"])
        self.assertFalse(result["execution"]["automatic_execution"])
        self.assertFalse(result["execution"]["network_access_by_mizan"])
        self.assertEqual(result["requested_by"], "analyst")

    def test_requires_explicit_authorization_attestation(self):
        with self.assertRaisesRegex(ValueError, "Confirm that you are authorized"):
            phantom_task.create_manifest(self.payload(authorized_scope=False), requester="a", workspace_id="w")

    def test_rejects_non_text_target_type(self):
        with self.assertRaisesRegex(ValueError, "Unsupported Phantom target type"):
            phantom_task.create_manifest(self.payload(target_type=[]), requester="a", workspace_id="w")

    def test_target_is_carried_as_data_without_scope_validation_or_network_access(self):
        target = "http://127.0.0.1/internal-path"
        result = phantom_task.create_manifest(self.payload(target=target), requester="a", workspace_id="w")
        self.assertEqual(result["target"], target)
        self.assertFalse(result["execution"]["network_access_by_mizan"])

    def test_rejects_scope_outside_allowlist_and_empty_scope(self):
        for scope in ([], ["arbitrary-command"], ["xss"] * 13):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                phantom_task.create_manifest(self.payload(scope=scope), requester="a", workspace_id="w")

    def test_accepts_identifier_for_mobile_target(self):
        result = phantom_task.create_manifest(
            self.payload(target_type="mobile", target="org.example.app"),
            requester="analyst", workspace_id="ws-1",
        )
        self.assertEqual(result["target"], "org.example.app")
        self.assertEqual(result["target_type"], "mobile")


if __name__ == "__main__":
    unittest.main()
