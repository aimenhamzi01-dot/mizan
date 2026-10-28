import os
import re
import tempfile
import unittest
from pathlib import Path

from scripts.bootstrap import prepare_env


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / ".env.example").write_text(
            "MIZAN_JUDGE_TOKEN=\nMODEL_API_KEY=\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_first_run_generates_private_token_and_unique_compose_project(self):
        token = prepare_env(self.root)
        env_path = self.root / ".env"
        content = env_path.read_text(encoding="utf-8")
        self.assertIsNotNone(token)
        self.assertGreaterEqual(len(token.encode("utf-8")), 32)
        self.assertIn("MIZAN_JUDGE_TOKEN=" + token, content)
        self.assertIn("MODEL_API_KEY=", content)
        match = re.search(r"(?m)^COMPOSE_PROJECT_NAME=(mizan-[0-9a-f]{16})$", content)
        self.assertIsNotNone(match)
        self.assertNotIn(token, (self.root / ".env.example").read_text(encoding="utf-8"))
        if os.name == "posix":
            self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)
        before = env_path.read_text(encoding="utf-8")
        self.assertIsNone(prepare_env(self.root))
        self.assertEqual(env_path.read_text(encoding="utf-8"), before)

    def test_separate_installations_get_different_tokens_and_volumes(self):
        second_root = self.root / "second-installation"
        second_root.mkdir()
        (second_root / ".env.example").write_text(
            "MIZAN_JUDGE_TOKEN=\nMODEL_API_KEY=\n", encoding="utf-8"
        )
        first_token = prepare_env(self.root)
        second_token = prepare_env(second_root)
        first_config = (self.root / ".env").read_text(encoding="utf-8")
        second_config = (second_root / ".env").read_text(encoding="utf-8")
        first_project = re.search(r"(?m)^COMPOSE_PROJECT_NAME=(.+)$", first_config).group(1)
        second_project = re.search(r"(?m)^COMPOSE_PROJECT_NAME=(.+)$", second_config).group(1)
        self.assertNotEqual(first_token, second_token)
        self.assertNotEqual(first_project, second_project)

    def test_valid_existing_token_is_preserved_and_not_returned(self):
        expected = "x" * 43
        env_path = self.root / ".env"
        env_path.write_text(
            "MIZAN_JUDGE_TOKEN=" + expected + "\nMODEL_API_KEY=my-own-key\n",
            encoding="utf-8",
        )
        token = prepare_env(self.root)
        content = env_path.read_text(encoding="utf-8")
        self.assertIsNone(token)
        self.assertIn("MIZAN_JUDGE_TOKEN=" + expected, content)
        self.assertIn("MODEL_API_KEY=my-own-key", content)
        self.assertIn("COMPOSE_PROJECT_NAME=mizan-", content)

    def test_weak_token_is_replaced_without_losing_other_settings(self):
        env_path = self.root / ".env"
        env_path.write_text(
            "MIZAN_JUDGE_TOKEN=short\nMODEL_API_KEY=private-value\n", encoding="utf-8"
        )
        token = prepare_env(self.root)
        content = env_path.read_text(encoding="utf-8")
        self.assertIsNotNone(token)
        self.assertNotEqual(token, "short")
        self.assertIn("MIZAN_JUDGE_TOKEN=" + token, content)
        self.assertIn("MODEL_API_KEY=private-value", content)

    def test_duplicate_secret_or_project_entries_are_rejected(self):
        env_path = self.root / ".env"
        env_path.write_text("MIZAN_JUDGE_TOKEN=\nMIZAN_JUDGE_TOKEN=\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            prepare_env(self.root)
        env_path.write_text(
            "MIZAN_JUDGE_TOKEN=" + "x" * 43 + "\n"
            "COMPOSE_PROJECT_NAME=mizan-one\nCOMPOSE_PROJECT_NAME=mizan-two\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            prepare_env(self.root)

    def test_invalid_compose_name_is_rejected(self):
        env_path = self.root / ".env"
        env_path.write_text(
            "MIZAN_JUDGE_TOKEN=" + "x" * 43 + "\nCOMPOSE_PROJECT_NAME=Not Valid\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "COMPOSE_PROJECT_NAME"):
            prepare_env(self.root)

    def test_symlinked_env_is_rejected(self):
        target = self.root / "other-file"
        target.write_text("leave unchanged\n", encoding="utf-8")
        (self.root / ".env").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            prepare_env(self.root)
        self.assertEqual(target.read_text(encoding="utf-8"), "leave unchanged\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
