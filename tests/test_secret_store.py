import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import review_store
import secret_store


class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        key = base64.urlsafe_b64encode(b"k" * 32).decode("ascii")
        self.env = patch.dict(os.environ, {
            "MIZAN_DB_PATH": str(Path(self.temp_dir.name) / "secrets.sqlite3"),
            "MIZAN_ENCRYPTION_KEY": key,
        })
        self.env.start()
        review_store.init_db()

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def test_user_key_round_trips_but_is_never_stored_as_plaintext(self):
        user_id = "user-123"
        api_key = "meta-private-user-key-not-real"
        secret_store.set_user_api_key(user_id, api_key)
        self.assertTrue(secret_store.has_user_api_key(user_id))
        self.assertEqual(secret_store.get_user_api_key(user_id), api_key)
        with review_store._connect() as conn:
            row = conn.execute("SELECT nonce, ciphertext FROM user_api_keys WHERE user_id=?", (user_id,)).fetchone()
        self.assertEqual(len(row["nonce"]), 12)
        self.assertNotIn(api_key.encode(), bytes(row["ciphertext"]))
        self.assertIsNone(secret_store.get_user_api_key("different-user"))

    def test_missing_master_key_refuses_to_save_and_wrong_key_cannot_decrypt(self):
        with patch.dict(os.environ):
            os.environ.pop("MIZAN_ENCRYPTION_KEY", None)
            with self.assertRaises(secret_store.SecretStoreError):
                secret_store.set_user_api_key("user-123", "test-key")
        secret_store.set_user_api_key("user-123", "test-key")
        with patch.dict(os.environ, {"MIZAN_ENCRYPTION_KEY": base64.urlsafe_b64encode(b"z" * 32).decode()}):
            with self.assertRaises(secret_store.SecretStoreError):
                secret_store.get_user_api_key("user-123")

    def test_key_can_be_replaced_and_removed(self):
        secret_store.set_user_api_key("user-123", "first-key")
        secret_store.set_user_api_key("user-123", "second-key")
        self.assertEqual(secret_store.get_user_api_key("user-123"), "second-key")
        self.assertTrue(secret_store.delete_user_api_key("user-123"))
        self.assertIsNone(secret_store.get_user_api_key("user-123"))
        self.assertFalse(secret_store.delete_user_api_key("user-123"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
