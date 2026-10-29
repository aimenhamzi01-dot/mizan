import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import auth_store
import review_store


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"MIZAN_DB_PATH": str(Path(self.temp_dir.name) / "auth.sqlite3")})
        self.env.start()
        review_store.init_db()

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def test_user_gets_one_high_entropy_token_and_only_its_digest_is_stored(self):
        workspace = auth_store.create_workspace("AppSec Team")
        user, token = auth_store.create_user("researcher.alex", "analyst", workspace["id"], created_by="owner")
        self.assertGreaterEqual(len(token), 40)
        self.assertEqual(user["role"], "analyst")
        principal = auth_store.authenticate_token(token)
        self.assertEqual(principal["id"], user["id"])
        self.assertEqual(principal["workspace_id"], workspace["id"])
        with review_store._connect() as conn:
            row = conn.execute("SELECT token_hash FROM users WHERE id=?", (user["id"],)).fetchone()
        self.assertNotEqual(row["token_hash"], token)
        self.assertNotIn(token, row["token_hash"])

    def test_revocation_is_immediate_and_removes_the_users_encrypted_key(self):
        workspace = auth_store.create_workspace("AppSec")
        user, token = auth_store.create_user("analyst.one", "analyst", workspace["id"], created_by="owner")
        with review_store._connect() as conn:
            conn.execute(
                "INSERT INTO user_api_keys(user_id, nonce, ciphertext, updated_at) VALUES (?, ?, ?, 'now')",
                (user["id"], b"n" * 12, b"ciphertext"),
            )
        self.assertTrue(auth_store.revoke_user(user["id"], workspace_id=workspace["id"]))
        self.assertIsNone(auth_store.authenticate_token(token))
        with review_store._connect() as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM user_api_keys WHERE user_id=?", (user["id"],)).fetchone())
        self.assertFalse(auth_store.revoke_user(user["id"], workspace_id=workspace["id"]))

    def test_duplicate_user_invalid_role_and_unknown_workspace_are_rejected(self):
        workspace = auth_store.create_workspace("AppSec")
        auth_store.create_user("reviewer.one", "reviewer", workspace["id"], created_by="owner")
        with self.assertRaises(auth_store.DuplicateUser):
            auth_store.create_user("reviewer.one", "analyst", workspace["id"], created_by="owner")
        with self.assertRaises(ValueError):
            auth_store.create_user("bad user", "analyst", workspace["id"], created_by="owner")
        with self.assertRaises(ValueError):
            auth_store.create_user("viewer.two", "owner", workspace["id"], created_by="owner")
        with self.assertRaises(auth_store.WorkspaceNotFound):
            auth_store.create_user("viewer.two", "viewer", "missing", created_by="owner")

    def test_repeated_initialization_records_schema_version_and_default_workspace(self):
        review_store.init_db()
        review_store.init_db()
        with review_store._connect() as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], review_store.SCHEMA_VERSION)
            row = conn.execute("SELECT name FROM workspaces WHERE id='default'").fetchone()
        self.assertEqual(row["name"], "Default workspace")

    def test_v1_database_migrates_existing_case_and_history_into_default_workspace(self):
        path = Path(self.temp_dir.name) / "legacy.sqlite3"
        with patch.dict(os.environ, {"MIZAN_DB_PATH": str(path)}):
            conn = sqlite3.connect(str(path))
            conn.executescript(
                "CREATE TABLE reports (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
                "language TEXT NOT NULL, report TEXT NOT NULL, code TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, "
                "analysis_json TEXT, suggested_decision TEXT, review_decision TEXT, reviewer TEXT NOT NULL DEFAULT '', "
                "review_note TEXT NOT NULL DEFAULT '');"
                "CREATE TABLE report_events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL, "
                "occurred_at TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, details_json TEXT NOT NULL);"
                "PRAGMA user_version=1;"
            )
            conn.execute(
                "INSERT INTO reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("legacy-id", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z", "en", "Legacy report", "", "received", None, None, None, "", ""),
            )
            conn.execute(
                "INSERT INTO report_events(report_id, occurred_at, event_type, actor, details_json) VALUES (?, ?, ?, ?, ?)",
                ("legacy-id", "2025-01-01T00:00:00Z", "report_received", "local-user", "{}"),
            )
            conn.commit()
            conn.close()

            review_store.init_db()
            case = review_store.get_report("legacy-id", workspace_id="default")
            self.assertEqual(case["report"], "Legacy report")
            self.assertEqual(review_store.list_reports(workspace_id="default")[0]["id"], "legacy-id")
            self.assertEqual(review_store.metrics(workspace_id="default")["total_reports"], 1)
            events = review_store.report_history("legacy-id", workspace_id="default")
            self.assertEqual(events[0]["actor"], "local-user")
            self.assertIsNone(events[0]["actor_user_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
