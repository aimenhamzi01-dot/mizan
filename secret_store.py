"""Authenticated encryption for per-user Meta API credentials.

The 256-bit installation key is supplied only through MIZAN_ENCRYPTION_KEY.
Ciphertext is bound to the owning user id as AES-GCM associated data.
"""
from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import review_store


class SecretStoreError(Exception):
    pass


def _master_key() -> bytes:
    encoded = os.environ.get("MIZAN_ENCRYPTION_KEY", "").strip()
    if not encoded:
        raise SecretStoreError("MIZAN_ENCRYPTION_KEY is not configured.")
    try:
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except Exception:
        raise SecretStoreError("MIZAN_ENCRYPTION_KEY is invalid.") from None
    if len(key) != 32:
        raise SecretStoreError("MIZAN_ENCRYPTION_KEY must encode exactly 32 bytes.")
    return key


def set_user_api_key(user_id: str, api_key: str) -> None:
    if not isinstance(api_key, str):
        raise ValueError("API key must be text.")
    api_key = api_key.strip()
    if not api_key or len(api_key) > 512:
        raise ValueError("API key must contain 1–512 characters.")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_master_key()).encrypt(nonce, api_key.encode("utf-8"), user_id.encode("utf-8"))
    review_store.init_db()
    with review_store._connect() as conn:
        conn.execute(
            "INSERT INTO user_api_keys(user_id, nonce, ciphertext, updated_at) "
            "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now')) "
            "ON CONFLICT(user_id) DO UPDATE SET nonce=excluded.nonce, "
            "ciphertext=excluded.ciphertext, updated_at=excluded.updated_at",
            (user_id, nonce, ciphertext),
        )


def get_user_api_key(user_id: str) -> str | None:
    review_store.init_db()
    with review_store._connect() as conn:
        row = conn.execute(
            "SELECT nonce, ciphertext FROM user_api_keys WHERE user_id=?", (user_id,)
        ).fetchone()
    if row is None:
        return None
    try:
        return AESGCM(_master_key()).decrypt(
            bytes(row["nonce"]), bytes(row["ciphertext"]), user_id.encode("utf-8")
        ).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError, ValueError):
        raise SecretStoreError("The saved API key could not be decrypted; verify the installation key.") from None


def has_user_api_key(user_id: str) -> bool:
    review_store.init_db()
    with review_store._connect() as conn:
        return conn.execute("SELECT 1 FROM user_api_keys WHERE user_id=?", (user_id,)).fetchone() is not None


def delete_user_api_key(user_id: str) -> bool:
    review_store.init_db()
    with review_store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute("DELETE FROM user_api_keys WHERE user_id=?", (user_id,))
        return cursor.rowcount > 0
