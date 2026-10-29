"""Local workspace identities and revocable personal API tokens for Mizan.

Tokens are generated with high entropy and only SHA-256 digests are stored.
The installation owner token remains in the private environment file; all
other users receive individual tokens that can be revoked independently.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import datetime, timezone

import review_store

ROLES = {"admin", "analyst", "reviewer", "viewer"}
USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{1,63}\Z")
MAX_WORKSPACE_NAME = 80


class AuthStoreError(Exception):
    """Base class for identity and workspace errors."""


class DuplicateUser(AuthStoreError):
    pass


class WorkspaceNotFound(AuthStoreError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_workspace(name: str, *, created_by: str = "installation-owner") -> dict:
    name = name.strip() if isinstance(name, str) else ""
    if not name or len(name) > MAX_WORKSPACE_NAME:
        raise ValueError("Workspace name must contain 1–80 characters.")
    workspace_id = str(uuid.uuid4())
    review_store.init_db()
    with review_store._connect() as conn:
        conn.execute(
            "INSERT INTO workspaces(id, name, created_at, created_by) VALUES (?, ?, ?, ?)",
            (workspace_id, name, _now(), created_by[:120]),
        )
    return {"id": workspace_id, "name": name}


def list_workspaces(workspace_id: str | None = None) -> list:
    review_store.init_db()
    with review_store._connect() as conn:
        if workspace_id is None:
            rows = conn.execute("SELECT id, name, created_at FROM workspaces ORDER BY name, id").fetchall()
        else:
            rows = conn.execute(
                "SELECT id, name, created_at FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchall()
    return [dict(row) for row in rows]


def create_user(username: str, role: str, workspace_id: str, *, created_by: str) -> tuple[dict, str]:
    username = username.strip() if isinstance(username, str) else ""
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 2–64 characters using letters, digits, '.', '_', '@' or '-'.")
    if not isinstance(role, str) or role not in ROLES:
        raise ValueError("Role must be one of: admin, analyst, reviewer, viewer.")
    if not isinstance(workspace_id, str) or not workspace_id:
        raise ValueError("A workspace is required.")

    user_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    review_store.init_db()
    with review_store._connect() as conn:
        exists = conn.execute("SELECT 1 FROM workspaces WHERE id = ?", (workspace_id,)).fetchone()
        if exists is None:
            raise WorkspaceNotFound("Workspace not found.")
        try:
            conn.execute(
                "INSERT INTO users(id, username, token_hash, role, workspace_id, active, created_at, created_by) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (user_id, username, _digest(token), role, workspace_id, _now(), created_by[:120]),
            )
        except Exception as exc:
            if "UNIQUE constraint failed: users.username" in str(exc):
                raise DuplicateUser("Username already exists.") from None
            raise
    return ({"id": user_id, "username": username, "role": role, "workspace_id": workspace_id}, token)


def authenticate_token(token: str) -> dict | None:
    if not isinstance(token, str) or not token or len(token) > 512:
        return None
    review_store.init_db()
    with review_store._connect() as conn:
        row = conn.execute(
            "SELECT id, username, role, workspace_id, active FROM users WHERE token_hash = ?",
            (_digest(token),),
        ).fetchone()
    if row is None or not row["active"]:
        return None
    return {
        "id": row["id"], "username": row["username"], "role": row["role"],
        "workspace_id": row["workspace_id"], "is_root": False,
    }


def list_users(workspace_id: str | None = None) -> list:
    review_store.init_db()
    with review_store._connect() as conn:
        if workspace_id is None:
            rows = conn.execute(
                "SELECT id, username, role, workspace_id, active, created_at "
                "FROM users ORDER BY created_at, username"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username, role, workspace_id, active, created_at "
                "FROM users WHERE workspace_id = ? ORDER BY created_at, username",
                (workspace_id,),
            ).fetchall()
    return [dict(row) for row in rows]


def revoke_user(user_id: str, *, workspace_id: str | None = None) -> bool:
    review_store.init_db()
    with review_store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if workspace_id is None:
            cursor = conn.execute("UPDATE users SET active=0 WHERE id=? AND active=1", (user_id,))
        else:
            cursor = conn.execute(
                "UPDATE users SET active=0 WHERE id=? AND workspace_id=? AND active=1",
                (user_id, workspace_id),
            )
        if cursor.rowcount:
            conn.execute("DELETE FROM user_api_keys WHERE user_id=?", (user_id,))
        return cursor.rowcount > 0


def rotate_user_token(user_id: str, *, workspace_id: str | None = None) -> str | None:
    """Replace an active user's token; return the new token once, or None."""
    token = secrets.token_urlsafe(32)
    review_store.init_db()
    with review_store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if workspace_id is None:
            cursor = conn.execute(
                "UPDATE users SET token_hash=? WHERE id=? AND active=1", (_digest(token), user_id)
            )
        else:
            cursor = conn.execute(
                "UPDATE users SET token_hash=? WHERE id=? AND workspace_id=? AND active=1",
                (_digest(token), user_id, workspace_id),
            )
        return token if cursor.rowcount else None


def get_user(user_id: str) -> dict | None:
    review_store.init_db()
    with review_store._connect() as conn:
        row = conn.execute(
            "SELECT id, username, role, workspace_id, active, created_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None
