#!/usr/bin/env python3
"""Create private owner-token, encryption-key, and Compose settings for Mizan."""
from __future__ import annotations

import base64
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
MIN_TOKEN_BYTES = 32
PROJECT_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")


def _key_value(line: str) -> Optional[Tuple[str, str]]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    return key.strip(), value.strip().strip('"').strip("'")


def _write_private(path: Path, text: str) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=".mizan-env-", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _valid_encryption_key(value: str) -> bool:
    try:
        return len(base64.urlsafe_b64decode(value.encode("ascii"))) == 32
    except Exception:
        return False


def prepare_env(root: Path = ROOT) -> Optional[str]:
    """Create/harden .env; return a newly generated owner token only once.

    The encryption key is never printed. Once its version marker exists, a
    missing or malformed key is treated as a recovery problem, not silently
    replaced, because doing so would make stored user keys undecryptable.
    """
    root = Path(root)
    env_path = root / ".env"
    example_path = root / ".env.example"
    if env_path.is_symlink():
        raise ValueError("Refusing to write through a symlinked .env file.")

    env_existed = env_path.exists()
    if env_existed:
        text = env_path.read_text(encoding="utf-8")
    else:
        if not example_path.is_file():
            raise FileNotFoundError(".env.example is missing; cannot initialize local configuration.")
        text = example_path.read_text(encoding="utf-8")

    lines = text.splitlines()
    found = {"MIZAN_JUDGE_TOKEN": [], "MIZAN_ENCRYPTION_KEY": [],
             "MIZAN_ENCRYPTION_KEY_VERSION": [], "COMPOSE_PROJECT_NAME": []}
    for index, line in enumerate(lines):
        item = _key_value(line)
        if item and item[0] in found:
            found[item[0]].append((index, item[1]))
    for key, items in found.items():
        if len(items) > 1:
            raise ValueError(".env contains duplicate %s entries; remove the duplicates first." % key)

    token = None
    token_entry = found["MIZAN_JUDGE_TOKEN"]
    current_token = token_entry[0][1] if token_entry else ""
    if len(current_token.encode("utf-8")) < MIN_TOKEN_BYTES:
        token = secrets.token_urlsafe(32)
        entry = "MIZAN_JUDGE_TOKEN=" + token
        if token_entry:
            lines[token_entry[0][0]] = entry
        else:
            lines.append(entry)

    key_entry = found["MIZAN_ENCRYPTION_KEY"]
    version_entry = found["MIZAN_ENCRYPTION_KEY_VERSION"]
    current_key = key_entry[0][1] if key_entry else ""
    key_was_initialized = bool(version_entry and version_entry[0][1] == "1")
    if not _valid_encryption_key(current_key):
        if key_was_initialized:
            raise ValueError(
                "MIZAN_ENCRYPTION_KEY is missing or invalid, but the key was previously initialized. "
                "Restore the original key from a private backup; generating a replacement would make saved user keys unreadable."
            )
        generated_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        entry = "MIZAN_ENCRYPTION_KEY=" + generated_key
        if key_entry:
            lines[key_entry[0][0]] = entry
        else:
            lines.append(entry)
    if not version_entry:
        lines.append("MIZAN_ENCRYPTION_KEY_VERSION=1")
    elif version_entry[0][1] == "":
        lines[version_entry[0][0]] = "MIZAN_ENCRYPTION_KEY_VERSION=1"
    elif version_entry[0][1] != "1":
        raise ValueError("Unsupported MIZAN_ENCRYPTION_KEY_VERSION; restore a supported private configuration.")

    project_entry = found["COMPOSE_PROJECT_NAME"]
    if project_entry:
        if not PROJECT_NAME_PATTERN.fullmatch(project_entry[0][1]):
            raise ValueError("COMPOSE_PROJECT_NAME must use lowercase letters, digits, '_' or '-'.")
    else:
        lines.append("COMPOSE_PROJECT_NAME=mizan-" + secrets.token_hex(8))

    updated_text = "\n".join(lines).rstrip("\n") + "\n"
    if token is not None or not env_existed or updated_text != text:
        _write_private(env_path, updated_text)
    else:
        os.chmod(env_path, 0o600)
    return token


def main() -> None:
    try:
        token = prepare_env()
    except (OSError, ValueError) as error:
        print("Could not prepare local configuration: %s" % error, file=sys.stderr)
        raise SystemExit(2)

    if token:
        print("Created a private Mizan installation-owner token. Copy it now; it will not be printed again:")
        print(token)
    else:
        print("A valid-length installation-owner token already exists in .env; it was preserved and not displayed.")
    print("A 256-bit key for encrypting researchers' Meta API keys is stored privately in .env and is never printed.")
    print("Next: docker compose up --build")


if __name__ == "__main__":
    main()
