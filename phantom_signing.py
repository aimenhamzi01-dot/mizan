"""Signing helpers for the Mizan -> Phantom task handoff."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

SIGNATURE_ALGORITHM = "HMAC-SHA256"


def _key() -> bytes:
    value = os.getenv("MIZAN_PHANTOM_SIGNING_KEY", "").strip()
    if len(value) < 32:
        raise RuntimeError("MIZAN_PHANTOM_SIGNING_KEY must be at least 32 characters.")
    return value.encode("utf-8")


def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k not in {"signature", "signature_algorithm"}}
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sign_manifest(manifest: dict[str, Any]) -> str:
    return hmac.new(_key(), canonical_manifest(manifest), hashlib.sha256).hexdigest()


def attach_signature(manifest: dict[str, Any]) -> dict[str, Any]:
    signed = dict(manifest)
    signed["signature_algorithm"] = SIGNATURE_ALGORITHM
    signed["signature"] = sign_manifest(signed)
    return signed


def verify_manifest_signature(manifest: dict[str, Any]) -> bool:
    signature = manifest.get("signature")
    if not isinstance(signature, str) or len(signature) != 64:
        return False
    try:
        expected = sign_manifest(manifest)
    except RuntimeError:
        return False
    return hmac.compare_digest(signature, expected)
