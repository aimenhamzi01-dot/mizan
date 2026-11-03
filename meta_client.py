"""Tiny standard-library client for the Meta Model API (OpenAI-compatible chat completions).

The application separately depends on `cryptography` for local API-key storage.
"""
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

DEFAULT_BASE = "https://api.meta.ai/v1"
DEFAULT_MODELS = "muse-spark-1.3,muse-spark-1.1"
MAX_RESPONSE_BYTES = 1_000_000
_ALLOWED_USAGE_KEYS = {"prompt_tokens", "completion_tokens", "total_tokens"}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class MetaAPIError(Exception):
    def __init__(self, message, status=500):
        super().__init__(message)
        self.status = status


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward provider credentials or case data to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_request(request, timeout):
    opener = urllib.request.build_opener(_NoRedirectHandler)
    return opener.open(request, timeout=timeout)


def _is_loopback_host(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_base(base):
    """Require HTTPS for remote endpoints; allow cleartext HTTP only on loopback."""
    try:
        parts = urlsplit(base)
        hostname = parts.hostname
        # Accessing .port validates malformed or out-of-range port values.
        _ = parts.port
    except ValueError:
        raise MetaAPIError("The configured Meta API endpoint is invalid.", 400)

    if (
        not parts.netloc
        or not hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise MetaAPIError("The configured Meta API endpoint is invalid.", 400)

    if parts.scheme == "https":
        return
    if parts.scheme == "http" and _is_loopback_host(hostname):
        return
    raise MetaAPIError(
        "Remote Meta API endpoints must use HTTPS; plain HTTP is allowed only for local development.",
        400,
    )


def get_config():
    key = (
        os.environ.get("MODEL_API_KEY")
        or os.environ.get("META_API_KEY")
        or os.environ.get("META_MODEL_API_KEY")
    )
    base = os.environ.get("META_API_BASE", DEFAULT_BASE).strip().rstrip("/")
    models = [m.strip() for m in os.environ.get("META_MODEL", DEFAULT_MODELS).split(",") if m.strip()]
    return key, base, models


def has_key(api_key=None):
    """Report whether an explicit user key or legacy installation key exists."""
    return bool(api_key or get_config()[0])


def _content_to_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def _safe_usage(value):
    if not isinstance(value, dict):
        return {}
    return {
        key: value[key]
        for key in _ALLOWED_USAGE_KEYS
        if type(value.get(key)) is int and 0 <= value[key] <= 100_000_000
    }


def chat(messages, *, api_key=None, max_tokens=3000, temperature=0.2, timeout=120,
         return_metadata=False):
    """Send a chat completion; optionally include response model and token usage."""
    configured_key, base, models = get_config()
    key = api_key or configured_key
    if not key:
        raise MetaAPIError("MODEL_API_KEY is not set. Add it to your .env file.", 401)
    _validate_base(base)

    for model in models:
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        effort = os.environ.get("META_REASONING_EFFORT")
        if effort:
            payload["reasoning_effort"] = effort

        req = urllib.request.Request(
            base + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
            method="POST",
        )
        try:
            with _open_request(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise MetaAPIError("Meta API response exceeded the configured size limit.", 502)
            data = json.loads(raw.decode("utf-8"))
            text = _content_to_text(data["choices"][0]["message"].get("content"))
            if not text.strip():
                raise MetaAPIError("The model returned an empty answer. Try again.", 502)
            if not return_metadata:
                return text
            response_model = data.get("model")
            if not isinstance(response_model, str) or not response_model.strip():
                response_model = model
            return {
                "content": text,
                "model": response_model[:120],
                "usage": _safe_usage(data.get("usage")),
            }
        except urllib.error.HTTPError as e:
            if e.code in _REDIRECT_STATUSES:
                raise MetaAPIError(
                    "The configured Meta API endpoint redirected the request. Configure the final trusted HTTPS endpoint directly.",
                    502,
                )
            try:
                body = e.read(4096).decode("utf-8", errors="replace")
            except (TimeoutError, socket.timeout):
                raise MetaAPIError("The Meta API request timed out; provider usage may be uncertain.", 504)
            if e.code in (400, 404) and "model" in body.lower():
                continue  # model name not available for this key: try the next one
            raise MetaAPIError("Meta API returned HTTP status %d." % e.code, e.code)
        except (TimeoutError, socket.timeout):
            raise MetaAPIError("The Meta API request timed out; provider usage may be uncertain.", 504)
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise MetaAPIError("The Meta API request timed out; provider usage may be uncertain.", 504)
            raise MetaAPIError("Could not reach the configured Meta API endpoint.", 502)
        except (KeyError, IndexError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise MetaAPIError("Unexpected response format from the API.", 502)
    raise MetaAPIError("No model available.", 502)
