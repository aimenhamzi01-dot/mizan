"""Tiny client for the Meta Model API (OpenAI-compatible chat completions).

Standard library only, so the project runs without `pip install`.
"""
import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE = "https://api.meta.ai/v1"
DEFAULT_MODELS = "muse-spark-1.3,muse-spark-1.1"
MAX_RESPONSE_BYTES = 1_000_000


class MetaAPIError(Exception):
    def __init__(self, message, status=500):
        super().__init__(message)
        self.status = status


def get_config():
    key = (
        os.environ.get("MODEL_API_KEY")
        or os.environ.get("META_API_KEY")
        or os.environ.get("META_MODEL_API_KEY")
    )
    base = os.environ.get("META_API_BASE", DEFAULT_BASE).rstrip("/")
    models = [m.strip() for m in os.environ.get("META_MODEL", DEFAULT_MODELS).split(",") if m.strip()]
    return key, base, models


def has_key():
    return bool(get_config()[0])


def _content_to_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def chat(messages, *, max_tokens=3000, temperature=0.2, timeout=120):
    """Send a chat completion. Tries each model in META_MODEL until one is accepted."""
    key, base, models = get_config()
    if not key:
        raise MetaAPIError("MODEL_API_KEY is not set. Add it to your .env file.", 401)

    last_error = None
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
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise MetaAPIError("Meta API response exceeded the configured size limit.", 502)
            data = json.loads(raw.decode("utf-8"))
            text = _content_to_text(data["choices"][0]["message"].get("content"))
            if not text.strip():
                raise MetaAPIError("The model returned an empty answer. Try again.", 502)
            return text
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode("utf-8", errors="replace")
            if e.code in (400, 404) and "model" in body.lower():
                continue  # model name not available for this key: try the next one
            raise MetaAPIError("Meta API returned HTTP status %d." % e.code, e.code)
        except urllib.error.URLError:
            raise MetaAPIError("Could not reach the configured Meta API endpoint.", 502)
        except (KeyError, IndexError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise MetaAPIError("Unexpected response format from the API.", 502)
    raise last_error or MetaAPIError("No model available.", 502)
