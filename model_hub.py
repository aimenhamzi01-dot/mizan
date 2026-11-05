"""MIZAN's Meta model registry and policy-gated adapter router.

Only the Muse Spark Chat Completions adapter is enabled by default. Muse Wonder
can be explicitly enabled as experimental after operator review. Other families
are represented in the registry but have no callable adapter until their exact
request/response contracts and deployment requirements are implemented.
"""
from __future__ import annotations

import os

import meta_client

REGISTRY_VERSION = "meta-hub-v1"
DEFAULT_MODEL_ID = "muse-spark-1.3"
TASK_SECURITY_TRIAGE = "security-triage"

# `model_id` is the provider's exact published API identifier when known.
# Checkpoint names are stored separately and never sent as hosted API model IDs.
_MODELS = [
    {
        "hub_id": "muse-spark-1.3", "family": "Muse Spark", "model_id": "muse-spark-1.3",
        "interface": "meta-hosted-api", "availability": "hosted-api-confirmed",
        "integration": "implemented", "adapter": "meta-chat-completions",
        "tasks": [TASK_SECURITY_TRIAGE], "modalities": ["text-in", "text-out"],
        "credential": "per-user Meta API key", "summary": "Default human-led report and code triage model.",
        "default": True,
    },
    {
        "hub_id": "muse-spark-1.2", "family": "Muse Spark", "model_id": "muse-spark-1.2",
        "interface": "meta-hosted-api", "availability": "hosted-api-confirmed",
        "integration": "implemented", "adapter": "meta-chat-completions",
        "tasks": [TASK_SECURITY_TRIAGE], "modalities": ["text-in", "text-out"],
        "credential": "per-user Meta API key", "summary": "Muse Spark version; selectable as an explicit model.",
        "default": False,
    },
    {
        "hub_id": "muse-spark-1.1", "family": "Muse Spark", "model_id": "muse-spark-1.1",
        "interface": "meta-hosted-api", "availability": "hosted-api-confirmed",
        "integration": "implemented", "adapter": "meta-chat-completions",
        "tasks": [TASK_SECURITY_TRIAGE], "modalities": ["text-in", "text-out"],
        "credential": "per-user Meta API key", "summary": "Muse Spark version; selectable as an explicit model.",
        "default": False,
    },
    {
        "hub_id": "muse-spark-1.3-contributor", "family": "Muse Spark", "model_id": "muse-spark-1.3-contributor",
        "interface": "meta-hosted-api", "availability": "hosted-api-confirmed",
        "integration": "pending-data-mode-review", "adapter": "meta-chat-completions",
        "tasks": [], "modalities": ["text-in", "text-out"], "credential": "per-user Meta API key",
        "summary": "Contributor data-use mode. Disabled pending explicit data-use disclosure and policy review.",
        "default": False,
    },
    {
        "hub_id": "muse-spark-1.2-contributor", "family": "Muse Spark", "model_id": "muse-spark-1.2-contributor",
        "interface": "meta-hosted-api", "availability": "hosted-api-confirmed",
        "integration": "pending-data-mode-review", "adapter": "meta-chat-completions",
        "tasks": [], "modalities": ["text-in", "text-out"], "credential": "per-user Meta API key",
        "summary": "Contributor data-use mode. Disabled pending explicit data-use disclosure and policy review.",
        "default": False,
    },
    {
        "hub_id": "muse-wonder-1.0", "family": "Muse Wonder", "model_id": "muse-wonder-1.0",
        "interface": "meta-hosted-api", "availability": "hosted-api-confirmed-preview",
        "integration": "experimental-opt-in", "adapter": "meta-chat-completions",
        "tasks": [TASK_SECURITY_TRIAGE], "modalities": ["text-image-video-audio-pdf-in", "text-out"],
        "credential": "per-user Meta API key", "summary": "Experimental hosted text model. Requires operator allowlisting and account access; no fallback to another model.",
        "default": False,
    },
    {
        "hub_id": "muse-wonder-full", "family": "Muse Wonder Full", "model_id": None,
        "interface": "meta-hosted-api-unverified", "availability": "hosted-api-not-confirmed",
        "integration": "pending-identifier", "adapter": "pending",
        "tasks": [], "modalities": ["text-image-video-audio-pdf-in", "text-out"],
        "credential": "not applicable until an official callable identifier is verified",
        "summary": "No official hosted API model identifier verified; not callable.", "default": False,
    },
    {
        "hub_id": "muse-image-1.0", "family": "Muse Image", "model_id": "muse-image-1.0",
        "interface": "meta-hosted-image-api", "availability": "hosted-api-confirmed",
        "integration": "pending-adapter-contract", "adapter": "pending-meta-image",
        "tasks": ["illustrative-image-generation"], "modalities": ["text-image-in", "image-out"],
        "credential": "per-user Meta API key", "summary": "Image-generation/editing interface documented; MIZAN image request/response handling is not enabled yet.",
        "default": False,
    },
    {
        "hub_id": "muse-voice-transcribe-1.0", "family": "Muse Voice Transcribe", "model_id": "muse-voice-transcribe-1.0",
        "interface": "meta-hosted-asr-api", "availability": "hosted-api-confirmed",
        "integration": "pending-adapter-contract", "adapter": "pending-meta-asr",
        "tasks": ["audio-case-intake"], "modalities": ["audio-in", "text-out"],
        "credential": "per-user Meta API key", "summary": "Hosted transcription model; MIZAN has no audio upload, consent, retention, or transcription workflow yet.",
        "default": False,
    },
    {
        "hub_id": "sam-3.1", "family": "SAM 3.1 / Object Multiplex", "model_id": None,
        "checkpoint_id": "facebook/sam3.1", "interface": "local-checkpoint",
        "availability": "gated-downloadable-weights", "integration": "pending-local-runtime",
        "adapter": "pending-local-vision", "tasks": ["visual-evidence-segmentation"],
        "modalities": ["image-video-in", "masks-boxes-scores-out"],
        "credential": "gated checkpoint access and local GPU runtime",
        "summary": "Local checkpoint only; no hosted SAM 3.1 API identifier/endpoint verified.", "default": False,
    },
    {
        "hub_id": "muse-glimmer-30b", "family": "Muse Glimmer", "model_id": None,
        "checkpoint_id": "meta-models/Muse-Glimmer-30B", "interface": "self-hosted-checkpoint",
        "availability": "downloadable-open-weights", "integration": "pending-local-runtime",
        "adapter": "pending-local-multimodal", "tasks": ["local-triage-evaluation"],
        "modalities": ["text-image-in", "text-out"], "credential": "operator-managed local runtime",
        "summary": "Self-hosted checkpoint; no Meta-operated hosted inference API verified.", "default": False,
    },
    {
        "hub_id": "muse-spark-open", "family": "Muse Spark Open", "model_id": None,
        "checkpoint_id": "meta-models/Muse-Spark-Open-816B-A42B", "interface": "self-hosted-checkpoint",
        "availability": "downloadable-open-weights", "integration": "pending-local-runtime",
        "adapter": "pending-local-multimodal", "tasks": ["local-triage-evaluation"],
        "modalities": ["text-image-video-audio-in", "text-out"], "credential": "operator-managed high-capacity runtime",
        "summary": "Open weights, separate license and substantial serving requirements; not a hosted Model API ID.", "default": False,
    },
    {
        "hub_id": "llama-open-weight", "family": "Llama and other Meta open-weight LLMs", "model_id": None,
        "interface": "self-hosted-or-third-party-provider", "availability": "downloadable-versioned-weights",
        "integration": "pending-local-runtime", "adapter": "pending-local-text",
        "tasks": ["local-triage-evaluation"], "modalities": ["text-image-in-version-dependent", "text-out"],
        "credential": "version-specific license/access and operator-managed runtime",
        "summary": "Llama 3.x/4 families have version-specific weights and terms; no Meta-hosted Llama API ID verified.",
        "default": False,
    },
]

_BY_ID = {item["hub_id"]: item for item in _MODELS}


class ModelHubError(ValueError):
    """A model is unknown, disabled, or does not support the requested task."""


class MetaChatAdapter:
    """Adapter for a registry-approved Meta Chat Completions model ID."""

    adapter_id = "meta-chat-completions"

    def invoke(self, model_id, messages, **kwargs):
        # A single candidate prevents silent fallback to a different model/family.
        return meta_client.chat(messages, model_candidates=[model_id], **kwargs)


class PendingAdapter:
    """Explicit non-callable adapter placeholder for unimplemented interfaces."""

    def __init__(self, adapter_id):
        self.adapter_id = adapter_id

    def invoke(self, *args, **kwargs):
        raise ModelHubError("This model adapter is pending configuration and is not callable.")


_ADAPTERS = {
    "meta-chat-completions": MetaChatAdapter(),
    "pending": PendingAdapter("pending"),
    "pending-meta-image": PendingAdapter("pending-meta-image"),
    "pending-meta-asr": PendingAdapter("pending-meta-asr"),
    "pending-local-vision": PendingAdapter("pending-local-vision"),
    "pending-local-multimodal": PendingAdapter("pending-local-multimodal"),
    "pending-local-text": PendingAdapter("pending-local-text"),
}


def _csv(name):
    return [part.strip() for part in os.environ.get(name, "").split(",") if part.strip()]


def enabled_model_ids():
    """Return only implemented standard-mode models, plus explicitly opted-in Wonder."""
    configured = _csv("META_MODEL") or meta_client.DEFAULT_MODELS.split(",")
    explicit = set(_csv("MIZAN_ENABLED_MODELS"))
    enabled = []
    for model_id in configured + list(explicit):
        item = _BY_ID.get(model_id)
        if not item or item["adapter"] != "meta-chat-completions":
            continue
        if item["integration"] == "experimental-opt-in" and model_id not in explicit:
            continue
        if item["integration"] != "implemented" and item["integration"] != "experimental-opt-in":
            continue
        if model_id not in enabled:
            enabled.append(model_id)
    return enabled


def enabled_spark_candidates(candidates):
    """Keep only explicitly enabled, implemented Muse Spark chat models."""
    enabled = set(enabled_model_ids())
    result, seen = [], set()
    for model_id in candidates or []:
        if not isinstance(model_id, str):
            continue
        model_id = model_id.strip()
        item = _BY_ID.get(model_id)
        if (
            not model_id
            or model_id not in enabled
            or model_id in seen
            or item is None
            or item["family"] != "Muse Spark"
            or item["integration"] != "implemented"
            or item["adapter"] != "meta-chat-completions"
            or TASK_SECURITY_TRIAGE not in item["tasks"]
        ):
            continue
        result.append(model_id)
        seen.add(model_id)
    return result


def legacy_spark_candidates():
    """Preserve the legacy Spark fallback order without bypassing hub policy."""
    configured = _csv("META_MODEL") or meta_client.DEFAULT_MODELS.split(",")
    candidates = enabled_spark_candidates(configured)
    if not candidates:
        raise ModelHubError("No enabled, implemented Muse Spark model is configured for this request.")
    return candidates


def default_model_id():
    enabled = enabled_model_ids()
    if DEFAULT_MODEL_ID in enabled:
        return DEFAULT_MODEL_ID
    return enabled[0] if enabled else DEFAULT_MODEL_ID


def resolve_model(model_id=None, task=TASK_SECURITY_TRIAGE):
    """Validate a request against the registry and task allowlist before egress."""
    selected = model_id or default_model_id()
    item = _BY_ID.get(selected)
    if item is None:
        raise ModelHubError("Unknown MIZAN model identifier.")
    if item["adapter"] != "meta-chat-completions":
        raise ModelHubError(item["summary"])
    if selected not in enabled_model_ids():
        raise ModelHubError("This model is not enabled by the installation operator.")
    if task not in item["tasks"]:
        raise ModelHubError("This model is not approved for the requested MIZAN task.")
    return dict(item)


def adapter_for(model):
    return _ADAPTERS[model["adapter"]]


def route_chat(model_id, task, messages, **kwargs):
    model = resolve_model(model_id, task)
    return adapter_for(model).invoke(model["model_id"], messages, **kwargs), model


def public_registry(has_meta_key=False):
    """Return safe, key-free model metadata for the authenticated UI/API."""
    enabled = set(enabled_model_ids())
    default = default_model_id()
    rows = []
    for model in _MODELS:
        row = dict(model)
        row["enabled"] = row["hub_id"] in enabled
        row["selectable"] = row["enabled"] and bool(row["tasks"])
        row["default"] = row["hub_id"] == default
        row["credential_configured"] = bool(has_meta_key) if row["credential"] == "per-user Meta API key" else False
        row["price_estimate"] = None
        rows.append(row)
    return {
        "registry_version": REGISTRY_VERSION,
        "default_model": default,
        "models": rows,
        "local_runtime": {
            "configured": bool(os.environ.get("MIZAN_LOCAL_MODEL_BASE", "").strip() and os.environ.get("MIZAN_LOCAL_MODEL_ID", "").strip()),
            "credentials_configured": bool(os.environ.get("MIZAN_LOCAL_MODEL_API_KEY", "").strip()),
            "adapter_active": False,
            "note": "Local endpoint settings are reported only; no local model request is made until a reviewed adapter is implemented.",
        },
        "usage_tracking": "Provider token counts are recorded when returned. Dollar cost is not estimated because a verified current price is not configured.",
        "comparison": "Multi-model comparison is not automatic; each outbound analysis remains a separate explicitly confirmed request.",
    }
