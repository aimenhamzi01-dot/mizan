# Contributing to Mizan

Thanks for helping improve Mizan. Keep changes focused, tested offline, and consistent with the project's read-only scope.

## Development setup

- Use Python 3.9 or newer and install `requirements.txt` (`cryptography` is used for AES-GCM key storage).
- Docker Engine and Docker Compose v2 are optional for local container validation.
- Keep `.env`, SQLite databases, report text, source snippets, API keys, user tokens, and user-provided vulnerability reports out of commits.
- Run `python -m unittest discover -s tests -v` before opening a change.
- If Docker is available, validate `docker compose config` with test-only values, build the image, and smoke-test `/healthz` and authenticated `/api/health`.

## Required safety invariants

- Never execute, import, simulate, or dynamically inspect submitted source code or proof-of-concept steps.
- Never contact a vulnerability target or add target-validation features.
- Keep report/code separate from system instructions; add adversarial tests for delimiters, placeholders, and prompt-like text.
- Preserve output normalization and the hard acceptance guardrails: contradicted code cannot be accepted, and scanner-dump cannot be accepted.
- Keep model analysis advisory. A final disposition requires an explicit authenticated human action and remains separate from model suggestion.
- Do not add automatic ticket closure, disclosure, reporter messaging, or target access.
- Keep credentials out of API responses and logs. The installation encryption key must never be printed or silently regenerated after initialization.
- Preserve constant-time owner-token validation and store only digests of individual user tokens. Test creation, revocation, rotation, and fail-closed behavior.
- Enforce role checks and workspace scope on every read and write; add cross-workspace regression tests for details, history, lists, metrics, analysis, review, and deletion.
- Preserve per-user provider-key separation: a non-owner must never inherit the installation-owner fallback key. Test AES-GCM storage, associated-data binding, and removal on revocation.
- Keep Docker bound to loopback by default. Document additional proxy configuration and test Host/Origin allow-lists; never expose the app directly to an untrusted network.

## Pull requests

Describe the behavior change, data flow, threat boundary, and privacy implications. Add offline unit and integration tests. For any change to authentication, authorization, prompts, egress, persistence, key rotation, deletion, container privileges, or network binding, explain the reason and include regression coverage before merging.
