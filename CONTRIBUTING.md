# Contributing to Mizan

Thanks for helping improve Mizan. Keep changes focused, tested offline, and consistent with the project's read-only scope.

## Development setup

- Use Python 3.9 or newer; no third-party Python packages are required for the app or tests.
- Docker Engine and Docker Compose v2 are optional for local container testing.
- Keep `.env`, SQLite databases, report text, source snippets, API keys, and user-provided vulnerability reports out of commits.
- Run `python -m unittest discover -s tests -v` before opening a change.
- If Docker is available, also run `docker compose config` with a test-only token, build the image, and smoke-test `/healthz` and authenticated `/api/health`.

## Required safety invariants

- Never execute, import, simulate, or dynamically inspect submitted source code or proof-of-concept steps.
- Never contact a vulnerability target or create target-validation features.
- Keep untrusted report/code content separate from system instructions; add adversarial tests for delimiters, placeholders, and prompt-like text.
- Preserve output normalization and the existing hard guardrails: contradicted code cannot be accepted, and scanner-dump cannot be accepted.
- Keep model analysis advisory. A final disposition requires an explicit human action and is stored separately from the model suggestion.
- Do not add automatic ticket closure, disclosure, reporter messaging, or target access.
- Keep credentials in private environment configuration; never return secrets or provider error bodies to the browser/logs.
- Keep `MIZAN_JUDGE_TOKEN` fail-closed, require at least 32 bytes, compare credentials in constant time, and never log or persist the browser token.
- Preserve per-researcher self-hosting and loopback-only Docker port publication. The per-install token is not multi-user authorization. A central public service needs a separate security/privacy design and review.

## Pull requests

Describe the behavior change, its data flow, and any privacy implications. Add offline unit and integration tests. For any change to system prompts, triage boundaries, decision rules, external egress, persistence, deletion, container privileges, or network binding, explain the reason and include regression coverage before merging.
