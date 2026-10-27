# Contributing to Mizan

Thanks for helping improve Mizan. Keep changes focused, tested offline, and consistent with the project's read-only scope.

## Development setup

- Use Python 3.9 or newer.
- No third-party Python dependencies are required.
- Keep `.env`, SQLite databases, report text, source snippets, API keys, and user-provided vulnerability reports out of commits.
- Run `python -m unittest discover -s tests -v` before opening a change.

## Required safety invariants

- Never execute, import, simulate, or dynamically inspect submitted source code or proof-of-concept steps.
- Never contact a vulnerability target or create target-validation features.
- Keep untrusted report/code content separate from system instructions; add adversarial tests for delimiters, placeholders, and prompt-like text.
- Preserve output normalization and the existing hard guardrails: contradicted code cannot be accepted, and scanner-dump cannot be accepted.
- Keep model analysis advisory. A final disposition requires an explicit human action and is stored separately from the model suggestion.
- Do not add automatic ticket closure, disclosure, reporter messaging, or target access.
- Keep credentials in environment configuration; never return secrets or provider error bodies to the browser/logs.
- Preserve loopback-only deployment unless a separate authenticated and reviewed network deployment design is approved.

## Pull requests

Describe the behavior change, its data flow, and any privacy implications. Add offline unit and integration tests. For any change to system prompts, triage boundaries, decision rules, external egress, persistence, or deletion, explain the reason and include regression coverage before merging.
