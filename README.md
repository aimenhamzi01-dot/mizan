# Mizan — Security Triage Workbench

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)

**Mizan is a local, human-led workbench for reviewing vulnerability reports.** It stores report text and optional source snippets, can request an AI recommendation from the configured Meta Model API, and records an explicit reviewer disposition separately from that recommendation. It is designed to help organize evidence—not to verify a live target or replace a security reviewer.

Built for the **Meta Global AI Developer Hackathon 2026**, Indie Developer Track, under **Build for Your World**.

## What it does

- Accepts a vulnerability report and optional pasted source snippet as text.
- Stores a case in a local SQLite database without making a model call.
- On a separate, explicit reviewer action, sends the selected report and snippet to the configured Meta Model API and stores its structured recommendation.
- Presents evidence, code-verification status, severity reasoning, recommendation, and draft response for review.
- Records a human decision (`accept`, `need-info`, `duplicate`, or `reject`) and reviewer note as a separate event; it never auto-applies the model's recommendation.
- Provides a searchable local queue, case metrics, event history, and deletion controls.
- Includes synthetic built-in examples for prompt injection, code-supported claims, and scanner noise. They work without an API key.
- Supports English and Arabic analysis language selection. The workbench interface is English.

## Safety and data-flow boundaries

- **Read-only source review:** Mizan never imports or executes submitted code, commands, exploits, or reproduction steps. It does not send requests, probes, DNS lookups, or other traffic to a reported target.
- **Explicit model egress:** Saving a case is local-only. Selecting **Analyze with Meta** requires a confirmation and sends that case's report and source snippet to the configured Meta Model API. Do not submit sensitive material unless you are authorized to share it with that service. Built-in demo results are canned and do not call the model.
- **Human decision:** A model suggestion is not a final disposition. Recording a human review is a separate, explicit operation. Mizan does not close a program ticket, send a report, or deliver a draft reply.
- **Prompt boundary:** Report and code are represented as JSON-quoted untrusted data in the user message, separate from the system message. One-pass interpolation and regression tests prevent embedded delimiters or template placeholders from changing that boundary.
- **Hard acceptance guardrails:** The output normalizer changes an `accept` suggestion to `reject` when supplied code contradicts the claim, and to `need-info` for a `scanner-dump` report. The model may still be wrong; reviewers must inspect the evidence and surrounding context.
- **Local storage:** Case text is stored in `data/mizan.sqlite3` by default (or the path in `MIZAN_DB_PATH`). The default directory is private to the current user and the database file is permission-restricted. The SQLite contents are **not encrypted**. Cases remain until deleted; deletion removes the case and its application-level event history. Users remain responsible for database copies and backups.
- **Deployment limitation:** The server binds to `127.0.0.1` and checks local Host/Origin headers, but has no user authentication, per-user authorization, comprehensive CSRF defense, or production deployment hardening. Do not expose it to an untrusted network or use it as a multi-tenant production service.

Mizan is a prototype, not a replacement for source review, vulnerability validation, or a program's reporting policy. Its sample cases are synthetic and are not evidence of detection accuracy.

## Quick start

**Requirements:** Python 3.9 or newer. No third-party Python packages are required.

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python server.py
```

Open <http://127.0.0.1:8000>. The workbench and built-in examples run without an API key. You can save and review cases locally. To enable live model analysis, copy `.env.example` to `.env`, set `MODEL_API_KEY` to a key you are authorized to use, then restart the server:

```bash
cp .env.example .env
# Edit .env and set MODEL_API_KEY
python server.py
```

Never commit `.env` or put a real key in source files. `.env` and local SQLite files are ignored by Git; `.env.example` contains only a placeholder. To choose a different database path, set `MIZAN_DB_PATH` in `.env` or the process environment.

## Reviewer workflow

1. Paste a report and, optionally, a short source snippet. Source is treated as read-only text; only the report and snippet are saved.
2. Select **Save report locally**. This creates a case with `received` status and makes no model request.
3. Select the case. If you choose to run **Analyze with Meta**, confirm that its report and code will be sent to the configured model API. A case with no model key remains stored and can still be reviewed locally.
4. Inspect the recommendation and evidence. A report stays in `analyzed` status until a reviewer chooses a final disposition.
5. Choose a human decision and optionally enter a reviewer label and note. Mizan records the decision in the local audit history; it does not send it anywhere.
6. Delete a case if it should be removed from the local database. Deletion also removes the application's event history for that case.

Cases and event history are stored locally and are not encrypted. Do not put production-sensitive information into this prototype unless the storage and retention arrangement is appropriate for it.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `MODEL_API_KEY` | Meta Model API key; `META_API_KEY` and `META_MODEL_API_KEY` are also accepted | Unset |
| `META_API_BASE` | OpenAI-compatible Meta Model API base URL | `https://api.meta.ai/v1` |
| `META_MODEL` | Comma-separated model names tried in order | `muse-spark-1.3,muse-spark-1.1` |
| `META_REASONING_EFFORT` | Optional reasoning-effort value passed to the API | Unset |
| `MIZAN_DB_PATH` | Local SQLite database path | `data/mizan.sqlite3` |
| `PORT` | Local HTTP server port | `8000` |

Configuration comes from environment variables or a local `.env` file. The server still binds to loopback; changing `PORT` does not make it a network-ready deployment. The configured `META_API_BASE` receives the bearer key and case contents, so only use a trusted, authorized endpoint. Model availability depends on the API account and service configuration.

## Local API

All routes are served by `server.py` on loopback. The API is intended for the bundled local interface, not for public or multi-user access.

| Method and route | Behavior |
|---|---|
| `GET /api/health` | Health and a boolean indicating whether a model key is configured |
| `GET /api/metrics` | Aggregate case counts only; no report contents |
| `GET /api/sample?kind=injection\|valid\|noise&lang=en\|ar` | Bundled sample input |
| `GET /api/reports` | Bounded, searchable case summaries; supports `status`, `q`, `limit`, and `offset` |
| `POST /api/reports` | Save report/code locally; does not call the model |
| `GET /api/reports/{id}` | Read one local case |
| `POST /api/reports/{id}/analyze` | Request model analysis for the selected case and save a recommendation |
| `POST /api/reports/{id}/review` | Record an explicit human disposition and note |
| `GET /api/reports/{id}/history` | Read local case events |
| `DELETE /api/reports/{id}` | Delete a case and its application-level history |
| `POST /api/triage` | Stateless compatibility endpoint; supports canned demo results or live triage |

The server validates local Host/Origin values and rejects non-object JSON, invalid content types, oversized request bodies, invalid decisions, and invalid workflow transitions. Live model routes require `confirm_egress: true`, in addition to the interface confirmation. Public API error messages are sanitized; routine logs omit report and code text.

## Tests and CI

Run all tests offline:

```bash
python -m unittest discover -s tests -v
```

The suite covers output normalization and hard guardrails, report/code isolation and delimiter-spoofing, SQLite storage and deletion, the human-review workflow, bounded API behavior, safe error handling, local-only UI assets, and existing demo behavior. Model calls are mocked in tests; CI requires no API key and makes no live model or target requests. GitHub Actions runs the suite on pushes and pull requests.

## Repository map

| Path | Purpose |
|---|---|
| `server.py` | Loopback HTTP server and case/review API |
| `review_store.py` | Local SQLite persistence, event history, metrics, and deletion |
| `meta_client.py` | Configured Meta Model API client |
| `prompts.py` | System and user message templates |
| `triage.py` | Triage flow, safe input interpolation, normalization, and acceptance guardrails |
| `demo_data.py` | English and Arabic canned demonstrations |
| `static/index.html` | Local human-review workbench UI |
| `tests/test_all.py` | Core triage, normalization, and legacy API tests |
| `tests/test_meta_client.py` | Mocked Meta client request, fallback, size-limit, and error-redaction tests |
| `tests/test_review_store.py` | SQLite store tests |
| `tests/test_workbench_api.py` | Local API integration tests using mocked model calls |
| `SECURITY.md` | Security boundaries and deployment limitations |
| `docs/ARCHITECTURE.md` | Components, trust boundaries, data flow, and case state machine |
| `docs/API.md` | Local API routes and example payloads |
| `docs/EVALUATION.md` | Safe model-evaluation protocol and honest performance limitations |
| `docs/OPERATIONS.md` | Local configuration, SQLite backup/restore, and troubleshooting |
| `CONTRIBUTING.md` | Development workflow and required safety invariants |
| `.github/workflows/tests.yml` | Offline GitHub Actions test workflow |

## License

This project is distributed under the [MIT License](LICENSE).
