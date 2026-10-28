# Mizan — Security Triage Workbench

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)

**Mizan is a self-hosted, human-led workbench for triaging vulnerability reports.** Each researcher runs a private local instance, configures their own Meta API key, and pays for their own model usage. There is no central Mizan service, shared provider key, or shared report database.

Built for the **Meta Global AI Developer Hackathon 2026**, Indie Developer Track, under **Build for Your World**.

## What it does

- Accepts a vulnerability report and optional pasted source snippet as text.
- Stores a case locally without making a model call.
- On a separate, explicit reviewer action, sends the selected report and snippet to the researcher's configured Meta Model API and stores its structured recommendation.
- Presents evidence, code-verification status, severity reasoning, recommendation, and a draft response for review.
- Records a human decision (`accept`, `need-info`, `duplicate`, or `reject`) separately from the model recommendation.
- Provides a searchable local queue, case metrics, event history, and deletion controls.
- Includes synthetic examples for prompt injection, code-supported claims, and scanner noise.
- Supports English and Arabic report-analysis language selection. The workbench interface is English.

## Run your own instance with Docker

**Requirements:** Docker Engine and Docker Compose v2. No Python packages or external database are needed.

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python3 scripts/run.py
# Copy the one-time token printed when this installation is first initialized.
```

Open <http://127.0.0.1:8000> and enter the generated local token. Docker publishes the service on loopback only; it is not exposed to the public network. The SQLite database is persisted in a project-scoped `mizan-data` Docker volume; each installation gets its own Compose project name. `docker compose down` stops the app and preserves data; do not use `docker compose down -v` unless you intend to remove the database volume.

To enable live analysis, edit the private `.env` file and set `MODEL_API_KEY` to **your own** authorized Meta API key, then restart the container. You pay Meta's usage charges associated with that key. Mizan does not receive or pay for a centrally shared model account. The key is supplied to the local process and is not stored in the case database.

```bash
docker compose up -d --build
```

To stop a background instance, run `docker compose down`. Keep `.env` private; it contains your local judge token and, if configured, your Meta key. It is ignored by Git.

## Run directly with Python

Python 3.9 or newer is required; no third-party Python packages are needed.

```bash
python3 scripts/bootstrap.py
python3 server.py
```

Open <http://127.0.0.1:8000>. The bootstrap script creates a strong per-install `MIZAN_JUDGE_TOKEN` in `.env` with owner-only permissions on POSIX systems and prints it only when first created. The server defaults to `127.0.0.1`; do not bind it to an untrusted network. Set `MODEL_API_KEY` in `.env` to enable live model analysis.

## Safety and data boundaries

- **Read-only source review:** Mizan never imports or executes submitted code, commands, exploits, or reproduction steps. It does not send requests, probes, DNS lookups, or other traffic to a reported target.
- **Explicit model egress:** Saving a case is local-only. Selecting **Analyze with Meta** requires confirmation and sends that case's report and source snippet to the configured Meta Model API. Do not submit material unless you are authorized to share it with that service. Built-in examples are synthetic.
- **Researcher-owned key and cost:** Each researcher configures their own Meta key in their own private instance and pays their own provider usage. Never put a real key in this public repository or in report text.
- **Local data ownership:** Cases and event history stay in the researcher's local SQLite database or Docker volume. The database is plaintext, not encrypted, and remains until deleted. Protect the host, backups, and `.env` file.
- **Local access token:** `MIZAN_JUDGE_TOKEN` is generated per installation and protects that instance's API. It is not a public account system. Do not expose the local server to other users or share an instance/token with untrusted parties.
- **Human decision:** A model suggestion is not a final disposition. A reviewer must explicitly record any final decision; Mizan does not close tickets, send reports, or message reporters.
- **Prompt boundary and hard guardrails:** Untrusted report/code values are JSON-quoted and kept separate from system instructions. The normalizer prevents acceptance when supplied code contradicts a claim or the input is classified as scanner noise. These controls do not make model output infallible.

Mizan is a self-hosted prototype, not a replacement for source review, vulnerability validation, or a program's reporting policy. Synthetic examples are not evidence of detection accuracy. A single central public service is intentionally not included; running separate instances keeps each researcher's data and model costs separate.

## Reviewer workflow

1. Start the researcher's private instance and enter its locally generated token.
2. Paste a report and, optionally, a source snippet. The submitted source is stored as text only.
3. Select **Save report locally**. This creates a `received` case and makes no model request.
4. If live analysis is needed, configure your own Meta key, choose **Analyze with Meta**, and confirm that the case will be sent to the configured provider.
5. Inspect the recommendation and evidence. It is advisory and does not determine the final disposition.
6. Record a human decision and optional reviewer note. Mizan stores it in local audit history and sends nothing externally.
7. Delete cases according to your own retention policy. Backups and copies outside Mizan remain your responsibility.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `MIZAN_JUDGE_TOKEN` | Per-installation Bearer token required for `/api/*`; minimum 32 bytes | Created by `scripts/bootstrap.py` |
| `MODEL_API_KEY` | Researcher's Meta Model API key; `META_API_KEY` and `META_MODEL_API_KEY` are also accepted | Unset; live analysis unavailable |
| `META_API_BASE` | OpenAI-compatible Meta Model API base URL | `https://api.meta.ai/v1` |
| `META_MODEL` | Comma-separated model names tried in order | `muse-spark-1.3,muse-spark-1.1` |
| `META_REASONING_EFFORT` | Optional reasoning-effort value passed to the API | Unset |
| `MIZAN_DB_PATH` | SQLite database path | `data/mizan.sqlite3` (Python) or `/app/data/mizan.sqlite3` (Docker) |
| `MIZAN_BIND_HOST` | Server bind address | `127.0.0.1` (Python); Compose uses `0.0.0.0` inside the container only |
| `PORT` | HTTP server port | `8000` |

The Docker Compose port mapping is explicitly bound to `127.0.0.1`. Do not change it to `0.0.0.0` or put the local service behind a public reverse proxy without designing and reviewing a separate multi-user deployment. `META_API_BASE` receives the Meta bearer key and case contents; only use a trusted, authorized endpoint.

## Local API

Every `/api/*` route requires `Authorization: Bearer <MIZAN_JUDGE_TOKEN>`. The local token protects one researcher's own instance; it does not provide account-level isolation. `GET /healthz` is unauthenticated and returns only `{"ok":true}` for container health checks.

| Method and route | Behavior |
|---|---|
| `GET /healthz` | Minimal unauthenticated container health check |
| `GET /api/health` | Health and a boolean indicating whether a model key is configured |
| `GET /api/metrics` | Aggregate case counts only; no report contents |
| `GET /api/sample?kind=injection\|valid\|noise&lang=en\|ar` | Bundled synthetic sample input |
| `GET /api/reports` | Bounded, searchable case summaries; supports `status`, `q`, `limit`, and `offset` |
| `POST /api/reports` | Save report/code locally; does not call the model |
| `GET /api/reports/{id}` | Read one local case |
| `POST /api/reports/{id}/analyze` | Request model analysis for the selected case and save a recommendation |
| `POST /api/reports/{id}/review` | Record an explicit human disposition and note |
| `GET /api/reports/{id}/history` | Read local case events |
| `DELETE /api/reports/{id}` | Delete a case and its application-level history |
| `POST /api/triage` | Stateless compatibility endpoint; supports canned demo results or live triage |

Live model routes require both the interface confirmation and `confirm_egress: true`. The server validates local Host/Origin values and rejects malformed JSON, invalid content types, oversized bodies, invalid decisions, and invalid workflow transitions. API error messages are sanitized; routine logs omit report and code text.

## Tests and CI

Run all tests offline:

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the Python regression suite, builds the Docker image, and smoke-tests the container health endpoint. Model calls are mocked; CI uses no real provider credential and contacts no vulnerability target.

## Repository map

| Path | Purpose |
|---|---|
| `server.py` | Loopback HTTP server, health endpoint, and case/review API |
| `review_store.py` | Local SQLite persistence, event history, metrics, and deletion |
| `meta_client.py` | Configured Meta Model API client |
| `prompts.py` | System and user message templates |
| `triage.py` | Triage flow, safe input interpolation, normalization, and acceptance guardrails |
| `demo_data.py` | English and Arabic synthetic examples |
| `static/index.html` | Local human-review workbench UI |
| `scripts/bootstrap.py` | Private per-installation configuration and token generation |
| `scripts/run.py` | One-command bootstrap and Docker Compose startup |
| `Dockerfile`, `compose.yaml` | Non-root, loopback-only Docker deployment with persistent SQLite volume |
| `tests/test_all.py` | Core triage, normalization, and compatibility API tests |
| `tests/test_bootstrap.py` | Private local setup and token-generation tests |
| `tests/test_meta_client.py` | Mocked Meta client request, fallback, size-limit, and error-redaction tests |
| `tests/test_review_store.py` | SQLite store tests |
| `tests/test_workbench_api.py` | Local API integration tests using mocked model calls |
| `SECURITY.md` | Security boundaries and self-hosted deployment limitations |
| `docs/ARCHITECTURE.md` | Components, trust boundaries, data flow, and case state machine |
| `docs/API.md` | Local API routes and example payloads |
| `docs/EVALUATION.md` | Safe model-evaluation protocol and honest performance limitations |
| `docs/OPERATIONS.md` | Self-hosted configuration, Docker, SQLite backup/restore, and troubleshooting |
| `CONTRIBUTING.md` | Development workflow and required safety invariants |
| `.github/workflows/tests.yml` | Offline tests and Docker smoke validation |

## License

This project is distributed under the [MIT License](LICENSE).
