# Mizan — Team Security Triage Workbench

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)

**Mizan is a self-hosted, human-led workbench for security-report triage.** One private installation can host multiple workspaces with role-scoped access. Each researcher signs in with an individual access token, stores their own Meta API key encrypted at rest, and is responsible for their own model usage. There is no central Mizan service or shared provider account.

Built for the **Meta Global AI Developer Hackathon 2026**, Indie Developer Track, under **Build for Your World**.

## Product capabilities

- Receive vulnerability reports and optional pasted source snippets as text; saving a case does not call a model.
- Separate workspaces with server-enforced access scoping for lists, metrics, details, history, analysis, review, and deletion.
- Individual high-entropy bearer tokens, stored as hashes, with role-based access, immediate revocation, and one-time token rotation.
- Roles: **installation owner** (global administrator), **workspace admin** (manage members in one workspace), **analyst** (submit and analyze), **reviewer** (review and disposition), and **viewer** (read only).
- Each researcher can store a personal Meta API key; it is encrypted at rest with AES-GCM using an installation key. No researcher key is shared by Mizan.
- Explicit confirmation before any case content is sent to the configured Meta-compatible endpoint.
- Searchable queue, aggregate metrics, audit events, human dispositions separate from model recommendations, and local deletion.
- Synthetic examples; English interface with English/Arabic report-analysis language selection.

Mizan never executes submitted code or exploits and never contacts a reported target. Model recommendations remain advisory; a human must record any disposition.

## Quick start: private local installation

**Requirements:** Docker Engine and Docker Compose v2. The Python-only option additionally uses the pinned dependency in `requirements.txt`.

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python3 scripts/run.py
```

On first run, Mizan creates a private `.env`, prints the installation-owner token once, stores a separate encryption key without printing it, and starts Compose. Open <http://127.0.0.1:8000> and sign in with the owner token. The owner can create workspaces and issue personal tokens from **Workspace administration**. Each user should save their own Meta API key in their account panel.

The application port is bound to loopback by default. SQLite is stored in a project-scoped Docker volume. `docker compose down` preserves it; `docker compose down -v` deletes it. Do not share the installation-owner token: it has global administrative access.

## Private team access behind a TLS reverse proxy

The app does not terminate TLS. Keep the Compose port bound to loopback and place a trusted reverse proxy on the same host. Set exact host and origin allow-lists in the private `.env`, for example:

```dotenv
MIZAN_ALLOWED_HOSTS=triage.internal.example
MIZAN_ALLOWED_ORIGINS=https://triage.internal.example
MIZAN_PUBLISH_HOST=127.0.0.1
```

Configure the proxy to enforce HTTPS and restrict access to your private network or organization. Do not publish Mizan directly to the public internet. The app validates `Host` and `Origin`, but these checks are not a substitute for TLS, network controls, rate limiting, monitoring, or a security review.

## Python-only setup

```bash
python3 -m pip install -r requirements.txt
python3 scripts/bootstrap.py
python3 server.py
```

Open <http://127.0.0.1:8000>. Python mode binds to loopback by default and stores cases at `data/mizan.sqlite3`. Never bind it to an untrusted network.

## Roles and workspace behavior

| Identity / role | Capabilities |
|---|---|
| Installation owner | Global access; create workspaces; create any role; revoke or rotate user tokens |
| Workspace admin | Read/manage members in their workspace; issue analyst, reviewer, and viewer tokens; revoke or rotate members |
| Analyst | Read workspace cases; submit cases; request model analysis |
| Reviewer | Read workspace cases; record or revise human dispositions |
| Viewer | Read workspace cases only |

All members of a workspace can read that workspace's cases; workspace roles are not per-case ownership. Cross-workspace access is rejected by the server (unknown cases return 404). Workspace admins cannot create other workspace admins or create workspaces. Only the installation owner token is global.

## Data, keys, and cost

- Reports, code snippets, analysis results, and review history are stored locally in SQLite **without database encryption**. Protect the host, Docker volume, backups, and `.env` file.
- Personal Meta API keys are encrypted in SQLite with AES-GCM. The 256-bit `MIZAN_ENCRYPTION_KEY` remains in `.env`; back it up securely with the database. If lost, saved personal API keys cannot be decrypted. Do not regenerate or rotate it casually.
- Each researcher supplies and pays for their own Meta API usage. The optional `MODEL_API_KEY` environment variable is a legacy fallback for the installation owner only; ordinary users use their encrypted personal key.
- A live analysis sends the selected case report and code to `META_API_BASE` only after explicit UI consent and server-side `confirm_egress: true`. Use only a trusted provider endpoint.
- Tokens are bearer secrets. They are not passwords, are not stored in browser storage, and have no automatic expiry. Admins can revoke or rotate individual tokens.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `MIZAN_JUDGE_TOKEN` | Private installation-owner token; full global administration; minimum 32 bytes | Created by bootstrap |
| `MIZAN_ENCRYPTION_KEY` | Base64url-encoded 32-byte AES-GCM key for personal provider credentials | Created by bootstrap |
| `MIZAN_ENCRYPTION_KEY_VERSION` | Bootstrap recovery guard; do not remove | `1` after setup |
| `MODEL_API_KEY` | Optional owner-only legacy model-key fallback | Unset |
| `META_API_BASE` | Trusted OpenAI-compatible Meta endpoint | `https://api.meta.ai/v1` |
| `META_MODEL` | Comma-separated models tried in order | `muse-spark-1.3,muse-spark-1.1` |
| `MIZAN_DB_PATH` | SQLite path | `data/mizan.sqlite3` (Python) or `/app/data/mizan.sqlite3` (Docker) |
| `MIZAN_BIND_HOST` | Process bind address | `127.0.0.1` (Python); `0.0.0.0` inside Docker |
| `MIZAN_PUBLISH_HOST` | Docker host bind address | `127.0.0.1` |
| `MIZAN_ALLOWED_HOSTS` | Exact trusted hostnames for a private proxy | Unset |
| `MIZAN_ALLOWED_ORIGINS` | Exact trusted HTTPS origins for a private proxy | Unset |
| `PORT` | HTTP server port | `8000` |

## API overview

All `/api/*` routes require a valid `Authorization: Bearer <token>` header. The owner token and individual user tokens are accepted; access is scoped to the authenticated user's workspace except for the owner. See [the API guide](docs/API.md).

| Route | Purpose |
|---|---|
| `GET /healthz` | Minimal unauthenticated container health check |
| `GET /api/me` | Current identity and whether a personal model key exists |
| `GET /api/workspaces` | Workspaces visible to the current identity |
| `GET /api/admin/users` | Workspace members for an administrator |
| `POST /api/admin/workspaces` | Create workspace (installation owner only) |
| `POST /api/admin/users` | Issue an individual user token; returned once |
| `POST /api/admin/users/{id}/rotate-token` / `DELETE /api/admin/users/{id}` | Rotate or revoke a user token |
| `PUT/DELETE /api/me/model-key` | Save or remove the current user's encrypted Meta key |
| `GET/POST /api/reports` | List cases / create a local case |
| `POST /api/reports/{id}/analyze` | Explicit live analysis using the current user's key |
| `POST /api/reports/{id}/review` | Record a human disposition |
| `GET /api/reports/{id}/history` | Read local audit events |
| `GET /api/metrics` | Workspace-scoped counts only |

`GET /healthz` returns only `{"ok":true}`. It exposes no identity, key, or case status.

## Safety and limitations

Mizan is a self-hosted prototype, not a vulnerability validator or a production SaaS. It does not implement password login, MFA, session cookies, automatic token expiry, database encryption, automatic retention, or TLS termination. Review the deployment and privacy boundaries in [SECURITY.md](SECURITY.md) before enabling private team access.

## Tests and CI

```bash
python3 -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

GitHub Actions runs the offline Python suite, builds the container, and smoke-tests its health endpoint and authenticated API. Provider calls are mocked; CI uses only test values and never contacts vulnerability targets.

## Repository map

| Path | Purpose |
|---|---|
| `server.py` | HTTP server, authentication, workspace RBAC, and API |
| `auth_store.py` | Individual identity tokens, roles, workspaces, revocation, and rotation |
| `secret_store.py` | AES-GCM encryption for per-user provider keys |
| `review_store.py` | SQLite migrations, scoped cases, events, metrics, and deletion |
| `meta_client.py` | Meta-compatible model API client |
| `triage.py`, `prompts.py` | Safe triage pipeline, prompt boundary, normalization, and guardrails |
| `static/index.html` | Researcher workbench, profile key settings, and workspace admin panel |
| `scripts/bootstrap.py`, `scripts/run.py` | Private initial setup and Compose startup |
| `Dockerfile`, `compose.yaml` | Hardened self-hosted container and persistent SQLite volume |
| `tests/` | Offline unit, storage, security, and API regression coverage |
| `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/OPERATIONS.md` | Architecture, API, and operations guidance |
| `docs/EVALUATION.md` | Safe evaluation protocol and limitations |

## License

This project is distributed under the [MIT License](LICENSE).
