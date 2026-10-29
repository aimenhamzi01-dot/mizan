# Self-Hosted Team Operations Guide

## 1. Initial installation

Requirements: Docker Engine and Docker Compose v2. From a trusted host:

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python3 scripts/run.py
```

The launcher creates a private `.env`, generates an installation-owner token, prints that token once, creates a separate AES-GCM encryption key without printing it, then builds and starts Compose. Keep the owner token and `.env` in a private location. Open `http://127.0.0.1:8000` and sign in with the owner token.

Alternatively, run `python3 scripts/bootstrap.py` to prepare `.env` first, save the one-time owner token securely, then start with `docker compose up --build`.

The container runs non-root, with a read-only root filesystem, dropped capabilities, and a volume at `/app/data`. The Docker volume is named `<COMPOSE_PROJECT_NAME>_mizan-data`; the project name is generated per installation. `docker compose down` preserves data. `docker compose down -v` deletes it.

## 2. Create workspaces and users

The installation owner has global administrative access. In the **Workspace administration** panel:

1. Create a workspace for each independent research group.
2. Select a workspace, enter a unique username and role, then issue an individual user token.
3. Deliver the token privately. It is displayed once and cannot be retrieved later.
4. To recover from a lost token, rotate it. The prior token becomes invalid immediately; deliver the new one privately. To remove access entirely, revoke the user.

Workspace admins can manage members in their own workspace, but cannot create other workspace admins or workspaces. Analysts may submit/analyze, reviewers may record human dispositions, and viewers are read-only. All members of the same workspace can see its cases; the system does not provide per-case ownership. The installation owner can see every workspace.

Tokens are bearer secrets with no automatic expiry. Store them in an approved password manager or secret channel. Never put them in a URL, public issue, shared terminal history, source file, or screenshot. If the installation-owner token is compromised, update `MIZAN_JUDGE_TOKEN` in `.env` and restart; this rotates global access.

## 3. Researcher-specific Meta keys and usage

Each researcher signs in with their personal token, opens **Your Meta API key**, and saves a provider key they are authorized to use. The key is encrypted in the local SQLite database with AES-256-GCM and the private `MIZAN_ENCRYPTION_KEY` from `.env`. Mizan never returns the saved key to the browser. Each user's analysis uses only that user's saved key; the optional `MODEL_API_KEY` environment variable is a legacy fallback for the installation owner only.

Each researcher is responsible for their provider account, authorization, and usage charges. No Mizan service pays or shares a provider key. Live analysis sends the selected report and snippet to `META_API_BASE` only after an explicit confirmation. Use only a trusted endpoint.

### Encryption-key backup and recovery

Back up `.env` securely along with the SQLite database/volume. `MIZAN_ENCRYPTION_KEY` is essential: losing it makes stored researcher keys unrecoverable. Do not delete it, regenerate it, or rotate it casually. Bootstrap records a version marker and refuses to replace a previously initialized but missing/invalid key. To intentionally rotate it, first design and test a re-encryption migration with a secure backup; direct replacement will make existing encrypted keys unreadable.

## 4. Private remote team access

The default service is available only on `127.0.0.1:8000`. For team members on a private network, keep the app bound to loopback and configure a trusted same-host TLS reverse proxy. Set exact values in the private `.env`, for example:

```dotenv
MIZAN_ALLOWED_HOSTS=triage.internal.example
MIZAN_ALLOWED_ORIGINS=https://triage.internal.example
MIZAN_PUBLISH_HOST=127.0.0.1
```

Configure the proxy to terminate TLS, redirect/require HTTPS, preserve the intended `Host` header, enforce organizational access controls, and prevent bypass of the proxy. Mizan only validates configured Host/Origin values; it does not terminate TLS, inspect proxy identity, or provide rate limiting. Never bind directly to `0.0.0.0` on a public interface or expose the port to the internet.

## 5. Direct Python mode

Python 3.9 or newer is required. From the repository root:

```bash
python3 -m pip install -r requirements.txt
python3 scripts/bootstrap.py
python3 server.py
```

Python mode binds to `127.0.0.1:8000` and defaults to `data/mizan.sqlite3`. Configure `PORT` or `MIZAN_DB_PATH` in the private environment as needed. The default data directory is restricted to `0700` and the database file to `0600` on POSIX systems.

## 6. Upgrade and migration

On startup, Mizan upgrades the SQLite schema to version 2. Existing cases are assigned to the `default` workspace and remain accessible to the installation owner. After upgrading an older `.env`, run the bootstrap script once to generate `MIZAN_ENCRYPTION_KEY`; do not overwrite an already initialized key. Create new workspaces and accounts after the migration.

Before upgrading, back up both the database volume and `.env`. Keep the encryption key matched to the database snapshot. If a key is missing after it was initialized, restore the original `.env` from backup rather than allowing a replacement.

## 7. Storage, privacy, and retention

The SQLite database stores report bodies, pasted code, recommendations, reviewer names/notes, and audit events as plaintext. The provider keys alone are encrypted. Protect the host, volume, `.env`, and backups with restrictive access. Mizan has no automatic retention expiry or centralized recovery service. Deleting a case removes it and its application-level history, but cannot erase backups or guarantee physical-media sanitization.

For Docker backups, identify the named volume with `docker volume ls`; it uses the installation's Compose project prefix. Stop the app before a simple file-level copy. Protect backups with restrictive filesystem permissions and a defined retention policy. Do not commit backups or `.env`.

## 8. Health and API access

`GET /healthz` is unauthenticated and returns only `{"ok":true}` for container readiness. All `/api/*` routes require an owner or user Bearer token. The owner token has global rights; user tokens are workspace-scoped and role-limited. See [API.md](API.md) for route behavior.

## Troubleshooting

- **Compose says owner token or encryption key is missing:** run `python3 scripts/bootstrap.py` and confirm `.env` is present. Do not commit or upload it.
- **Bootstrap says restore the original encryption key:** restore the matching private `.env` backup; do not generate a new key over the database.
- **HTTP 503 on an API route:** no owner token is configured and no provisioned user is available, or the local identity store could not initialize.
- **HTTP 401 / sign-in rejected:** use a valid, non-revoked personal token. Admins can rotate a user's token if necessary.
- **HTTP 403:** the role does not permit the requested action, or the Host/Origin is not allow-listed.
- **HTTP 404 for a case:** it may not exist or may belong to another workspace.
- **Port 8000 is in use:** set `PORT=9000` in `.env` and restart Compose.
- **Researcher cannot analyze:** they must save their own provider key in the profile and explicitly confirm egress.
- **Key decryption fails:** verify `MIZAN_ENCRYPTION_KEY` matches the database backup.
- **Database locked:** ensure another Mizan process is not using the same SQLite path; writes use a five-second busy timeout.
