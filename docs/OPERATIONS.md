# Local Operations Guide

## Configure judge access

Every `/api/*` route requires a shared Bearer token in `MIZAN_JUDGE_TOKEN`. Generate at least 32 random bytes; for example:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Copy the result to `.env` or configure it through the deployment secret manager. Keep `.env` private (`chmod 600 .env` on POSIX), do not commit or log the token, and give it to judges only through a private channel. The token is sent in the `Authorization: Bearer …` header, never a URL. The UI keeps it in browser memory only; locking or reloading clears it.

The token is shared and grants full access to every case and API action, including deletion. Mizan has no per-judge accounts, roles, or individual revocation. Rotate the environment value and restart the service to invalidate every copy. An absent or shorter-than-32-byte token makes all API routes fail closed with HTTP 503; a missing or invalid request token returns HTTP 401.

## Start and stop

Run `python server.py` from the project directory. The server binds to `127.0.0.1` only and defaults to port `8000`; use `PORT` to select another local port. Stop it with `Ctrl+C`. A Bearer token does not add TLS, rate limiting, per-user authorization, or production deployment controls. Do not expose this server directly through a public reverse proxy or bind it to `0.0.0.0` without a separate security review and deployment hardening. Any network-accessible judge demo also needs HTTPS and protections for its database and model key.

## Model API setup

Live analysis is optional. Set `MODEL_API_KEY` in the local process environment or `.env` to a key you are authorized to use. The key is loaded from configuration and is not stored in the case database. Never paste keys into reports, review notes, or source code. The configured `META_API_BASE` receives the bearer key as well as report/code contents; use only a trusted provider endpoint.

The UI's built-in examples load synthetic sample reports; loading or saving them does not call the model. The compatibility route `/api/triage` also has fixed canned demo responses. Only an explicitly confirmed live analysis sends the selected case to the configured model API.

## Local database

By default, Mizan creates `data/mizan.sqlite3`. On POSIX systems, it sets the default data directory to mode `0700` and the database file to `0600`. The database is ordinary SQLite plaintext, not encrypted. Treat it as sensitive security data. A custom `MIZAN_DB_PATH` is the operator's responsibility; place it in a private directory with restrictive permissions.

The database contains original report text, source snippets, normalized analysis, reviewer labels/notes, and application-level events. There is no automatic retention expiry. Cases remain until a reviewer deletes them or removes the database. The delete route removes rows and enables SQLite secure-delete for deleted content, but it cannot guarantee forensic erasure from storage media, snapshots, backups, or filesystem copies.

## Backup and restore

Stop the server before copying the SQLite file. For a consistent backup while the server is running, use SQLite's online backup API rather than copying only the main database file while WAL activity is in progress:

```bash
python - <<'PY'
import sqlite3
source = sqlite3.connect("data/mizan.sqlite3")
destination = sqlite3.connect("mizan-backup.sqlite3")
source.backup(destination)
destination.close()
source.close()
PY
```

Backups contain plaintext report data. Store them securely, set restrictive permissions, and delete them according to your own retention policy. To restore, stop Mizan, replace the configured database file with the backup, ensure the file and parent directory are private, then restart the server. There is no automatic backup or cloud sync.

## Troubleshooting

- **HTTP 503 on an API route:** `MIZAN_JUDGE_TOKEN` is missing or shorter than 32 bytes in the server environment.
- **HTTP 401 / sign-in rejected:** check that the exact current token is entered; reloading or locking clears the browser's in-memory token. Rotating the server token invalidates old copies.
- **No Meta API key:** local intake, queue, human review, and synthetic examples still work; live model analysis remains unavailable.
- **Model API error:** check key validity, service availability, configured model names, and the trusted `META_API_BASE`; provider details are intentionally not returned to the browser.
- **Database locked:** ensure another Mizan process is not holding the same database. SQLite writes use a five-second busy timeout.
- **Lost local data:** Mizan cannot recover deleted cases without an operator-managed backup.
