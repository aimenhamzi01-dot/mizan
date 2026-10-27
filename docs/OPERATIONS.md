# Local Operations Guide

## Start and stop

Run `python server.py` from the project directory. The server binds to `127.0.0.1` only and defaults to port `8000`; use `PORT` to select another local port. Stop it with `Ctrl+C`. Do not put this server behind a public reverse proxy or bind it to `0.0.0.0` without a separate security review and implementation of authentication, authorization, CSRF/origin defenses, transport security, rate limits, and privacy controls.

## Model API setup

Live analysis is optional. Copy `.env.example` to `.env` and configure a key you are authorized to use. The key is loaded from the local process environment and is not stored in the case database. Never paste keys into reports, review notes, or source code. The configured `META_API_BASE` receives the bearer key as well as report/code contents; use only a trusted provider endpoint.

Canned sample results do not call the model. Saving a case does not call the model. Only an explicit analysis action sends the selected case to the configured model API.

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

- **Demo mode / no key:** local intake, queue, review, and canned samples still work; live analysis requires a valid configured key.
- **Model API error:** check key validity, service availability, configured model names, and the trusted `META_API_BASE`; provider details are intentionally not returned to the browser.
- **Database locked:** ensure another Mizan process is not holding the same database. SQLite writes use a five-second busy timeout.
- **Lost local data:** Mizan cannot recover deleted cases without an operator-managed backup.
