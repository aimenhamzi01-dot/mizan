# Self-Hosted Operations Guide

## Local installation and access

Each researcher runs an independent Mizan instance. There is no central service or shared account. From a fresh clone, start Docker and initialize a private configuration with one command:

```bash
python3 scripts/run.py
```

The launcher creates `.env` if needed, generates a random per-install token, prints it once, then builds and starts Docker Compose. Alternatively, prepare the configuration first with `python3 scripts/bootstrap.py`, save the printed token privately, then run `docker compose up --build`.

### Docker Compose (recommended)

Requirements: Docker Engine and Docker Compose v2. The web UI is available at `http://127.0.0.1:8000`. Compose publishes only on loopback. The container runs as a non-root user with a read-only root filesystem, drops Linux capabilities, and enables a minimal health check.

SQLite is stored in the Compose volume key `mizan-data`. Its actual Docker volume name is prefixed by this installation's unique `COMPOSE_PROJECT_NAME`, which the bootstrap script stores in `.env`. This keeps separately bootstrapped clones from sharing the same volume. `docker compose down` stops the app and preserves data; `docker compose down -v` deletes this installation's data volume.

To enable live analysis, set your own Meta API key in the private `.env` file as `MODEL_API_KEY=...`, then restart:

```bash
docker compose up -d --build
```

Each researcher uses their own provider account and is responsible for the associated model usage charges. Mizan does not provide a central paid API key. Keep `.env` out of Git and restrict its permissions; the bootstrap script sets mode `0600` on POSIX systems.

### Direct Python mode

Python 3.9 or newer is required; no third-party Python packages are needed.

```bash
python3 scripts/bootstrap.py
python3 server.py
```

The server binds to `127.0.0.1` by default and uses port `8000`. The default SQLite path is `data/mizan.sqlite3`. Set `PORT` or `MIZAN_DB_PATH` in `.env` to customize these values. The Python server does not include TLS termination and must not be exposed directly to an untrusted network.

## Model API setup

Live analysis is optional. Set `MODEL_API_KEY` in the private `.env` file or local process environment to a key you are authorized to use. `META_API_KEY` and `META_MODEL_API_KEY` are also accepted. The key is loaded by the server and is not stored in the case database. Never paste keys into reports, review notes, or source code.

The configured `META_API_BASE` receives the bearer key and report/code contents when a researcher explicitly confirms a live analysis. Use only a trusted provider endpoint. Built-in examples are synthetic; loading and saving them does not call the model. The compatibility route's canned responses are also local-only.

## Local database and retention

Python mode creates `data/mizan.sqlite3` by default. Docker mode stores the database in this installation's project-scoped `mizan-data` volume. On POSIX systems, Mizan restricts the default Python data directory to `0700` and the database file to `0600`. The Docker volume is mounted at `/app/data`, owned by the non-root application user. SQLite data is plaintext and not encrypted by this application.

The database contains original report text, source snippets, model recommendations, reviewer labels/notes, and application-level events. There is no automatic retention expiry. Cases remain until deleted or the database/volume is removed. Deletion cannot guarantee forensic erasure from backups, snapshots, or underlying storage.

## Backup and restore

Backups contain plaintext security reports. Stop Mizan before making a file-level copy. For direct Python mode, use SQLite's online backup API while the service is running, or stop the server before copying the database.

For Docker, use a documented Docker named-volume backup/restore procedure. Determine the exact volume with `docker volume ls`; it has the form `<COMPOSE_PROJECT_NAME>_mizan-data`, where the unique project name is recorded in the private `.env`. Stop the service for a simple file-level backup. Protect backup files with restrictive permissions and delete them according to your own retention policy. Do not commit database files or backups.

## Health check

`GET /healthz` returns only `{"ok":true}` and is unauthenticated so Docker can determine whether the process is ready. The endpoint does not expose case data or whether a model key is configured. All `/api/*` routes remain protected by the per-install Bearer token.

## Troubleshooting

- **Docker Compose says the judge token is missing:** run `python3 scripts/bootstrap.py` and keep the generated `.env` file.
- **HTTP 503 on an API route:** `MIZAN_JUDGE_TOKEN` is missing or shorter than 32 bytes in the server environment.
- **HTTP 401 / sign-in rejected:** enter the token for this local installation; reloading or locking clears the browser's in-memory token.
- **Port 8000 is in use:** set `PORT=9000` in `.env` and restart Compose. The default Compose mapping keeps the host and container ports aligned and remains bound to `127.0.0.1`.
- **No Meta API key:** local intake, queue, human review, and synthetic examples still work; live analysis remains unavailable.
- **Model API error:** check your own key, service availability, configured model names, and trusted `META_API_BASE`. Provider details are intentionally not returned to the browser.
- **Database locked:** ensure another Mizan process is not using the same SQLite database. Writes use a five-second busy timeout.
- **Lost local data:** Mizan cannot recover deleted cases without an operator-managed backup.
