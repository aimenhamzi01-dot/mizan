# Security and Responsible Use

Mizan is a **self-hosted, single-researcher** triage workbench. Each researcher runs a separate local instance, stores cases in their own SQLite database, and configures their own Meta API key. There is no central Mizan service, shared model key, or shared report database in this repository.

## Data flow and storage

- Saving a case stores the report and optional source snippet in local SQLite. Python mode defaults to `data/mizan.sqlite3`; Docker Compose stores data in the `mizan-data` volume at `/app/data/mizan.sqlite3`.
- The SQLite file is plaintext, not encrypted by Mizan. Protect the computer, Docker volume, backups, and `.env` file as sensitive vulnerability data.
- Every `/api/*` route requires `Authorization: Bearer <MIZAN_JUDGE_TOKEN>`. `scripts/bootstrap.py` creates a random per-install token and restricts `.env` permissions on POSIX systems. The token protects one local instance; it is not an account system and grants full access to that instance's cases.
- The Docker Compose port is published only on `127.0.0.1`. The container listens on `0.0.0.0` inside its private Docker network; do not widen the host port mapping or expose the service directly to an untrusted network.
- `GET /healthz` is unauthenticated for container health checks and returns only `{"ok":true}`. It does not reveal model-key status, case data, or configuration.
- Live analysis is optional. Saving a case makes no model request. After an explicit UI confirmation and an API request containing `confirm_egress: true`, the case report and source snippet are sent to the configured Meta-compatible endpoint.
- Each researcher configures their own `MODEL_API_KEY` locally and pays their own provider usage. The key is not stored in the case database. The configured `META_API_BASE` receives the bearer key and case content, so only use a trusted, authorized provider endpoint.
- Cases remain until the researcher deletes them or removes the database. There is no automatic retention expiry. Deletion removes the case and application-level event history, but cannot guarantee forensic erasure from backups, snapshots, or storage media.
- Routine logs and API errors do not include report text, code, API keys, or upstream provider bodies.

## AI and review boundaries

The report and supplied code are passed as user-provided data in a separate model message, never appended to system instructions. Untrusted strings are JSON-quoted and inserted with one-pass template substitution so embedded newlines cannot forge the visible report/code closing delimiters or replace template fields. The output normalizer retains these hard rules: a claim marked contradicted by supplied code cannot be accepted, and a `scanner-dump` cannot be accepted. Tests include delimiter-spoofing and placeholder-injection cases.

These controls reduce risk but do not make model output infallible. Review all evidence and context. Mizan cannot establish whether omitted route decorators, middleware, or other authorization layers change the interpretation of a pasted snippet.

## Deployment boundary

This repository provides separate self-hosted instances, not a shared public SaaS. The API uses a per-install shared token rather than individual user identities or roles. The app has no TLS termination, rate limiting, or public multi-tenant controls. Keep it on loopback and do not expose it through a public reverse proxy without a separate security design and review. A central public service would require account authentication, per-user data isolation, quotas, abuse controls, protected secret handling, and a security/privacy review.

Mizan does not test a reported system. Do not add exploit execution, automated target access, or auto-applied decisions as extensions to this project.

## Reporting a vulnerability in Mizan

Open a GitHub issue for non-sensitive problems. For sensitive issues, contact the repository maintainer privately; do not post exploit details or secrets in a public issue.
