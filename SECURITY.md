# Security and Responsible Use

Mizan is a local, read-only triage workbench. It stores report text and optional source snippets as text, and can ask a configured Meta Model API to produce a recommendation. It never imports or executes submitted code, runs exploits or reproduction steps, or contacts a vulnerability target. A model recommendation is not a final decision; only an explicit reviewer action records a human disposition. Mizan does not send decisions or draft replies to a bug-bounty platform or reporter.

## Data flow and storage

- Saving a case writes its report and optional code to a local SQLite database. The default path is `data/mizan.sqlite3`; `MIZAN_DB_PATH` can select another local path. The database is not encrypted by this application.
- Every `/api/*` route requires `Authorization: Bearer <MIZAN_JUDGE_TOKEN>`. The server accepts only a configured token at least 32 bytes long and fails closed if it is missing or too short. Comparisons use constant-time digest comparison. The token is not returned or logged.
- The judge token is shared and grants full API access, including reading and deleting every case. It does not provide per-judge identity, roles, individual revocation, expiration, or rate limiting. Rotate the server-side token to revoke all copies and distribute it only through a private channel.
- The UI keeps the entered token in JavaScript memory only; it is sent in the Authorization header and is cleared when the page is locked or reloaded. It is not placed in a URL, cookie, `localStorage`, or `sessionStorage`.
- Saving a case does not call a model. A separate, explicit **Analyze with Meta** action sends that case's report and source snippet to the configured Meta Model API. Reviewers must confirm this egress in the interface first; live API routes also require `confirm_egress: true`.
- Built-in examples return bundled canned results and do not call the model.
- Cases remain in the local database until deleted through the workbench or the database file is removed. Deleting a case also removes its application-level event history. Users remain responsible for backups and any copies outside Mizan.
- Routine HTTP logs and API error responses do not include report text, code, API keys, or upstream provider bodies. The health route reveals only whether a model key is configured.

## AI and review boundaries

The report and supplied code are passed as user-provided data in a separate model message, never appended to system instructions. Untrusted strings are JSON-quoted and inserted with one-pass template substitution so embedded newlines cannot forge the visible report/code closing delimiters or replace template fields. The output normalizer retains these hard rules: a claim marked contradicted by supplied code cannot be accepted, and a `scanner-dump` cannot be accepted. The tests include delimiter-spoofing and placeholder-injection cases.

These controls reduce risk but do not make model output infallible. Review all evidence and context. In particular, the application cannot establish whether omitted route decorators, middleware, or other authorization layers change the interpretation of a pasted snippet.

## Deployment boundary

The included server binds to `127.0.0.1` and checks local `Host`/`Origin` headers. Bearer authentication protects every API route, but this single shared token is not a multi-user authorization system. There is no TLS termination, rate limiting, per-reviewer identity, or production deployment hardening. Do not expose the server directly to an untrusted network or store regulated/sensitive production data in it. The local SQLite file is plaintext. Any network-accessible judge demo needs HTTPS, controlled hosting, rate limits, database protections, and a separate security review.

Mizan does not test a reported system. Do not add exploit execution, automated target access, or auto-applied decisions as extensions to this project.

## Reporting a vulnerability in Mizan

Open a GitHub issue for non-sensitive problems. For sensitive issues, contact the repository maintainer privately; do not post exploit details or secrets in a public issue.
