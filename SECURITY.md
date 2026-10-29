# Security and Responsible Use

Mizan is a self-hosted team workbench. One operator-controlled installation can host multiple workspaces, with server-enforced workspace scoping and role checks. It is not a public SaaS and does not terminate TLS.

## Identity and authorization

- The installation-owner token is read from private `MIZAN_JUDGE_TOKEN`, must be at least 32 bytes, and is compared in constant time. It grants global administrative access; keep it private.
- Individual user tokens are generated from high-entropy randomness. Only SHA-256 token digests are stored in SQLite. Tokens are returned once at creation or rotation and can be immediately revoked. They have no automatic expiry.
- Roles are enforced in the server, not only the UI: workspace admins manage members in their own workspace; analysts submit and analyze; reviewers record dispositions; viewers are read-only. Only the installation owner can create workspaces or assign workspace-admin privileges.
- All members of a workspace can read its cases. Cases are not privately owned by an individual user. Workspace admins can view all data in their workspace; the installation owner can view all workspaces.
- There is no password login, MFA, cookie session, or identity-provider integration. A bearer token is equivalent to the user's access. Do not transmit one over untrusted HTTP.

## Data flow and storage

- Case text, source snippets, model recommendations, review notes, and application-level audit events are stored in local SQLite. Reports and code are plaintext in the database; Mizan does not encrypt the SQLite database.
- Existing database records are migrated to the `default` workspace. Subsequent queries and writes for ordinary users carry the authenticated workspace scope; cross-workspace lookups return 404.
- Per-user Meta API keys are encrypted at rest with AES-256-GCM (via `cryptography`). The installation's 32-byte `MIZAN_ENCRYPTION_KEY` is held in `.env`, never returned through the API, and must be backed up securely. Losing it makes saved user API keys unreadable. Possession of both the database and encryption key permits decryption.
- User tokens are bearer secrets. They are not stored in browser local/session storage; the UI keeps the current token in memory and sends it in the `Authorization` header.
- Saving a case makes no model request. Live analysis requires both UI confirmation and `confirm_egress: true` at the API. The authenticated user's own key is used; only the installation owner can fall back to the optional legacy environment key.
- `META_API_BASE` receives the provider bearer key and case content during live analysis. Treat this operator setting as trusted. Do not point it at an untrusted host.
- Cases remain until manually deleted or the database is removed. There is no automatic retention period. Deletion removes the case and application-level event history, but cannot guarantee forensic erasure from backups, snapshots, or storage media.
- Routine logs and API errors omit report text, source code, bearer tokens, API keys, and upstream provider error bodies.

## Network and deployment boundary

- Docker binds its host port to `127.0.0.1` by default; the process listens on `0.0.0.0` only inside the container.
- Private remote team access should use a trusted TLS reverse proxy with access restrictions. Configure exact `MIZAN_ALLOWED_HOSTS` and `MIZAN_ALLOWED_ORIGINS`; do not publish the app directly to the public internet. The application does not terminate or verify TLS itself.
- Host/Origin checks are a limited defense, not comprehensive CSRF protection, rate limiting, abuse prevention, or a replacement for network controls. Mizan does not trust `X-Forwarded-*` headers.
- The container uses a non-root user, read-only root filesystem, dropped Linux capabilities, and a persistent private Docker volume. Host administrators and anyone with volume or `.env` access remain trusted.
- There is no built-in rate limiting, token expiry, encrypted report storage, automatic backup, quota/billing service, monitoring, or compliance certification. Operators must review their threat model and privacy obligations before using sensitive reports.

## AI and review boundaries

Submitted source and reproduction steps are stored as text only. Mizan never executes submitted code, runs exploits, probes a target, or initiates target connectivity. The triage layer keeps report/code separate from system instructions, JSON-quotes untrusted values, and retains hard guardrails that prevent acceptance when supplied code contradicts a claim or the report is classified as scanner noise.

These controls reduce risk but do not make model output infallible. The model cannot infer omitted route decorators, middleware, deployment settings, or other authorization layers from a partial snippet. Every final disposition remains a human responsibility. Mizan does not close tickets, contact programs, or message reporters.

## Reporting a vulnerability in Mizan

Open a GitHub issue for non-sensitive problems. For sensitive issues, contact the repository maintainer privately; do not post exploit details, tokens, API keys, report data, or encryption keys in a public issue.
