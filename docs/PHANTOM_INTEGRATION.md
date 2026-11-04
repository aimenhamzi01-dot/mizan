# Mizan–Phantom integration

Mizan remains the primary workbench and decision plane. Phantom is a bounded worker, not an independent scanner that accepts arbitrary targets.

## Workflow

1. Sign in to Mizan as a workspace admin or analyst. Open **Prepare an authorized Phantom task**.
2. Enter the target and choose only authorized checks. Confirm the authorization checkbox and create the manifest. Mizan emits a JSON task with a unique ID, a two-hour expiry, and an HMAC-SHA256 signature.
3. Transfer the manifest through an approved private channel to the isolated Phantom operator. Phantom verifies the signature, expiry, execution policy, target type, scope, and configured target allowlist before accepting it. Direct unsigned scans are disabled by default.
4. Export the completed Phantom `ScanResult` as JSON. In Mizan, load it through **Import a completed Phantom result**, inspect and edit the draft, then save it as a local report. The importer treats scanner findings, severity, source excerpts, and Phantom's `verified` flag as claims.
5. Any later Meta analysis still requires its separate explicit consent. A human reviewer records the final disposition in Mizan.

## Security model and limits

The manifest contains no API key, bearer token, report body, source code, or model content. Its HMAC signature detects edits but does not independently prove legal authorization. Phantom requires `PHANTOM_API_TOKEN`, rejects unsigned, expired, or tampered manifests, enforces `PHANTOM_ALLOWED_TARGETS`, rejects private/reserved IP resolutions, disables redirects, verifies TLS, and limits fetched source to 2 MB. These are defense-in-depth controls; a human must still verify authorization.

Set the same high-entropy value in both services:

```env
MIZAN_PHANTOM_SIGNING_KEY=<random value, at least 32 characters>
```

Phantom also requires:

```env
PHANTOM_API_TOKEN=<random value>
PHANTOM_ALLOWED_TARGETS=https://authorized.example.com
PHANTOM_ALLOW_DIRECT_SCANS=false
```

Keep Phantom private and bind Docker to loopback unless a private TLS gateway and exact allowlists are in place. Revoke and rotate any credentials that were ever committed or exposed; never include `.env` in images or bundles.

## API

`POST /api/phantom/tasks/manifest` accepts an authenticated Mizan JSON request:

```json
{
  "target": "https://in-scope.example.org",
  "target_type": "web",
  "scope": ["xss", "idor", "auth"],
  "authorized_scope": true
}
```

The response is `{ "manifest": { ... } }` with format `mizan-phantom-task-v1`, task ID, creation and expiry timestamps, the requesting user/workspace, authorization attestation, execution limits, `signature_algorithm`, and `signature`. Phantom accepts a start request only in this form:

```json
{
  "manifest": { "format": "mizan-phantom-task-v1", "...": "signed fields" }
}
```

Send `X-Phantom-API-Token` with the configured service token. A body containing only `{ "target": "https://arbitrary.example" }` is rejected in secure mode.
