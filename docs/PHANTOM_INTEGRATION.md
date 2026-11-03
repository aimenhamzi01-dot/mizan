# Mizan–Phantom integration, phase 1

Mizan remains the primary workbench and decision plane. This phase adds an analyst-controlled task-manifest generator and uses the existing Phantom-result import preview for the return trip. It is a manual handoff, not live orchestration.

## Workflow

1. Sign in to Mizan as a workspace admin or analyst. Open **Prepare an authorized Phantom task**.
2. Enter the target and choose only the authorized checks. Confirm the authorization checkbox and create the manifest. Mizan downloads a JSON task file with a unique task ID and a two-hour expiry.
3. Transfer the manifest through an approved private channel to the isolated Phantom operator. Review target and scope again before starting any scan. The current Phantom API does not yet consume or cryptographically verify Mizan task manifests; the operator must manually copy the target, target type, and scope into Phantom. Do not treat a manifest as proof of authorization.
4. Export the completed Phantom `ScanResult` as JSON. In Mizan, load it through **Import a completed Phantom result**, inspect and edit the draft, then save it as a local report. The importer treats scanner findings, severity, source excerpts, and Phantom's `verified` flag as claims.
5. Any later Meta analysis still requires its separate explicit consent. A human reviewer records the final disposition in Mizan.

## What this phase does and does not do

The manifest endpoint is authenticated and limited to analyst/admin roles. It requires an explicit user attestation and restricts the task-type and scan-category fields to bounded enumerations. It does **not** validate the target, determine whether it is in a bounty program's scope, or verify the user's authorization. The target string is carried as data without a network lookup or a connection. It creates no persistent job record and does not contact Phantom, resolve a target, execute code, or make a model call.

The manifest carries no API key, bearer token, report body, source code, or model content. It is a coordination file, not a signed capability: anyone who can edit the JSON can change its fields. Phantom's current `/scan/start` endpoint does not authenticate callers or enforce Mizan's authorization statement. Operate Phantom only on a private, restricted network. Before a live scanner-worker integration, add service authentication, target allowlists, DNS/IP egress enforcement (including redirect and DNS-rebinding controls), bounded worker concurrency and resource limits, persistent job/result storage, and a verified task signature or authenticated queue.

This handoff does not make Phantom production-safe. The repository's exposed `.env` credentials must be revoked and rotated before using it. Do not include that `.env` in images or bundles. Keep Phantom private until its API authentication, TLS validation, target controls, and deployment exposure have been fixed.

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

The response is `{ "manifest": { ... } }` with format `mizan-phantom-task-v1`, `task_id`, creation and expiry timestamps, the requesting user/workspace, an authorization attestation, and execution limits. The service role is always taken from the authenticated Mizan principal, not from the request body. Installation-owner requests default to the `default` workspace and may specify another existing workspace. The expiry is informational; Phantom does not yet enforce it.
