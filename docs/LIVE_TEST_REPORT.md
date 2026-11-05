# Mizan Live Validation Report

**Run date:** 2026-11-04 09:30 CET
**Suite:** `mizan-live-http-validation`
**Result:** **45/45 passed · 0 failed**

## Executive summary

Mizan was started as a real local HTTP service and exercised through its public API using a temporary SQLite database. The suite used real HTTP requests, real authentication tokens, real workspace records, real role checks, real persistence, real local static-analysis execution, and real Mizan–Phantom manifest/provenance flows.

This was not a mocked API test. The only intentionally isolated parts were the external boundaries: no Meta provider request and no external target request were made during this run. All test data was synthetic and the temporary database was discarded after validation.

## Environment

| Item | Value |
|---|---|
| Service | Mizan local HTTP server |
| Bind address | `127.0.0.1` |
| Port | `8765` |
| Storage | Temporary SQLite database |
| Provider calls | 0 |
| External target calls | 0 |
| Test data | Synthetic only |
| Test client | Python standard-library HTTP client |
| Result | 45 passed, 0 failed |

## Coverage matrix

### Public surface and authentication — 7 checks

- Public index responds successfully.
- Public `/healthz` responds with the expected health payload.
- Unauthenticated API requests return `401`.
- Invalid bearer tokens return `401`.
- Installation-owner identity is resolved correctly.
- Authenticated health exposes storage status without credentials.
- A non-JSON request body is rejected with `415`.

### Workspaces, roles, and identity — 11 checks

- Owner can list workspaces.
- Owner can create an isolated workspace.
- Owner can provision an analyst.
- Owner can provision a reviewer.
- Owner can provision a viewer.
- Each account resolves to the expected role and workspace.
- Reviewer cannot create cases.
- Viewer cannot create cases.
- Viewer cannot record a review decision.

### Case lifecycle and local analysis — 7 checks

- Analyst creates a synthetic case.
- The case appears in the correct scoped queue.
- Workspace-scoped metrics are available.
- Case detail is readable by an authorized workspace member.
- Review is blocked before model analysis.
- Local static analysis runs against saved source text.
- Static-analysis output remains separate from model analysis.

### Offline bilingual intelligence — 4 checks

- English prompt-injection sample loads.
- English offline triage returns the expected `reject` decision.
- Arabic prompt-injection sample loads.
- Arabic offline triage returns the expected `reject` decision.

The live responses showed the intended behavior: the prompt-injection text remained inside the report boundary, the supplied code contradicted the SQL-injection claim, citation integrity was verified against the supplied sources, and the synthetic decision was `reject` rather than an automatic acceptance.

### Phantom evidence handoff — 5 checks

- A provenance-rich Phantom result previews successfully.
- A viewer is denied Phantom import access.
- A malformed Phantom result is rejected with `400`.
- Mizan creates a signed `mizan-phantom-task-v1` manifest with HMAC-SHA256.
- A manifest without the required authorization attestation is rejected with `400`.

The successful manifest included the bounded execution policy, a two-hour task expiry, the requested scope, and `automatic_execution: false`.

### Workspace isolation — 5 checks

- A second workspace can be created.
- A second-workspace analyst can be provisioned.
- The second workspace cannot list, read, or inspect the history of the first workspace's case.

### Token lifecycle and authorization — 6 checks

- Owner rotates a user token.
- The old token is immediately rejected with `401`.
- Owner revokes the user token.
- An analyst is denied case deletion with `403`.
- Owner deletes the case successfully.
- The deleted case is no longer readable and returns `404`.

## Reproduce the validation

Start Mizan with a private test configuration and a temporary database, then run:

```bash
python3 scripts/live_validation.py \
  --base-url http://127.0.0.1:8765 \
  --owner-token "$MIZAN_JUDGE_TOKEN"
```

The suite prints one machine-readable summary line followed by one line per check:

```text
{"suite":"mizan-live-http-validation","total":45,"passed":45,"failed":0}
PASS | public index | HTTP 200
...
PASS | deleted case is no longer readable | HTTP 404
```

The harness is intentionally provider-free. It validates the real server and all local workflow boundaries without sending report or code content outside the machine.

## What this report establishes

This run establishes that the local Mizan service can:

- Serve and authenticate a live API.
- Enforce role and workspace boundaries.
- Persist and retrieve real cases in SQLite.
- Preserve separation between static analysis, model analysis, and human review.
- Handle bilingual offline cases.
- Validate and sign a Phantom handoff.
- Preserve Phantom provenance during preview.
- Rotate and revoke tokens.
- Fail safely on malformed, unauthorized, or out-of-scope requests.

It is a live integration validation report, not a claim of universal model accuracy, production load capacity, or security of an external deployment. Provider-evaluation runs require an explicitly authorized Meta API key and a separate consented test dataset.
