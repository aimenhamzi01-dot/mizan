# Mizan API Guide

Run Mizan with `python3 server.py` or `docker compose up --build`. The default UI is `http://127.0.0.1:8000`; Compose publishes on loopback. For private team access behind a TLS reverse proxy, configure `MIZAN_ALLOWED_HOSTS` and `MIZAN_ALLOWED_ORIGINS` and keep the app port private.

Every `/api/*` route requires an `Authorization: Bearer <token>` header. The installation-owner token grants global administration. Individual user tokens are workspace-scoped and role-limited. Tokens are shown once at creation/rotation. Request bodies must use `Content-Type: application/json` and be JSON objects.

For a local terminal, read a token without echoing it:

```bash
read -rsp 'Mizan access token: ' TOKEN; printf '\n'
AUTH=(-H "Authorization: Bearer $TOKEN")
```

Never put tokens or API keys in URLs, issues, source control, or shared logs. Clear shell variables when finished with `unset TOKEN AUTH`.

## Roles

| Role | Allowed actions |
|---|---|
| Installation owner token | Global read/write; create workspaces; create any role; revoke/rotate users |
| Workspace `admin` | Workspace read; manage members; create analyst/reviewer/viewer; revoke/rotate workspace members |
| `analyst` | Read workspace data; submit cases; request analysis |
| `reviewer` | Read workspace data; record human dispositions |
| `viewer` | Read only |

All users in a workspace share visibility of its cases. Workspace admins cannot create other admins or access another workspace. Unknown/out-of-scope case IDs return 404.

## Identity and workspace administration

The installation owner can create a workspace:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/admin/workspaces \
  -H 'Content-Type: application/json' \
  -d '{"name":"Product Security"}'
```

Create an individual researcher token (returned once):

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/admin/users \
  -H 'Content-Type: application/json' \
  -d '{"username":"researcher.alex","role":"analyst","workspace_id":"WORKSPACE_ID"}'
```

`role` is `admin`, `analyst`, `reviewer`, or `viewer`. A workspace admin may provision only the admin's own workspace and cannot assign the `admin` role. The API stores only a digest of each token; preserve the response privately for the user.

Other identity routes:

| Method and route | Behavior |
|---|---|
| `GET /api/me` | Current user id, username, role, workspace, and boolean `has_model_key` |
| `GET /api/workspaces` | All workspaces for owner; the current workspace for a user |
| `GET /api/admin/users` | Active/revoked users in the permitted administrative scope |
| `POST /api/admin/users/{id}/rotate-token` | Replace token; old token is invalidated immediately; new token returned once |
| `DELETE /api/admin/users/{id}` | Revoke user and remove that user's encrypted provider key |

An administrator cannot rotate or revoke the currently authenticated account through the UI. Revoke and recreate an account if a role change is required.

## Personal Meta API keys

Each researcher supplies their own authorized API key; Mizan does not provide provider billing. The key is encrypted in the local database with AES-GCM. It is never returned from the API. Example:

```bash
curl "${AUTH[@]}" -X PUT http://127.0.0.1:8000/api/me/model-key \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"YOUR_PERSONAL_KEY"}'
curl "${AUTH[@]}" -X DELETE http://127.0.0.1:8000/api/me/model-key
```

Do not place a real key in shell history. Prefer the profile panel in the UI. The installation-owner token may use the legacy `MODEL_API_KEY` environment fallback; ordinary user tokens never inherit it. `MIZAN_ENCRYPTION_KEY` must remain private and backed up with the database.

## Health and queue

```bash
curl http://127.0.0.1:8000/healthz
curl "${AUTH[@]}" http://127.0.0.1:8000/api/health
curl "${AUTH[@]}" 'http://127.0.0.1:8000/api/reports?status=received&limit=25'
curl "${AUTH[@]}" http://127.0.0.1:8000/api/metrics
```

`GET /healthz` is unauthenticated for container health checks and returns only `{"ok":true}`. `/api/health` returns `ok`, boolean `has_key`, and storage type. It never returns credentials. List responses are bounded summaries; metrics contain workspace-scoped counts only.

## Save a case locally

An analyst submits a case to their own workspace; it is stored as text and no model call is made:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/reports \
  -H 'Content-Type: application/json' \
  -d '{"report":"Synthetic report text","code":"def example(): pass","lang":"en"}'
```

The installation owner may include `workspace_id` to assign a case; an ordinary analyst cannot select another workspace. The returned case has `status: "received"`, `analysis: null`, and `review_decision: null`.

## Request an AI recommendation

The authenticated analyst uses their own saved Meta key. The API requires explicit consent as well as the UI confirmation:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/reports/CASE_ID/analyze \
  -H 'Content-Type: application/json' -d '{"confirm_egress":true}'
```

The selected report and source snippet are sent to the configured `META_API_BASE`. The analysis stores a model recommendation and never sets a human disposition. Saving a report alone is always local-only. The response includes `analysis_meta` with the resolved model identifier (when supplied by the provider), prompt version and SHA-256 of the prompt template, elapsed milliseconds, and allowlisted token counts when available. It does not include the prompt content or API key.

An optional second-pass challenge costs at least one additional model request. It must be explicitly authorized in both the request and the UI:

```json
{"confirm_egress":true,"challenge_pass":true,"confirm_challenge_egress":true}
```

`challenge_pass` defaults to `false`; setting it to `true` without `confirm_challenge_egress: true` returns HTTP 400 without calling the model. The second pass is advisory, not independent verification. Its `challenge_pass.status` can be `clear`, `flagged`, `inconclusive`, `invalid-evidence`, `invalid-response`, or `unavailable`. A flagged, inconclusive, or invalid result downgrades the suggested decision to `need-info` and records the primary-pass suggestion separately as `primary_decision`. An unavailable challenge leaves the first-pass suggestion visible and explicitly marks the extra pass unavailable. No status sets a human disposition.

Each analysis includes an `evidence` array. Every item has `source` (`report` or `code`), an exact `quote`, a `relation` (`supports`, `contradicts`, or `context-needed`), a short explanation, and server-computed fields: `verified`, zero-based `start` and `end` character offsets, `match_count`, and `ambiguous`. Offsets refer to the trimmed report/code value analyzed by Mizan; the UI locates the exact quote in the source text and highlights its first occurrence. Repeated quotes remain literal matches but are marked ambiguous. The server checks that the full quote is present in the stated input. If any quote is missing, malformed, or attributed to the wrong source, `citation_integrity` is `unverified` and the suggested decision is downgraded to `need-info`. `missing_context` lists questions that could change the assessment.

Example excerpt:

```json
{
  "citation_integrity": "verified",
  "evidence": [
    {
      "source": "code",
      "quote": "invoice = Invoice.objects.get(id=invoice_id)",
      "relation": "supports",
      "explanation": "The shown lookup is by id, without a user scope in this function.",
      "verified": true,
      "start": 0,
      "end": 44,
      "match_count": 1,
      "ambiguous": false
    }
  ],
  "analysis_meta": {
    "model": "muse-spark-1.3",
    "prompt_version": "evidence-triage-v1",
    "prompt_sha256": "...",
    "elapsed_ms": 4200,
    "usage": {"prompt_tokens": 1400, "completion_tokens": 420, "total_tokens": 1820}
  },
  "missing_context": ["Check whether outer middleware scopes this route."]
}
```

`verified` means only that the text matches the supplied source exactly. It does not establish semantic relevance, truth, reachability, or completeness; the reviewer must inspect the surrounding code and make the final decision. The optional stateless `POST /api/triage` accepts the same `challenge_pass` and separate confirmation fields for live requests; built-in demo cases make no model calls.

`POST /api/triage` remains available for stateless compatibility. Synthetic canned results can be requested with `{ "demo":"injection", "lang":"en" }`. A live call requires analyst/admin role, the user's own key (or owner-only fallback), and `confirm_egress: true`.

## Record a human disposition

A case must have model analysis before a disposition is recorded. Only a reviewer, workspace admin, or installation owner may do so:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/reports/CASE_ID/review \
  -H 'Content-Type: application/json' \
  -d '{"decision":"need-info","note":"Check route-level authorization before confirming."}'
```

The server records the authenticated username and user id; a client-supplied `reviewer` value is not trusted. Decisions are `accept`, `need-info`, `duplicate`, and `reject`. No ticket or message is sent.

## Read and delete cases

```bash
curl "${AUTH[@]}" http://127.0.0.1:8000/api/reports/CASE_ID
curl "${AUTH[@]}" http://127.0.0.1:8000/api/reports/CASE_ID/history
curl "${AUTH[@]}" -X DELETE http://127.0.0.1:8000/api/reports/CASE_ID
```

Case deletion requires admin role in the relevant workspace (or the installation owner). It removes the case and application-level events, not backups or external copies.

## Routes and errors

- `GET /api/sample?kind=injection|valid|noise&lang=en|ar` — synthetic sample input (any authenticated role).
- `GET /api/reports` — bounded workspace-scoped summaries with `status`, `q`, `limit`, and `offset` filters.
- `GET /api/reports/{id}` and `/history` — workspace-scoped detail and events.
- `GET /api/metrics` — counts scoped to the active workspace.
- Missing/invalid credentials return 401; insufficient role returns 403; unknown/out-of-scope cases return 404.
- If no owner token or provisioned users are available, API access fails closed with HTTP 503.
- Request bodies are capped at 2 MiB; unsupported content types, oversized input, invalid decisions, and workflow errors return sanitized 4xx responses.
- Provider error bodies and secrets are not returned to the browser.
