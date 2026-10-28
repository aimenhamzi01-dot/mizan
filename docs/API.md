# Local API Guide

Run Mizan with `python3 server.py` or `docker compose up --build`. The local UI and API are available at `http://127.0.0.1:8000`. Docker Compose publishes on loopback only. Every `/api/*` route requires `Authorization: Bearer <MIZAN_JUDGE_TOKEN>`. The token is generated per installation and grants full access to that installation's cases; it is not an individual user account. Each researcher should run a separate instance and configure their own provider key. Do not expose this local API publicly. JSON request bodies must use `Content-Type: application/json`.

Create the local token with `python3 scripts/bootstrap.py`. It is printed once when generated and stored in the private `.env` file. Read the token without echoing it, then reuse the header array below (Bash):

```bash
read -rsp 'Local Mizan token: ' TOKEN; printf '\n'
AUTH=(-H "Authorization: Bearer $TOKEN")
```

Do not put the token in a URL, issue, screenshot, or source file. Clear the shell variable when finished with `unset TOKEN AUTH`.

## Health and queue

```bash
curl http://127.0.0.1:8000/healthz
curl "${AUTH[@]}" http://127.0.0.1:8000/api/health
curl "${AUTH[@]}" 'http://127.0.0.1:8000/api/reports?status=received&limit=25'
curl "${AUTH[@]}" http://127.0.0.1:8000/api/metrics
```

`GET /healthz` is unauthenticated for container health checks and returns only `{"ok":true}`. It reveals no case data or provider-key status. The authenticated API health response includes `ok`, a boolean `has_key`, and the storage type; it never returns either secret. List results are bounded summaries and metrics contain counts only.

## Save a report locally

Saving is local and makes no model request:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/reports \
  -H 'Content-Type: application/json' \
  -d '{"report":"Synthetic report text","code":"def example(): pass","lang":"en"}'
```

The returned `report.id` is a UUID. The new case has `status: "received"`, `analysis: null`, and `review_decision: null`.

## Request an AI recommendation

This route sends report/code to the locally configured Meta Model API using the installer's own provider key. The UI requires explicit confirmation, and the API also requires `confirm_egress: true`:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/reports/CASE_ID/analyze \
  -H 'Content-Type: application/json' -d '{"confirm_egress":true}'
```

The result stores an `analysis` and `suggested_decision`; it does not set a final human disposition. If the provider key is absent or the model call fails, the report remains stored and the browser receives a sanitized error. The researcher is responsible for their provider charges and for ensuring the report may be sent to that endpoint.

## Record a human disposition

A case must have an analysis before recording a review. The decision is an explicit human choice and remains separate from the suggestion:

```bash
curl "${AUTH[@]}" -X POST http://127.0.0.1:8000/api/reports/CASE_ID/review \
  -H 'Content-Type: application/json' \
  -d '{"decision":"need-info","reviewer":"Reviewer A","note":"Check route-level authorization before confirming."}'
```

Valid decisions are `accept`, `need-info`, `duplicate`, and `reject`. Reviews are recorded in local event history. No ticket or message is sent.

## Read and delete a case

```bash
curl "${AUTH[@]}" http://127.0.0.1:8000/api/reports/CASE_ID
curl "${AUTH[@]}" http://127.0.0.1:8000/api/reports/CASE_ID/history
curl "${AUTH[@]}" -X DELETE http://127.0.0.1:8000/api/reports/CASE_ID
```

Deletion removes the case and its application-level event history from the configured database. It does not delete backups, copies, or files outside that database.

## Stateless compatibility and canned examples

`POST /api/triage` remains available for compatibility. Send `{ "demo": "injection", "lang": "en" }` for a bundled canned result without a model call, or send `{ "report": "...", "code": "...", "lang": "en", "confirm_egress": true }` for stateless live analysis. Both calls still require the Bearer header. The persisted workflow is preferred because it separates intake, model analysis, and human review.

`GET /api/sample?kind=injection&lang=en` returns a synthetic sample input; `kind` may be `injection`, `valid`, or `noise`, and `lang` may be `en` or `ar`. This route also requires the Bearer header.

## Limits and errors

- If `MIZAN_JUDGE_TOKEN` is unset or shorter than 32 bytes, API routes fail closed with HTTP 503.
- Missing, malformed, or incorrect Bearer credentials return HTTP 401 with `WWW-Authenticate: Bearer`.
- HTTP request bodies are capped at 2 MiB.
- Report text, source context, reviewer labels, and notes have explicit character limits.
- JSON top-level values must be objects; unsupported content types and invalid workflow transitions return 4xx responses.
- Missing cases return 404; cases in an invalid state return 409.
- Provider error bodies are not exposed to the browser.
