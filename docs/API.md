# Local API Guide

The API is served by `python server.py` on `http://127.0.0.1:8000`. It has no authentication and is not designed for public or multi-user use. It checks local `Host` and browser `Origin` values. Examples use loopback only. Do not change the host to a vulnerability target. JSON request bodies must use `Content-Type: application/json`.

## Health and queue

```bash
curl http://127.0.0.1:8000/api/health
curl 'http://127.0.0.1:8000/api/reports?status=received&limit=25'
curl http://127.0.0.1:8000/api/metrics
```

The health response includes `ok`, a boolean `has_key`, and the storage type. It never returns the key. List results are bounded summaries; they do not include full report or source-code bodies. Metrics contain counts only.

## Save a report locally

Saving is local and makes no model request:

```bash
curl -X POST http://127.0.0.1:8000/api/reports \
  -H 'Content-Type: application/json' \
  -d '{"report":"Synthetic report text","code":"def example(): pass","lang":"en"}'
```

The returned `report.id` is a UUID. The new case has `status: "received"`, `analysis: null`, and `review_decision: null`.

## Request an AI recommendation

This workflow route sends report/code to the configured Meta Model API. In the UI, it is preceded by an explicit confirmation; the API also requires the exact boolean `confirm_egress: true` so a caller cannot accidentally trigger egress with an empty request body. This flag is an explicit intent signal, not authentication; only use the local trusted interface:

```bash
curl -X POST http://127.0.0.1:8000/api/reports/CASE_ID/analyze \
  -H 'Content-Type: application/json' -d '{"confirm_egress":true}'
```

The result stores an `analysis` and `suggested_decision`; it does not set a final human disposition. A model key must be configured. If the model call fails, the report remains stored and the browser receives a sanitized error.

## Record a human disposition

A case must have an analysis before recording a review. The decision is an explicit human choice and remains separate from the suggestion:

```bash
curl -X POST http://127.0.0.1:8000/api/reports/CASE_ID/review \
  -H 'Content-Type: application/json' \
  -d '{"decision":"need-info","reviewer":"Reviewer A","note":"Check the route-level authorization before confirming."}'
```

Valid decisions are `accept`, `need-info`, `duplicate`, and `reject`. Reviews are recorded in the local event history. No ticket or message is sent.

## Read and delete a case

```bash
curl http://127.0.0.1:8000/api/reports/CASE_ID
curl http://127.0.0.1:8000/api/reports/CASE_ID/history
curl -X DELETE http://127.0.0.1:8000/api/reports/CASE_ID
```

Deletion removes the case and its application-level event history from the configured database. It does not delete backups, copies, or files outside that database.

## Stateless compatibility and canned examples

`POST /api/triage` remains available for compatibility. Send `{ "demo": "injection", "lang": "en" }` for a bundled canned result without a model call, or send `{ "report": "...", "code": "...", "lang": "en", "confirm_egress": true }` to request stateless live analysis. The persisted workflow is preferred because it separates intake, model analysis, and human review.

`GET /api/sample?kind=injection&lang=en` returns a built-in sample input; `kind` may be `injection`, `valid`, or `noise`, and `lang` may be `en` or `ar`.

## Limits and errors

- HTTP request bodies are capped at 2 MiB.
- Report text, source context, reviewer labels, and notes have explicit character limits.
- JSON top-level values must be objects; unsupported content types and invalid workflow transitions return 4xx responses.
- Missing cases return 404; cases in an invalid state return 409.
- Provider error bodies are not exposed to the browser.
