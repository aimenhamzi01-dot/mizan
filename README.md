# Mizan

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)

**Mizan is an AI-assisted security-report triage prototype.** It reads an inbound vulnerability report and optional pasted source code, flags prompt-injection attempts in the report, reasons about whether the claim is supported by the supplied code, and proposes a decision with evidence and a draft reply. A human reviewer always makes the final decision.

Built for the **Meta Global AI Developer Hackathon 2026**, Indie Developer Track, under **Build for Your World**.

## Safety and scope

- **Read and reason only:** Mizan does not execute submitted code, commands, exploits, or proof-of-concept steps. It does not test a vulnerability against a target system.
- **Untrusted report separation:** The report is passed as untrusted user data in a separate message, not merged into the system instructions. The test suite includes a check for this separation.
- **Hard decision guardrails:** `triage.normalize()` changes an `accept` recommendation to `reject` when the supplied code contradicts the claim, and to `need-info` for a raw `scanner-dump` report.
- **Human decision required:** Recommendations are not automatically applied or sent to a program or reporter.
- **External API disclosure:** Demo examples work locally without an API key. For live triage, the report and optional code are sent to the configured Meta Model API. Do not submit sensitive data unless you are authorized to share it with that service.
- **Local prototype:** The included HTTP server binds to `127.0.0.1` by default and has no production authentication or deployment hardening. Do not expose it to an untrusted network.

Mizan is a prototype, not a replacement for security review, vulnerability validation, or a bug-bounty program's policies. Its sample cases are illustrative and are not evidence of real-world detection accuracy.

## Features

- English-first interface with an optional Arabic language toggle.
- Three built-in demonstrations: a prompt-injection attempt, a code-supported report, and a raw scanner dump. These return canned results and do not require an API key.
- Structured recommendations: `accept`, `need-info`, `duplicate`, or `reject`, with claim details, code-verification status, severity reasoning, evidence, detected injection phrases, and a draft response.
- Request size limits and response normalization in the triage path.
- A standard-library-only Python server and client; no third-party Python packages are required.

## Quick start

**Requirements:** Python 3.9 or newer. No `pip install` step is needed.

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
cp .env.example .env
```

Edit `.env` and replace the placeholder with an API key you are authorized to use:

```dotenv
MODEL_API_KEY=your_meta_api_key
```

Then start the local server:

```bash
python server.py
```

Open <http://127.0.0.1:8000>. The built-in sample buttons work without an API key. Submitting a custom report for live model triage requires a configured key.

Never commit `.env` or put a real API key in source files. `.env` is ignored by Git; `.env.example` contains only a placeholder.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `MODEL_API_KEY` | API key; `META_API_KEY` and `META_MODEL_API_KEY` are also accepted | Unset |
| `META_API_BASE` | OpenAI-compatible Meta Model API base URL | `https://api.meta.ai/v1` |
| `META_MODEL` | Comma-separated model names tried in order | `muse-spark-1.3,muse-spark-1.1` |
| `PORT` | Local HTTP server port | `8000` |
| `META_REASONING_EFFORT` | Optional reasoning-effort value passed through to the API | Unset |

These values can be placed in the local `.env` file or supplied as environment variables. Model availability depends on the API account and service configuration.

## How it works

1. The browser sends a report, optional code, and selected response language to `POST /api/triage`.
2. `triage.py` builds separate system and user messages. The report is explicitly marked as untrusted content; supplied code is included as read-only context.
3. In live mode, `meta_client.py` sends those messages to the configured Meta Model API. It does not contact the reported target or execute the supplied code.
4. The model returns structured fields. `triage.normalize()` constrains their shape and applies the hard decision guardrails.
5. The interface presents the recommendation, evidence, injection findings, and draft reply for a human reviewer.

The server also provides `GET /api/health` and `GET /api/sample`. The sample endpoint serves canned examples; it does not call the model.

## Tests and CI

Run the full test suite locally:

```bash
python -m unittest discover -s tests -v
```

The tests cover normalization guardrails, request validation, sample and server behavior, mocked model responses, injection handling, and separation of report data from system instructions. GitHub Actions runs the test suite on every push and pull request; no API key or live model call is required for the tests.

## Repository map

| Path | Purpose |
|---|---|
| `server.py` | Local HTTP server and API routes |
| `meta_client.py` | Meta Model API client |
| `prompts.py` | System and user message templates, including the untrusted-report boundary |
| `triage.py` | Triage request flow, output normalization, and hard decision guardrails |
| `demo_data.py` | English and Arabic canned demonstrations |
| `static/index.html` | English-first, bilingual triage interface |
| `tests/test_all.py` | Unit and local HTTP-server tests |
| `.github/workflows/tests.yml` | GitHub Actions test workflow |

## License

This project is distributed under the [MIT License](LICENSE).
