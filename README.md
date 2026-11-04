<div align="center">

<img src="assets/mizan-logo.png" alt="Mizan logo" width="250">

# Mizan

### Evidence-led security triage. Human judgment stays in control.

<p><strong>AI-assisted vulnerability review with verifiable evidence, prompt-injection awareness, and human accountability.</strong></p>

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)
[![Meta Muse Spark](https://img.shields.io/badge/AI-Meta%20Muse%20Spark-0866ff?style=for-the-badge)](https://dev.meta.ai/docs/models)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License MIT](https://img.shields.io/badge/License-MIT-2f6f62?style=for-the-badge)](LICENSE)

**Built for the [Meta Global AI Developer Hackathon 2026](https://dev.meta.ai/events/global-hackathon)**<br>
*Indie Developer Track · Build for Your World*

<br>

<a href="https://youtu.be/HWmw2o5sIv4"><img src="assets/mizan-demo-preview.png" alt="Mizan evidence-linked security triage workbench" width="900"></a>

<p>
<a href="https://youtu.be/HWmw2o5sIv4"><strong>▶ Watch the live demo</strong></a> ·
<a href="#judge-quick-start"><strong>Run the demo</strong></a> ·
<a href="https://github.com/aimenhamzi01-dot/mizan"><strong>Explore the source</strong></a>
</p>

</div>

> **Mizan uses Meta's Muse Spark to accelerate vulnerability-report triage while keeping evidence inspection and the final security decision in human hands.**

## Why Mizan

Security researchers spend valuable time sorting actionable findings from scanner noise, incomplete claims, and reports that contain instructions aimed at manipulating an AI reviewer. Mizan turns that workflow into a focused review surface built around evidence, provenance, and accountability.

It is built from firsthand security-review experience. Mizan does not replace the researcher; it helps the researcher reach a better-informed decision faster.

## The idea in one view

```text
Untrusted report + supplied code
              ↓
       Mizan + Meta Muse Spark
              ↓
 Evidence matching + context review
              ↓
     Human reviewer decision
              ↓
      Auditable disposition
```

## What makes Mizan different

<table>
<tr>
<td width="50%" valign="top">

### Evidence-linked analysis

Muse Spark returns a structured assessment with source-labelled excerpts from the report and supplied code. Mizan independently checks every quote against its stated source and calculates its location and occurrence count.

</td>
<td width="50%" valign="top">

### Prompt-injection awareness

Report content is treated as untrusted data. Instruction-like text inside a submission is inspected as part of the report rather than followed as a command.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Fail-closed review

Missing evidence, incomplete model output, contradictory code, or unverifiable citations are routed toward `need-info` instead of being presented as a confident acceptance.

</td>
<td width="50%" valign="top">

### Human accountability

The model recommendation and the authenticated reviewer's final disposition are separate records with an auditable history. The model advises; the reviewer decides.

</td>
</tr>
</table>

## How Mizan uses Meta Muse Spark

Mizan uses the Meta Model API with Muse Spark's structured JSON Schema output for security triage. The model can:

1. Extract the vulnerability claim, component, impact, and reproduction steps.
2. Identify prompt-injection attempts and scanner-style noise.
3. Assess whether supplied code supports, contradicts, or leaves the claim unverified.
4. Return source-labelled evidence, missing context, severity reasoning, and a proposed disposition.
5. Run an optional cross-version challenge pass to look for contradictions and missing assumptions.

Mizan then applies independent server-side checks to the response. Structured output makes the assessment easier to inspect; the human reviewer remains accountable for the final decision.

## Judge quick start

> **Recommended:** Docker Engine and Docker Compose v2<br>
> **Offline demo:** works without a Meta API key<br>
> **Live analysis:** can use the judge's own authorized Meta Model API key<br>
> **Permission required from the project owner:** none

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python3 scripts/run.py
```

The first run creates a private local configuration and prints an installation-owner token once. Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** and sign in with that token.

### Try the offline workflow

1. Load the built-in synthetic IDOR evidence trail.
2. Inspect the report, supplied code, source-labelled excerpts, and missing context.
3. Load the prompt-injection example and see how untrusted instructions remain inside the report boundary.
4. Record a human disposition and inspect the authenticated audit event.

### Try live Meta analysis

1. Open **Your Meta API key**.
2. Save an authorized Meta Model API key owned by the researcher.
3. Select a synthetic case and choose **Analyze with Meta**.
4. Confirm the data transfer and inspect the structured Muse Spark assessment.

No project-owner account, token, API key, or permission is required from the repository owner.

### Python-only setup

```bash
python3 -m pip install -r requirements.txt
python3 scripts/bootstrap.py
python3 server.py
```

## Three-minute judge walkthrough

| Time | What to show |
|---|---|
| **0:00–0:25** | A noisy vulnerability report containing instruction-like text. |
| **0:25–1:20** | Muse Spark's structured claim, injection warning, and evidence excerpts. |
| **1:20–2:05** | Source matching, occurrence counts, and missing-context signals. |
| **2:05–2:35** | The reviewer's disposition and authenticated audit history. |
| **2:35–3:00** | Workspaces, roles, and the optional Phantom result handoff. |

## Technical highlights

- Meta Model API integration with Muse Spark model routing and strict JSON Schema output.
- Bilingual synthetic demo coverage in English and Arabic.
- Exact source-quote matching with offsets and repeated-occurrence detection.
- Prompt-injection-safe separation of developer instructions from report and code data.
- Workspace isolation and server-side role enforcement.
- AES-GCM encryption for researcher-supplied Meta API keys.
- Local deterministic static-analysis hints that never execute submitted code.
- Optional editable import of a completed Phantom `ScanResult` as an unverified draft.
- Docker deployment, health checks, CI, and a lightweight standard-library server.

## Validation

<div align="center">

| 128 | 6 | 2 |
|:---:|:---:|:---:|
| **Automated tests passing** | **Bilingual synthetic cases** | **Review languages** |

</div>

The test suite covers triage, evidence integrity, prompt-injection boundaries, authentication, role enforcement, workspace isolation, encrypted key storage, API behavior, persistence, and safe error handling. Offline evaluation runs without provider credentials, model calls, or target connections.

## Further reading

| Guide | Purpose |
|---|---|
| [Architecture and trust boundaries](docs/ARCHITECTURE.md) | System design and data flow |
| [Evaluation protocol](docs/EVALUATION.md) | Synthetic evaluation and metrics |
| [API reference](docs/API.md) | HTTP endpoints and payloads |
| [Operations guide](docs/OPERATIONS.md) | Deployment and maintenance |
| [Security and responsible use](SECURITY.md) | Security model and responsible-use guidance |
| [Phantom integration](docs/PHANTOM_INTEGRATION.md) | Optional scanner handoff |
| [Contributing](CONTRIBUTING.md) | Development workflow |

## License

Mizan is released under the [MIT License](LICENSE).
