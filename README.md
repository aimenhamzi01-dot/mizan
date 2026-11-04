<div align="center">

<img src="assets/mizan-logo.png" alt="Mizan logo" width="260">

# Mizan

### Evidence-led security triage. Human judgment stays in control.

A self-hosted AI workbench that helps security researchers turn noisy vulnerability reports into structured, evidence-linked review decisions.

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-2f6f62.svg)](LICENSE)
[![Meta Model API](https://img.shields.io/badge/Models-Meta%20Muse%20Spark-0866ff.svg)](https://dev.meta.ai/docs/models)

**Built for the [Meta Global AI Developer Hackathon 2026](https://dev.meta.ai/events/global-hackathon)** · Indie Developer Track · *Build for Your World*

<a href="https://youtu.be/HWmw2o5sIv4"><img src="assets/mizan-demo-preview.png" alt="Mizan evidence-linked security triage workbench" width="920"></a>

[▶ Watch the live demo](https://youtu.be/HWmw2o5sIv4) · [Download the preview MP4](assets/Mizan-Hackathon-Demo.mp4) · [Explore the source](https://github.com/aimenhamzi01-dot/mizan)

</div>

> **The one-line pitch:** Mizan uses Meta's Muse Spark to accelerate vulnerability-report triage while keeping evidence inspection and the final security decision in human hands.

## Why Mizan

Security researchers spend valuable time sorting actionable findings from scanner noise, incomplete claims, and reports that contain instructions aimed at manipulating an AI reviewer. Mizan turns that workflow into a focused review surface built around evidence, provenance, and accountability.

Mizan was built from firsthand security-review experience. Its goal is not to replace the researcher. Its goal is to help the researcher reach a better-informed decision faster.

## What makes Mizan different

- **Evidence-linked analysis:** Muse Spark returns a structured assessment with source-labelled excerpts from the report and supplied code.
- **Server-verified citations:** Mizan independently checks whether each quoted excerpt exists in its stated source, calculates its location and occurrence count, and highlights it for review.
- **Prompt-injection awareness:** Report content is handled as untrusted data, so instruction-like text inside a submission is treated as evidence to inspect rather than as a command to follow.
- **Fail-closed review:** Missing evidence, incomplete model output, contradictory code, or unverifiable citations are routed toward `need-info` instead of being presented as a confident acceptance.
- **Human accountability:** The model recommendation and the authenticated reviewer's final disposition are separate records with an auditable history.
- **Research-team workflow:** Workspaces, role-based access, encrypted researcher API keys, local case intake, review metrics, and optional second-look analysis work together in one product.

## How Mizan uses Meta Muse Spark

Mizan uses the Meta Model API with Muse Spark's structured JSON Schema output for security triage. The model can:

1. Extract the reported vulnerability claim, component, impact, and reproduction steps.
2. Identify prompt-injection attempts and scanner-style noise.
3. Assess whether the supplied code supports, contradicts, or leaves the claim unverified.
4. Return source-labelled evidence, missing context, severity reasoning, and a proposed disposition.
5. Run an optional cross-version challenge pass to look for contradictions and missing assumptions.

Mizan then applies independent server-side checks to the model response. The model is an advisor; the reviewer remains the decision maker.

## Judge-ready walkthrough

The included synthetic demo is designed to be reproducible locally without a provider key or external network call:

1. Start Mizan and sign in with the installation-owner token.
2. Load the built-in IDOR evidence trail.
3. Inspect the report, supplied code, source-labelled excerpts, and missing context.
4. Load the prompt-injection example and see how untrusted instructions remain inside the report boundary.
5. Record a human disposition and inspect the authenticated audit event.

For the strongest live demonstration, add an authorized Meta API key, select a synthetic case, choose **Analyze with Meta**, and confirm the data transfer. The UI exposes the structured assessment, model metadata, evidence matches, and human-review workflow.

### Suggested three-minute demo flow

- **0:00–0:25 — The problem:** show a noisy vulnerability report containing instruction-like text.
- **0:25–1:20 — Meta reasoning:** run the case through Muse Spark and show the structured claim, injection warning, and evidence excerpts.
- **1:20–2:05 — Evidence inspection:** show source matching, occurrence counts, and missing-context signals.
- **2:05–2:35 — Human control:** record the reviewer's disposition and open the audit history.
- **2:35–3:00 — Product workflow:** show workspaces, roles, and the optional Phantom result handoff.

## Workflow at a glance

```text
Untrusted report + supplied code
              ↓
       Mizan + Muse Spark
              ↓
 Evidence matching + context review
              ↓
     Human reviewer decision
              ↓
      Auditable disposition
```

1. **Receive:** save a report and optional source snippet locally.
2. **Analyze:** explicitly authorize sending the selected case to the configured Meta endpoint.
3. **Inspect:** review the structured assessment, source-labelled evidence, and missing context.
4. **Challenge:** optionally authorize a second-look pass.
5. **Decide:** record or revise the human disposition with an authenticated audit event.

## Technical highlights

- Meta Model API integration with Muse Spark model routing and strict JSON Schema output.
- Bilingual synthetic demo coverage in English and Arabic.
- Exact source-quote matching with offsets and repeated-occurrence detection.
- Prompt-injection-safe separation of developer instructions from report and code data.
- Workspace isolation and server-side role enforcement.
- AES-GCM encryption for researcher-supplied Meta API keys.
- Local deterministic static-analysis hints that never execute submitted code.
- Optional editable import of a completed Phantom `ScanResult` as an unverified draft.
- Docker deployment, health checks, CI, and a standard-library HTTP server.

## Validation

- **128 automated tests passing** across triage, evidence integrity, prompt-injection boundaries, authentication, role enforcement, workspace isolation, encrypted key storage, API behavior, persistence, and safe error handling.
- **6 bilingual synthetic evaluation cases** covering supported claims, contradictory code, missing context, prompt injection, scanner noise, and citation integrity.
- Offline evaluation runs without model calls, provider credentials, or target connections.

## Run Mizan locally

### Docker Compose

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python3 scripts/run.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and sign in with the installation-owner token printed during first-run setup.

### Python-only mode

```bash
python3 -m pip install -r requirements.txt
python3 scripts/bootstrap.py
python3 server.py
```

The offline judge walkthrough works without a Meta API key. Live analysis uses the researcher's authorized Meta Model API key after explicit confirmation.

## Further reading

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [API reference](docs/API.md)
- [Operations guide](docs/OPERATIONS.md)
- [Security and responsible use](SECURITY.md)
- [Phantom integration](docs/PHANTOM_INTEGRATION.md)
- [Contributing](CONTRIBUTING.md)

## License

Mizan is released under the [MIT License](LICENSE).
