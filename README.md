<div align="center">
<img src="assets/mizan-logo.png" alt="Mizan logo" width="230">

# Mizan

### Turn uncertain vulnerability reports into reviewable security decisions.

<p><strong>Meta Muse Spark + evidence provenance + human accountability.</strong></p>

[![Tests](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml/badge.svg)](https://github.com/aimenhamzi01-dot/mizan/actions/workflows/tests.yml)
[![Meta Muse Spark](https://img.shields.io/badge/Powered%20by-Meta%20Muse%20Spark-0866ff?style=for-the-badge)](https://dev.meta.ai/docs/models)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License MIT](https://img.shields.io/badge/License-MIT-2f6f62?style=for-the-badge)](LICENSE)

**Built for the [Meta Global AI Developer Hackathon 2026](https://dev.meta.ai/events/global-hackathon)**<br>
*Indie Developer Track · Build for Your World*

<a href="https://youtu.be/HWmw2o5sIv4"><img src="assets/mizan-demo-preview.png" alt="Mizan evidence-linked security triage workbench" width="900"></a>

<p>
<a href="https://youtu.be/HWmw2o5sIv4"><strong>▶ Watch the 3-minute demo</strong></a> ·
<a href="#judge-quick-start"><strong>Run the offline demo</strong></a> ·
<a href="https://github.com/aimenhamzi01-dot/phantom"><strong>Explore Phantom, the evidence worker</strong></a>
</p>
</div>

> **Mizan is a human-led security review workbench. Muse Spark accelerates reasoning; Mizan makes the evidence inspectable; the reviewer owns the decision.**

## The 20-second idea

Security teams receive reports that mix real clues, scanner noise, missing context, and text designed to steer an AI reviewer. Mizan turns that uncertainty into a structured review path:

```text
Untrusted report + supplied code
              ↓
       Meta Muse Spark analysis
              ↓
 Evidence quotes checked by Mizan
              ↓
  Reviewer decision + audit history
```

The result is not a black-box verdict. It is a decision that a researcher can inspect, challenge, and explain.

## Why this is different

### Evidence before confidence
Muse Spark returns a structured claim, impact, severity reasoning, missing context, and source-labelled evidence. Mizan independently matches every quote to the report or code, calculates its location and occurrence count, and makes the evidence visible beside the recommendation.

### Prompt-injection aware by design
A vulnerability report is data, not instructions. Report text and source code are JSON-quoted inside a separate model input boundary. Instruction-like text is analyzed as part of the submission instead of becoming a command for the reviewer.

### Human judgment stays in control
The model recommendation, the authenticated human disposition, and the audit trail are separate records. Mizan helps a researcher decide faster without pretending that literal text matching or model confidence proves exploitability.

### Built for real security workflows
Mizan includes workspaces, roles, encrypted researcher-owned Meta API keys, server-side authorization, offline synthetic cases, bilingual English/Arabic examples, local heuristic analysis, and an optional signed handoff to [Phantom](https://github.com/aimenhamzi01-dot/phantom).

## The Mizan + Phantom evidence loop

[Phantom](https://github.com/aimenhamzi01-dot/phantom) is Mizan's bounded evidence worker. It can collect authorized HTTPS/DNS/TLS context and run optional Semgrep checks on an authorized source URL. It returns a signed, provenance-rich result; Mizan imports it as reviewable evidence, never as an automatic verdict.

```text
Mizan creates a signed task
          ↓
Phantom collects bounded evidence
          ↓
Muse Spark organizes the evidence
          ↓
Mizan checks provenance and presents the case
          ↓
Human reviewer records the final disposition
```

The integration contract is explicit and versioned:

- [`mizan-phantom-task-v1`](schemas/mizan-phantom-task-v1.schema.json)
- [`phantom-scan-result-v1`](schemas/phantom-scan-result-v1.schema.json)

## How Meta Muse Spark is used

Mizan uses the Meta Model API with Muse Spark structured JSON Schema output to:

1. Extract the claim, component, impact, reproduction steps, and missing context.
2. Identify prompt-injection attempts and scanner-style noise.
3. Compare the claim with supplied code as supporting, contradictory, or unverifiable.
4. Return source-labelled evidence and a proposed disposition.
5. Optionally run a separately confirmed cross-version challenge pass for contradictions.

Mizan then applies independent server-side guardrails. Incomplete output, fabricated citations, contradictory code, and unsupported acceptance recommendations are routed toward `need-info` for human review.

## Judge quick start

The offline demo is designed for a judge who wants to see the product before configuring a provider key.

```bash
git clone https://github.com/aimenhamzi01-dot/mizan.git
cd mizan
python3 scripts/run.py
```

Open **http://127.0.0.1:8000**, sign in with the one-time owner token printed by the launcher, and choose a built-in case. The offline path demonstrates the complete review loop without model credentials or target access:

1. Load the **Prompt-injection case** or **IDOR evidence trail**.
2. Inspect the structured claim, source quotes, missing context, and decision guardrails.
3. Load the bilingual Arabic example to see the same evidence-led workflow in Arabic.
4. Record a human disposition and open the authenticated audit history.

For live analysis, save an authorized Meta Model API key in the profile, select a case, and explicitly confirm the egress. The key is encrypted at rest and is never returned to the browser.

### Python-only setup

```bash
python3 -m pip install -r requirements.txt
python3 scripts/bootstrap.py
python3 server.py
```

## Three-minute judge walkthrough

**0:00–0:20 — The problem.** Show a noisy report containing a fake instruction aimed at the AI reviewer.

**0:20–1:05 — The intelligence.** Run Muse Spark and show the extracted claim, injection signal, missing context, and structured evidence.

**1:05–1:40 — The proof.** Jump from an evidence quote to its exact source location. Show a repeated or fabricated quote being treated as unverified.

**1:40–2:20 — The judgment.** Show the model suggestion beside a human disposition and the authenticated audit event.

**2:20–2:45 — The extension.** Show a signed Phantom task and a provenance-rich imported result.

**2:45–3:00 — The promise.** Close on the principle: faster security review, inspectable evidence, human accountability.

## Technical highlights

- Meta Model API integration with Muse Spark routing and strict JSON Schema output.
- Server-side evidence matching with offsets, occurrence counts, and visible provenance.
- Prompt-injection-safe separation of developer instructions from report and code data.
- Fail-closed recommendations when evidence or model structure is incomplete.
- Human and model decisions stored separately with authenticated audit events.
- Workspace isolation, role enforcement, bearer-token rotation, and encrypted personal Meta keys.
- English and Arabic synthetic demo cases with a path to RTL presentation.
- Deterministic local static-analysis hints that never execute submitted code.
- Signed Mizan → Phantom task handoff and versioned result schemas.
- Docker deployment, health checks, CI, and a lightweight standard-library server.

## Validation

| 128 | 6 | 2 |
|:---:|:---:|:---:|
| **Automated tests passing** | **Bilingual synthetic cases** | **Review languages** |

The suite covers evidence integrity, prompt-injection boundaries, authentication, authorization, workspace isolation, encrypted key storage, API behavior, persistence, Phantom import, and safe failure handling. The offline evaluator is intentionally deterministic and makes zero provider calls.

The project team has also exercised Mizan on real security-review workflows and reports strong practical results. Those field trials are the reason the product is designed around evidence inspection, explicit human disposition, and an auditable history rather than a single opaque model score.

## Explore the build

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [API reference](docs/API.md)
- [Operations guide](docs/OPERATIONS.md)
- [Mizan–Phantom integration](docs/PHANTOM_INTEGRATION.md)
- [Phantom repository](https://github.com/aimenhamzi01-dot/phantom)
- [Security and responsible use](SECURITY.md)

## License

Mizan is released under the [MIT License](LICENSE).
