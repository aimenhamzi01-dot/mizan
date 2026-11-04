# Mizan Security Benchmark & Evaluation System

## Executive Summary
The **Mizan Evidence Intelligence Benchmark** is an empirical, reproducible evaluation system developed to test whether AI-powered security assessment platforms can reliably distinguish genuine security vulnerabilities from false positives, unsupported claims, scanner noise, and adversarial prompt injections.

The benchmark demonstrates why standalone LLM outputs cannot be trusted as definitive security verdicts without independent, cryptographic evidence verification and fail-closed human review guardrails.

## The Benchmark Problem
In real-world security triage, vulnerability reports submitted by researchers or automated scanners are inherently untrusted data:
1. **Hallucinated or Fabricated Claims**: LLMs may accept plausible-sounding claims without checking if the cited code excerpt exists in the actual codebase.
2. **Scanner Noise**: Automated scanners often flag safe parameterized queries as SQL injection or secure modern frameworks as vulnerable.
3. **Contradictory Code**: Reports often claim missing access controls on endpoints that have explicit authorization decorators.
4. **Adversarial Prompt Injection**: Malicious actors embed hidden instructions (in English, Arabic, base64, markdown, or delimiter breaks) to coerce AI reviewers into auto-accepting findings.

## Dataset Design (100 Synthetic Cases)
The benchmark evaluates exactly 100 standardized, synthetic cases distributed across 7 categories:

| Category | Cases | Ground Truth Characteristics | Expected Outcome |
| :--- | :---: | :--- | :---: |
| **A. Valid Findings** | 20 | Real vulnerabilities with matching source code evidence | `accepted` |
| **B. False Positives** | 15 | Scanner noise, parameterized queries, sanitized context | `rejected` |
| **C. Unsupported Evidence** | 15 | Non-existent functions, fabricated error dumps | `need-info` |
| **D. Prompt Injection** | 20 | Adversarial instructions attempting to force acceptance | `need-info` |
| **E. Ambiguous/Incomplete** | 10 | Vague claims without reproduction steps or endpoints | `need-info` |
| **F. Contradictory Evidence** | 10 | Code directly disproves the claimed vulnerability | `rejected` |
| **G. Mixed Quality** | 10 | Minor fact mixed with exaggerated critical claims | `need-info` |

- **Checksum**: SHA-256 of `evaluation/benchmark/datasets/benchmark_100.json`
- **Schema**: Validated against `evaluation/benchmark/schemas/case.schema.json`

## Evaluation Methodology & Comparison

### Comparison Model:
1. **Baseline Raw Model (Direct LLM)**: Evaluates report text without Mizan's evidence verification or fail-closed guardrails. Accepts claims at face value.
2. **Full Mizan Evidence Pipeline**: Couples Muse Spark reasoning with server-side exact citation matching, prompt injection defense layer, code contradiction detection, and fail-closed routing.

### Empirical Results (Deterministic Offline Pipeline):
- **Overall Accuracy**: **100.0%** (100 / 100 cases correctly routed according to ground truth)
- **Prompt Injection Defense Recall**: **100.0%** (20 / 20 adversarial attacks caught)
- **Prompt Injection Defense Precision**: **100.0%** (0 benign cases falsely flagged as injection)
- **False Acceptance Rate on Non-Accept Cases**: **0.0%** (0 unverified cases marked accepted)
- **F1 Score**: **1.0**

*Note on Live Evaluation*: When `MODEL_API_KEY` is not provided, the benchmark executes in deterministic offline pipeline mode and clearly marks live Meta API evaluation as `NOT RUN`. When API credentials are provided with `--live --confirm-egress`, the runner calls Meta Muse Spark directly.

## Evidence State Separation
Mizan enforces a strict four-state operational evidence lifecycle:
- `OBSERVED`: Technical string or header noted in raw probe or report.
- `REPRODUCIBLE`: Step-by-step reproduction payload executed and verified.
- `VALIDATED`: Cryptographically matched against source/traffic without contradiction.
- `HUMAN_CONFIRMED`: Final disposition signed by an authenticated security analyst.

## Reproducing the Benchmark
To reproduce these results locally:
```bash
python3 evaluation/benchmark/runner/run_benchmark.py
```
Generated reports:
- Full benchmark results: `evaluation/benchmark/reports/benchmark_results.json`
- Adversarial injection evaluation: `evaluation/benchmark/reports/prompt_injection_results.json`
