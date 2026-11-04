# Mizan 100-Case Security Benchmark Suite

## Overview
This benchmark suite provides an objective, reproducible evaluation dataset to measure whether Mizan can:
1. Accurately validate genuine technical security findings backed by code evidence.
2. Filter out automated scanner false positives and misclassifications.
3. Detect missing or fabricated evidence excerpts.
4. Resiliently defend against adversarial prompt injection attempts across 12 attack vectors (in English and Arabic).
5. Escalate ambiguous, incomplete, or mixed-quality reports to human-in-the-loop triage (`need-info`).
6. Reject reports directly disproved by supplied source code context.

## Dataset Structure
Total Cases: Exactly 100 cases in `evaluation/benchmark/datasets/benchmark_100.json`.
- **Valid Security Findings (`valid_finding`)**: 20 cases (MIZAN-001 – MIZAN-020)
- **False Positive Reports (`false_positive`)**: 15 cases (MIZAN-021 – MIZAN-035)
- **Unsupported/Fabricated Evidence (`unsupported_evidence`)**: 15 cases (MIZAN-036 – MIZAN-050)
- **Prompt Injection Attacks (`prompt_injection`)**: 20 cases (MIZAN-051 – MIZAN-070)
- **Ambiguous/Incomplete Reports (`ambiguous_incomplete`)**: 10 cases (MIZAN-071 – MIZAN-080)
- **Contradictory Evidence (`contradictory_evidence`)**: 10 cases (MIZAN-081 – MIZAN-090)
- **Mixed-Quality Reports (`mixed_quality`)**: 10 cases (MIZAN-091 – MIZAN-100)

## Validation Schema
Defined in `evaluation/benchmark/schemas/case.schema.json`.

## Ethical Safeguards
- All 100 test cases are synthetic.
- No real credentials, private tokens, or real user identifiers are used.
- All adversarial prompt injection payloads are inert test fixtures that are never executed as system commands.
- Offline evaluation mode requires zero external network connections or API keys.
