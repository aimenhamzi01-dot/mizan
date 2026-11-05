# Mizan Historical Evaluation Baseline Snapshot

This is a historical snapshot dated 2026-11-04, not a report of the current test suite or current evaluation quality. Earlier copies recorded inconsistent test totals; those counts are intentionally omitted. Use the test-runner and CI summaries for the exact results of a given revision.

## Date & Execution Environment
- **Date**: 2026-11-04
- **Branch**: `unified-mizan`
- **Python**: 3.12.13
- **Test-runner details**: Historical; current validation commands are maintained in `CONTRIBUTING.md` and CI.

## Architecture & Existing Capabilities
Mizan is an evidence-linked security report triage workbench and assessment platform.

### Core Components
1. **Report Triage & AI Pipeline (`triage.py`, `prompts.py`, `meta_client.py`)**:
   - Accepts untrusted vulnerability report text and optional inert source code context.
   - Invokes Meta Muse Spark using structured JSON Schema (`TRIAGE_RESPONSE_FORMAT`).
   - JSON-quotes untrusted input before prompt substitution to protect delimiter boundaries.
   - Enforces fail-closed server-side guardrails: downgrades decisions to `need-info` if citations fail exact matching, if schema is incomplete, or if code contradicts claims.
   - Supports an optional second-pass cross-version challenge pass (`CHALLENGE_RESPONSE_FORMAT`).

2. **Target & Scope Management (`security_scope.py`)**:
   - Manages authorized target domains, IPs, permitted ports, and excluded assets.
   - Enforces SSRF defense by blocking loopback, RFC 1918 private ranges, carrier-grade NAT, cloud metadata (`169.254.169.254`), multicast, and IPv6 equivalents.

3. **Reconnaissance & Scanner Engines (`recon_engine.py`, `scanner_engine.py`)**:
   - Performs passive DNS resolution (A/AAAA) and TLS certificate parsing (SANs, expiry).
   - Safe HTTP scanner evaluating security headers, cookie flags (Secure/HttpOnly/SameSite), and exposed files.

4. **Prompt Injection Defense (`prompt_defense.py`)**:
   - Heuristic pattern detection in English and Arabic for instruction overrides, persona hijacking, and delimiter escape.
   - Enforces context isolation and strict prohibition of AI autonomous tool authorization.

5. **Evidence Intelligence & Audit Trail (`evidence_engine.py`, `audit_trail.py`)**:
   - SHA-256 cryptographic hashing of normalized technical evidence.
   - Verification status tracking (verified, unverified, contradictory, insufficient).
   - Tamper-evident append-only audit trail with SHA-256 hash linking and credential redaction.

## Existing Test Coverage
- `tests/test_all.py`: Core server, triage, and client integration tests.
- `tests/test_auth_store.py`: Identity, tokens, and workspace scoping.
- `tests/test_bootstrap.py`: Startup, key generation, and configuration validation.
- `tests/test_evaluation_harness.py`: Legacy 6-case synthetic fixture evaluation.
- `tests/test_meta_client.py`: Meta API client formatting, errors, and URL safety.
- `tests/test_phantom_import.py`: Phantom scan result import and preview mapping.
- `tests/test_phantom_task.py`: Signed task manifest creation and validation.
- `tests/test_review_store.py`: SQLite persistence and migration integrity.
- `tests/test_secret_store.py`: AES-256-GCM API key encryption.
- `tests/test_static_analysis.py`: Deterministic source code heuristic checks.
- `tests/test_unified_platform.py`: Scope enforcement, evidence hashing, risk scoring, prompt injection.
- `tests/test_unified_api.py`: End-to-end REST API workflows.
- `tests/test_workbench_api.py`: Workbench role enforcement and error handling.

## Baseline Test Results

No current test count is asserted in this historical snapshot. The repository has changed since the baseline date; use the current `unittest`, `pytest`, and CI outputs for revision-specific results.

## Identified Weaknesses & Missing Evaluation Dimensions
1. **Limited Evaluation Dataset**:
   - The legacy `evaluation_cases.json` contains only 6 cases, which is insufficient for statistically significant measurement of precision, recall, F1, and false-positive rates.
2. **Missing Distinction in Evidence States**:
   - Needs explicit operational states separating `OBSERVED`, `REPRODUCIBLE`, `VALIDATED`, and `HUMAN_CONFIRMED`.
3. **Adversarial Prompt Injection Breadth**:
   - Existing checks test common keyword overrides, but need a formalized test suite covering 12 distinct attack families (e.g. delimiter smuggling, authority impersonation, nested injections, severity manipulation, multilingual attacks).
4. **DNS Rebinding & Connection Pinning in Scanner**:
   - In `scanner_engine.py`, `SafeHTTPClient` resolves the hostname for SSRF validation, but the underlying `HTTPConnection` creates a new connection using the hostname. To eliminate DNS rebinding risks, the connection must pin to the validated IP directly with the `Host` header set.
5. **No Direct Model vs Pipeline Comparative Benchmark**:
   - Prior evaluations only evaluated whether the final output had valid fields, without comparing raw unverified model output vs the full Mizan guardrail pipeline on identical inputs.

## Historical Plan of Action

The original baseline proposed a 100-case suite, adversarial runner, evidence evaluator, and model comparison. The repository now contains synthetic regression artifacts, but their deterministic category-driven output is not an empirical model comparison. Live-provider evaluation and controlled human adjudication remain separate activities and are not evidenced by this baseline document.
