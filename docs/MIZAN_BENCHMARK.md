# Mizan synthetic triage regression harness

## Purpose and limits

This repository includes a synthetic regression dataset and deterministic guardrail harness for selected security-triage scenarios. It is useful for checking that known fixtures exercise the intended normalization and prompt-injection rules. It is **not** a live model benchmark, a validated security ground-truth set, or a measure of production accuracy.

All benchmark records are synthetic. The dataset has a fixed set of 100 cases across seven categories: valid-finding examples, false-positive/scanner-noise examples, unsupported evidence, prompt-injection-labeled examples, ambiguous or incomplete reports, contradictory evidence, and mixed-quality reports. The exact records and expected labels are in `evaluation/benchmark/datasets/benchmark_100.json`; validate them against `evaluation/benchmark/schemas/case.schema.json`.

## What the offline runner does

`evaluation/benchmark/runner/run_benchmark.py` has a deterministic offline path and a separately gated live-provider path. The offline path does not call Meta. It constructs a synthetic advisory from each case’s category, applies normalization and hard-coded regex injection checks, and compares the resulting decision with the fixture’s expected label. Its “baseline” decision is a heuristic, not an unguarded language-model response. Consequently, perfect values in the stored offline artifact describe this constructed test path only; they must not be presented as Mizan or Muse Spark model accuracy.

`evaluation/benchmark/runner/adversarial_eval.py` checks the prompt-injection detector against the fixture-level boolean labels and reports aggregate results. The dataset contains twenty injection-labeled records, but the evaluator does not produce measured coverage per attack family. Its named family list is not a family-level evaluation. Do not claim comprehensive jailbreak resistance from these outputs.

The stored result at `evaluation/benchmark/reports/benchmark_results.json` is a historical deterministic artifact. It records commit `79b75f42c05ed5152941162b363970f7b6c47874`, date `2026-11-04`, and dataset SHA-256 `8764641f0b03b7edd769b1e35c1c68bbe24b2b1f9a8c7de0a8834dd3006d2689`. Its checksum matches the current 100-case fixture; its metrics do not measure a live provider run.

## Separate evaluation tracks

| Track | Command or evidence | What it establishes | What it does not establish |
|---|---|---|---|
| Synthetic 100-case harness | `python evaluation/benchmark/runner/run_benchmark.py` (offline default) | Deterministic behavior of the category-driven harness on its synthetic labels | Live model accuracy, independent adjudication, semantic truth, or field performance |
| Six-case offline fixture check | `python scripts/evaluate.py` | Fixture structure/language coverage; zero model calls | A model run or triage accuracy |
| Mocked provider and application tests | `python -m unittest discover -s tests -v` and `python -m pytest -q` | Local contracts and deterministic application behavior under tests/mocks | Live Meta behavior or human agreement |
| Live provider evaluation | `python scripts/evaluate.py --live --confirm-egress --limit 1` | One explicitly authorized synthetic case sent to the configured provider | General performance or independent ground truth; provider usage may be charged |
| Human reviewer evaluation | No result is recorded in this repository | Requires a separate, documented adjudication exercise | Must not be inferred from the product’s ordinary human-review workflow |

The 100-case runner also supports live mode only with `--live --confirm-egress`; it sends the synthetic benchmark text to the configured provider. Review output paths before running: the script writes a main report and the adversarial report. Keep live artifacts separate, dated, and labeled with the model, prompt/schema version, fixture checksum, usage, and failures.

## Evidence-state note

The benchmark helper includes labels and a small state-transition utility for test examples. Those labels do not constitute an operational evidence lifecycle or proof that a real issue was reproduced, cryptographically validated, or human-confirmed. Exact quotation matching is only a string-level check; semantic relevance, exploitability, severity, and correctness require independent review.
