# Benchmark and evaluation status — corrected

**Reviewed:** 2026-11-05
**Repository base revision:** `85caff2054ae3cc48bd4573e7badd8e63227c471` (`main` before this Phase 2C change set)
**Scope:** Documentation audit, duplicate-analysis determinism, and test-runner/CI updates. No Meta provider call or human benchmark review was performed for this change set.

This report supersedes the earlier implementation narrative in this file. It separates evidence from different evaluation tracks and makes no production model-accuracy claim. Test counts are deliberately not copied here; the current runner and CI output report them for each revision.

## 1. Synthetic 100-case regression harness

The repository contains a fixed, synthetic 100-case dataset in `evaluation/benchmark/datasets/benchmark_100.json`, spanning seven categories. Its SHA-256 is `8764641f0b03b7edd769b1e35c1c68bbe24b2b1f9a8c7de0a8834dd3006d2689`.

The checked-in result artifact records `deterministic_offline_pipeline`, commit `79b75f42c05ed5152941162b363970f7b6c47874`, and timestamp `2026-11-04T10:40:15.263215Z`. Its dataset checksum matches the current fixture. A fresh in-process execution of the offline benchmark and its injection evaluator on 2026-11-05 reproduced the stored summary for that dataset; no provider was contacted and the tracked result files were not rewritten.

**Interpretation is intentionally narrow.** In `run_benchmark.py`, the purported “baseline” is a hand-coded heuristic, not a direct LLM result. The offline path constructs a synthetic model advisory from each case’s category, passes that object through normalization, and overrides its decision to `need-info` when the prompt-injection regex fires. The resulting decision is compared with the fixture’s expected outcome. Therefore, the reported perfect decision metrics are deterministic harness behavior on category-labeled synthetic cases—not empirical model accuracy, independent evidence validation, or a measurement of real-world vulnerability triage. The injection evaluator compares the regex detector with the fixtures’ injection labels and reports aggregate counts; it does not measure coverage by attack family or semantic resistance.

To inspect the harness implementation and stored historical artifact, see `evaluation/benchmark/runner/run_benchmark.py` and `evaluation/benchmark/reports/benchmark_results.json`. Running the benchmark script writes result files; review its output paths before rerunning it in a working tree.

## 2. Offline fixture validation

`python scripts/evaluate.py` is a separate, small-fixture check. It validates the six hand-authored synthetic English/Arabic fixture records and reports `mode: offline-fixture-validation` with `model_calls: 0`. It does **not** call `triage`, score live model output, or establish accuracy. The unit test `tests/test_evaluation_harness.py` also checks that the default CLI path does not invoke the model.

## 3. Mocked provider contracts and local automated tests

The standard-library `unittest` suite and the `pytest` suite exercise deterministic application behavior, persistence, authentication/authorization, evidence normalization, duplicate review aids, and provider request/response/error contracts. Provider boundaries are mocked; these tests make no live Meta inference request. Local HTTP integration tests use synthetic inputs and temporary storage, and are not provider evaluations.

The new determinism regression starts separate Python processes under several `PYTHONHASHSEED` values and compares extracted signals, similarity details, candidate order, and enriched triage output. This specifically guards against hash-order changes affecting normalization or duplicate ranking.

Current validation commands are:

```bash
python -m unittest discover -s tests -v
python -m pytest -q
python scripts/evaluate.py
```

CI installs test-only dependencies from `requirements-dev.txt`, runs both test runners, and runs the offline fixture check. The application’s runtime dependency list remains separate.

## 4. Live Meta provider evaluation

No live Meta evaluation was run for this report. The code has opt-in live evaluation paths, but the presence of a runner or an offline JSON artifact is not evidence that a live provider run occurred. A live run requires a configured personal provider key and the explicit `--live --confirm-egress` flags. It sends the selected synthetic report/code text to the configured provider and may incur charges. Record the model identifier, prompt/schema version, fixture checksum, date, usage, failures, and output artifact for any future run; report it separately from mocked tests and synthetic harness metrics.

## 5. Human reviewer evaluation

No controlled human-reviewed benchmark result is recorded here. A human disposition in ordinary product workflow is not, by itself, a benchmark. Any future human evaluation should use authorized, sanitized cases, an explicit adjudication rubric, independent review of semantic evidence relevance and outcome, and a separate record of disagreements and overrides. Do not use model labels as ground truth.

## 6. Related local service report

`docs/LIVE_TEST_REPORT.md` records a dated local HTTP/API integration run. It explicitly reports zero provider calls and zero external-target calls, so it must not be described as a live Meta evaluation. Its run-specific totals are historical evidence for that dated run, not a current, revision-independent test count.
