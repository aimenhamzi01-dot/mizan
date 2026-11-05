# Synthetic security-triage regression dataset

This directory contains a deterministic, synthetic fixture set for exercising selected Mizan triage guardrails. It is a regression harness, **not** a live-model benchmark or a source of production accuracy claims.

## Dataset

`datasets/benchmark_100.json` contains 100 synthetic cases across seven fixture categories. The dataset SHA-256 recorded by the checked-in result artifact is `8764641f0b03b7edd769b1e35c1c68bbe24b2b1f9a8c7de0a8834dd3006d2689`. Validate the format with `schemas/case.schema.json`. `datasets/generate_cases.py` generates the fixture records.

## Offline runner semantics

Run `python evaluation/benchmark/runner/run_benchmark.py` for the deterministic offline path. It makes no provider request. The runner synthesizes a model-advisory object from each fixture’s category, passes it through Mizan normalization, and compares the result with the fixture label. Its comparison “baseline” is a keyword/regex heuristic rather than a raw LLM. The reported scores therefore describe this constructed harness path only, not actual model decisions or empirical security accuracy.

`runner/adversarial_eval.py` checks the prompt-defense regex against the cases’ injection labels and returns aggregate counts. It does not assess attack-family coverage or semantic jailbreak resistance. The checked-in files under `reports/` are historical outputs, not evidence of a live model run. The main result records commit `79b75f42c05ed5152941162b363970f7b6c47874` and the dataset SHA-256 above.

The benchmark runner writes output files. `--output` changes the main report path, but the adversarial report is always written to `evaluation/benchmark/reports/prompt_injection_results.json`; rerunning the script can overwrite that tracked file.

## Other evaluation tracks

- `python scripts/evaluate.py` validates a separate six-case synthetic bilingual fixture set and makes zero model calls; it does not run triage.
- `python -m unittest discover -s tests -v` and `python -m pytest -q` run local automated tests. Provider calls in these tests are mocked.
- A live Meta evaluation requires an authorized key and explicit `--live --confirm-egress`. It sends selected synthetic report/code text to the configured provider and may incur charges. No live result is included here.
- No controlled human-review benchmark result is recorded. Human assessment of semantic evidence relevance, severity, and ground truth must be reported separately.

See `docs/MIZAN_BENCHMARK.md`, `docs/EVALUATION.md`, and `docs/BENCHMARK_FINAL_REPORT.md` for the distinctions and limitations.
