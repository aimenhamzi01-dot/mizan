# Evaluation Protocol

## What the tests establish

The automated suite is offline and deterministic. It checks triage behavior, exact evidence-quote matching and fail-closed behavior, input/output boundaries, token authentication, role enforcement, workspace isolation, token creation/revocation/rotation, AES-GCM key storage, persistence and workflow state, safe errors, and the hard acceptance guardrails. Model calls are mocked. These tests do **not** establish that Muse Spark correctly classifies real reports, calibrates severity, or improves researcher outcomes.

Bundled results are fixed synthetic examples, not a model benchmark. Do not report their pass rate as accuracy.

The repository also includes six hand-labeled, synthetic English/Arabic regression cases in `tests/fixtures/evaluation_cases.json`. Their expected outcomes are narrow test labels for these scenarios, not universal security ground truth.

## Keep evaluation tracks separate

| Track | What runs | What the result means |
|---|---|---|
| Synthetic 100-case benchmark | `evaluation/benchmark/runner/run_benchmark.py` uses category-driven synthetic advisories; its injection check compares a regex with fixture labels | A deterministic guardrail-harness regression only. The baseline is a heuristic, not a raw LLM. Its scores are not model accuracy or per-family jailbreak coverage. |
| Offline six-fixture check | `python scripts/evaluate.py` validates the bundled synthetic fixtures and makes zero model calls | Fixture/schema and language-coverage validation only; it does not invoke triage. |
| Mocked provider contracts and automated tests | `unittest` and `pytest` exercise provider request/response/error behavior with mocked calls | Local application and contract regression only; no live Meta inference. |
| Live Meta provider evaluation | Opt-in commands below, with a configured key and explicit egress consent | A dated run on the selected synthetic cases and model configuration; it is not independent human ground truth and may incur provider charges. |
| Human reviewer evaluation | No controlled human benchmark result is recorded in this repository | Must be run and reported separately with an adjudication rubric; ordinary human review workflow is not a benchmark result. |

The dated `docs/LIVE_TEST_REPORT.md` is a local HTTP/API integration run with no provider or external-target calls. “Live server” in that report does not mean live Meta evaluation.

## Safe evaluation set

Use synthetic or explicitly authorized, sanitized reports only. Do not add unredacted bug-bounty reports, access tokens, personal data, private messages, or customer source code to this public repository. Keep expected labels separate from model output and record the rationale for each label.

| Dimension | Example | What to inspect |
|---|---|---|
| Supported claim | Synthetic handler returns private object fields without checking ownership | Does the model cite only shown evidence and identify missing route/middleware context? |
| Contradictory code | Query scopes objects to the authenticated account | Does the model distinguish the claim from supplied implementation and avoid acceptance? |
| Missing context | Authentication/reachability/impact is asserted but not shown | Does it request evidence instead of inventing it? |
| Prompt injection | Report contains instruction-like text or fake closing markers | Is it treated as untrusted report content? |
| Scanner noise | Generic output with no concrete evidence or impact | Does it ask for missing information and avoid overconfidence? |
| Citation integrity | Model quotes a real excerpt, a fabricated excerpt, and a real excerpt from the wrong input | Are exact matches verified against the stated report/code source, and are failures downgraded to `need-info`? |
| Evidence relevance | A quote exists but does not logically support the explanation | Does a human catch that literal matching is not semantic verification? |
| Multilingual input | Equivalent synthetic English and Arabic reports | Are evidence and requested response language consistent? |
| Severity calibration | Different confidentiality, integrity, and availability consequences | Is severity reasoned from stated impact? |
| Workspace isolation | Users in different test workspaces try to access one another's synthetic cases | Do list, metrics, details, history, analysis, review, and deletion remain scoped? |

## Suggested metrics

For a labeled set, calculate recommendation accuracy, confusion matrix, false-accept rate, abstention rate, quote exact-match rate, wrong-source rate, semantically irrelevant evidence rate (human-labeled), prompt-injection success rate, human-review override rate, and severity agreement. Report sample count, model identifier, prompt version, date, and configuration. Separate the deterministic string-match result from human judgments of relevance and correctness. A small synthetic set is useful for regression, not field-performance claims.

## Local evaluation harness

Run `python scripts/evaluate.py` to validate the fixture schema and bilingual coverage. This default mode is offline and makes zero model calls. Unit tests also exercise the metric calculations without network access.

To compare a configured model against the bundled synthetic labels, provide your own authorized API key through `MODEL_API_KEY`, `META_API_KEY`, or `META_MODEL_API_KEY`, then explicitly run:

```bash
python scripts/evaluate.py --live --confirm-egress --limit 1
```

Omit `--limit 1` to run the full fixture set. Each case makes at least one model request and may incur provider charges. Results contain case IDs, decisions, model/prompt metadata, and aggregate metrics, but not report or code text. Use `--output evaluation-results.json` to save the output locally; protect and delete it according to your research data policy.

The default live profile uses strict JSON Schema output and high reasoning on the latest available primary Muse Spark model. To compare reasoning budgets, repeat the same synthetic run with `META_REASONING_EFFORT=medium`; keep the model order, fixture set, prompt/schema version, and labels fixed, and compare decisions, evidence integrity, token usage, and latency. Each repeat is a new paid API run. Such a small fixture set is exploratory and cannot establish general model accuracy.

The optional cross-version challenge requires explicit authorization for its additional requests. It tries a configured Muse Spark version different from the primary model when available; it is still the same model family and is not independent verification.

```bash
python scripts/evaluate.py --live --confirm-egress --include-challenge --confirm-extra-calls --limit 1
```

The harness reports recommendation accuracy, false-accept rate on non-accept labels, code-verification agreement, prompt-injection detection recall, and exact citation-integrity rate. It does not automatically score semantic relevance, exploitability, severity calibration, or whether the hand-authored labels are correct; those require human adjudication. A small set is useful for regression and error analysis only, not a production accuracy claim.

## Running an evaluation

1. Install Mizan locally or in an isolated private environment. Run `python3 -m pip install -r requirements-dev.txt`, then `python -m unittest discover -s tests -v`, `python -m pytest -q`, and `python scripts/evaluate.py`.
2. Start Mizan and sign in with the privately generated installation-owner token.
3. Create a dedicated evaluation workspace and an analyst account. Keep the issued personal token private.
4. Ask the researcher to enter their own authorized Meta API key in the profile. The key is stored encrypted using `MIZAN_ENCRYPTION_KEY`; the researcher bears any provider usage charges.
5. Use synthetic or sanitized cases only. Each live analysis sends the selected report and source text to `META_API_BASE` after explicit consent.
6. Have a separate reviewer account record human labels. Export or analyze only protected local data; do not publish raw cases or credentials.
7. Calculate metrics from reviewed labels. Do not treat model confidence or reasoning as independent ground truth.

CI remains offline and makes no model calls or target connections. No provider credential is included in the repository; live evaluation is always an explicit user action.
