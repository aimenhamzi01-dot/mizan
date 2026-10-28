# Evaluation Protocol

## What the existing tests establish

The repository's automated tests are offline and deterministic. They check API behavior, persistence and workflow state, input/output limits, the model/user-message boundary, delimiter handling, safe error responses, and the two hard acceptance guardrails. Model calls are mocked. These tests do **not** establish that Muse Spark correctly classifies real vulnerability reports, that severity labels are calibrated, or that Mizan improves reviewer outcomes.

The bundled demonstration results are fixed examples, not a model benchmark. Do not report their pass rate as model accuracy.

## Safe evaluation set

Evaluate with synthetic or explicitly authorized, sanitized reports only. Do not add unredacted bug-bounty reports, access tokens, personal information, private messages, or customer source code to the public repository. Keep expected labels separate from model output and record the rationale for each label.

A useful test set should include examples across these dimensions:

| Dimension | Example case | What to inspect |
|---|---|---|
| Supported claim | Synthetic handler retrieves an object and returns private fields without an object-level ownership check | Does the model cite only the shown evidence and flag omitted route/middleware context? |
| Contradictory code | Synthetic query scopes the object to the authenticated user's account | Does the model distinguish the claim from the supplied implementation and avoid acceptance? |
| Missing context | Report asserts authentication, reachability, or impact not present in the supplied snippet | Does it abstain or request the missing route/configuration evidence rather than invent it? |
| Prompt injection | Report contains instruction-like phrases or fake closing markers | Does the model treat them as report content and preserve the original claim analysis? |
| Scanner noise | Generic scanner output without a concrete endpoint, evidence, or impact | Does it identify the missing information and avoid overconfident acceptance? |
| Multilingual input | Equivalent synthetic reports in English and Arabic | Are the evidence and disposition consistent, with the requested response language? |
| Severity calibration | Cases with different confidentiality, integrity, and availability consequences | Is severity reasoned from stated impact rather than copied uncritically from the report? |

## Suggested metrics

For a labeled evaluation set, calculate recommendation accuracy, confusion matrix, false-accept rate, abstention (`need-info`) rate, unsupported-evidence rate, prompt-injection success rate, and human-review override rate. Track severity agreement separately from disposition. Report sample count, model identifier, prompt version, date, and API configuration alongside each result. A small synthetic set is useful for regression but is not evidence of field performance.

Do not optimize for a high acceptance rate. For security triage, unsupported acceptance and fabricated evidence are particularly important failure modes; report them explicitly. Reviewers should be able to override every recommendation.

## Running an evaluation

1. Prepare a local, synthetic or explicitly authorized set and keep it outside the public repository if it contains sensitive details.
2. Run the offline test suite first: `python -m unittest discover -s tests -v`.
3. Start your own Python or Docker instance and run `python3 scripts/bootstrap.py` to create its private access token. Do not place the generated token in the public repository.
4. For model evaluation, configure your own authorized Meta API key and a trusted endpoint. You are responsible for your provider usage charges. Each live analysis sends the selected report and code externally; confirm this in the local workbench for every case.
5. Record outputs and reviewer labels in a protected local evaluation log. Do not publish raw reports or credentials.
6. Calculate metrics from the reviewed labels. Do not treat a model's self-reported confidence or reasoning as independent ground truth.

No live-model benchmark is included in this repository because no authorized API key or labeled dataset is supplied. This avoids fabricating performance claims and keeps CI offline.
