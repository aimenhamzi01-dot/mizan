# Evaluation Protocol

## What the tests establish

The automated suite is offline and deterministic. It checks triage behavior, input/output boundaries, token authentication, role enforcement, workspace isolation, token creation/revocation/rotation, AES-GCM key storage, persistence and workflow state, safe errors, and the hard acceptance guardrails. Model calls are mocked. These tests do **not** establish that Muse Spark correctly classifies real reports, calibrates severity, or improves researcher outcomes.

Bundled results are fixed synthetic examples, not a model benchmark. Do not report their pass rate as accuracy.

## Safe evaluation set

Use synthetic or explicitly authorized, sanitized reports only. Do not add unredacted bug-bounty reports, access tokens, personal data, private messages, or customer source code to this public repository. Keep expected labels separate from model output and record the rationale for each label.

| Dimension | Example | What to inspect |
|---|---|---|
| Supported claim | Synthetic handler returns private object fields without checking ownership | Does the model cite only shown evidence and identify missing route/middleware context? |
| Contradictory code | Query scopes objects to the authenticated account | Does the model distinguish the claim from supplied implementation and avoid acceptance? |
| Missing context | Authentication/reachability/impact is asserted but not shown | Does it request evidence instead of inventing it? |
| Prompt injection | Report contains instruction-like text or fake closing markers | Is it treated as untrusted report content? |
| Scanner noise | Generic output with no concrete evidence or impact | Does it ask for missing information and avoid overconfidence? |
| Multilingual input | Equivalent synthetic English and Arabic reports | Are evidence and requested response language consistent? |
| Severity calibration | Different confidentiality, integrity, and availability consequences | Is severity reasoned from stated impact? |
| Workspace isolation | Users in different test workspaces try to access one another's synthetic cases | Do list, metrics, details, history, analysis, review, and deletion remain scoped? |

## Suggested metrics

For a labeled set, calculate recommendation accuracy, confusion matrix, false-accept rate, abstention rate, unsupported-evidence rate, prompt-injection success rate, human-review override rate, and severity agreement. Report sample count, model identifier, prompt version, date, and configuration. A small synthetic set is useful for regression, not field-performance claims.

## Running an evaluation

1. Install Mizan locally or in an isolated private environment. Run `python3 -m pip install -r requirements.txt` and `python -m unittest discover -s tests -v`.
2. Start Mizan and sign in with the privately generated installation-owner token.
3. Create a dedicated evaluation workspace and an analyst account. Keep the issued personal token private.
4. Ask the researcher to enter their own authorized Meta API key in the profile. The key is stored encrypted using `MIZAN_ENCRYPTION_KEY`; the researcher bears any provider usage charges.
5. Use synthetic or sanitized cases only. Each live analysis sends the selected report and source text to `META_API_BASE` after explicit consent.
6. Have a separate reviewer account record human labels. Export or analyze only protected local data; do not publish raw cases or credentials.
7. Calculate metrics from reviewed labels. Do not treat model confidence or reasoning as independent ground truth.

No live-model benchmark is included because the repository contains neither a labeled dataset nor an authorized provider credential. CI remains offline and makes no target connections.
