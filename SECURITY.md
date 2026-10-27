# Security & Responsible Use

Mizan is a **read-only triage assistant**. It reads a report's text and, optionally,
related source code, and produces a proposed decision with evidence. It never:

- executes, runs, or simulates running any code, command, exploit, or proof of concept
- contacts any external system, target, or API other than the Meta Model API
- auto-applies a decision — every output is a recommendation for a human reviewer

The untrusted report text is always passed to the model inside a clearly fenced
user-message block, separate from the system instructions, and the model is
explicitly told to treat any instructions embedded in the report as data, not
commands. `tests/test_all.py` includes an automated check for this isolation.

If you plan to extend this project with automated verification against a live
target, that is **out of scope for this codebase** and should not reuse this
code as a base, since it was deliberately built to avoid that capability.

## Reporting a vulnerability in Mizan itself

Open an issue on this repository, or contact the maintainer directly for
anything sensitive.
