"""Small offline heuristic source-code checks for Mizan.

This module treats submitted source as inert text. It never imports or executes
it, spawns a process, fetches dependencies, or contacts a target. Findings are
review leads, not proof that a vulnerability is exploitable.
"""
from __future__ import annotations

import hashlib
import re

SUPPORTED_LANGUAGES = {"auto", "python", "javascript", "typescript", "java", "go", "php", "ruby", "csharp", "generic"}
MAX_SOURCE_CHARS = 40_000
MAX_FINDINGS = 100

_RULES = [
    {
        "id": "MIZAN-PY-EVAL",
        "languages": {"python"},
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "title": "Dynamic code evaluation",
        "severity": "high",
        "confidence": "medium",
        "cwe": "CWE-95",
        "description": "Dynamic evaluation can become code execution when input is attacker-controlled. Review the value's origin and all surrounding safeguards.",
    },
    {
        "id": "MIZAN-PY-SHELL-TRUE",
        "languages": {"python"},
        "pattern": re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(.*\bshell\s*=\s*True\b"),
        "title": "Shell execution enabled in subprocess",
        "severity": "high",
        "confidence": "medium",
        "cwe": "CWE-78",
        "description": "shell=True can make command construction unsafe when data is untrusted. Review argument provenance and whether a fixed executable with an argument list can be used.",
    },
    {
        "id": "MIZAN-PY-UNSAFE-PICKLE",
        "languages": {"python"},
        "pattern": re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "title": "Deserialization with pickle",
        "severity": "high",
        "confidence": "medium",
        "cwe": "CWE-502",
        "description": "Unpickling attacker-controlled data can execute code. Determine whether the serialized input is trusted and authenticated.",
    },
    {
        "id": "MIZAN-SQL-FSTRING",
        "languages": {"python"},
        "pattern": re.compile(r"\.(?:execute|executemany)\s*\(\s*f[\"']"),
        "title": "Possible SQL query interpolation",
        "severity": "medium",
        "confidence": "low",
        "cwe": "CWE-89",
        "description": "An f-string appears to be passed to a database execution method. Confirm whether untrusted values are interpolated; parameterized queries are generally safer.",
    },
    {
        "id": "MIZAN-JS-EVAL",
        "languages": {"javascript", "typescript"},
        "pattern": re.compile(r"\beval\s*\("),
        "title": "Dynamic JavaScript evaluation",
        "severity": "high",
        "confidence": "medium",
        "cwe": "CWE-95",
        "description": "Dynamic evaluation can become code execution when input is attacker-controlled. Review the source of the evaluated value.",
    },
    {
        "id": "MIZAN-JS-INNERHTML",
        "languages": {"javascript", "typescript"},
        "pattern": re.compile(r"\.innerHTML\s*="),
        "title": "HTML inserted through innerHTML",
        "severity": "medium",
        "confidence": "low",
        "cwe": "CWE-79",
        "description": "innerHTML is a potential DOM-XSS sink if attacker-controlled markup reaches it. Verify data flow and sanitization before drawing a conclusion.",
    },
    {
        "id": "MIZAN-JS-CHILD-PROCESS",
        "languages": {"javascript", "typescript"},
        "pattern": re.compile(r"\bchild_process\.(?:exec|execSync)\s*\("),
        "title": "Shell-based child process execution",
        "severity": "high",
        "confidence": "medium",
        "cwe": "CWE-78",
        "description": "Shell-based process execution is risky when command text contains untrusted values. Review construction and consider fixed commands with argument arrays.",
    },
    {
        "id": "MIZAN-TLS-VERIFY-OFF",
        "languages": {"python", "javascript", "typescript", "java", "go", "php", "ruby", "csharp", "generic"},
        "pattern": re.compile(r"(?:verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)", re.I),
        "title": "TLS certificate verification appears disabled",
        "severity": "medium",
        "confidence": "medium",
        "cwe": "CWE-295",
        "description": "The source contains a common setting that can disable TLS peer verification. Confirm the runtime behavior and whether this is test-only code.",
    },
    {
        "id": "MIZAN-SECRET-LITERAL",
        "languages": {"python", "javascript", "typescript", "java", "go", "php", "ruby", "csharp", "generic"},
        "pattern": re.compile(r"\b(?:api[_-]?key|secret|password|passwd|access[_-]?token)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']", re.I),
        "title": "Possible hard-coded credential",
        "severity": "medium",
        "confidence": "low",
        "cwe": "CWE-798",
        "description": "A credential-like assignment contains a string literal. It may be a placeholder or test value; verify locally and rotate any real exposed secret.",
    },
]


def _choose_language(code: str, requested: str) -> str:
    if not isinstance(requested, str) or requested not in SUPPORTED_LANGUAGES:
        raise ValueError("Choose a supported source language.")
    if requested != "auto":
        return requested
    if re.search(r"\b(?:def|import|from|lambda)\b|\bNone\b|\bTrue\b|\bFalse\b", code):
        return "python"
    if re.search(r"\b(?:const|let|function|=>|export)\b", code):
        return "javascript"
    return "generic"


def analyze_source(code: str, language: str = "auto") -> dict:
    """Run deterministic source-text heuristics and return bounded evidence."""
    if not isinstance(code, str):
        raise ValueError("Source code must be text.")
    if not code.strip():
        raise ValueError("No source code was supplied with this case.")
    if len(code) > MAX_SOURCE_CHARS:
        raise ValueError("Source code exceeds the local analysis size limit.")
    selected = _choose_language(code, language)
    findings = []
    for line_number, line in enumerate(code.splitlines(), 1):
        if not line.strip():
            continue
        for rule in _RULES:
            if selected not in rule["languages"]:
                continue
            if rule["pattern"].search(line):
                findings.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "cwe": rule["cwe"],
                    "line": line_number,
                    "source_snippet": line[:500],
                    "description": rule["description"],
                    "verified": False,
                })
                if len(findings) >= MAX_FINDINGS:
                    break
        if len(findings) >= MAX_FINDINGS:
            break
    counts = {level: sum(item["severity"] == level for item in findings) for level in ("high", "medium", "low")}
    return {
        "engine": "mizan-local-heuristics-v1",
        "mode": "offline-source-text-only",
        "language": selected,
        "source_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "source_lines": len(code.splitlines()),
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": findings,
        "limitations": [
            "Pattern matches are review leads, not proof of a vulnerability or exploitability.",
            "No source code was executed, imported, fetched, or sent to a model or external service.",
            "No findings does not establish that the code is secure.",
        ],
    }
