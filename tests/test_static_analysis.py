import hashlib
import unittest

import static_analysis


class StaticAnalysisTests(unittest.TestCase):
    def test_python_rules_return_exact_line_evidence_without_verification_claim(self):
        source = "import subprocess\ncursor.execute(f'SELECT * FROM users WHERE id={user_id}')\nsubprocess.run(user_command, shell=True)\nvalue = eval(user_input)\n"
        result = static_analysis.analyze_source(source, "python")
        ids = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("MIZAN-PY-SHELL-TRUE", ids)
        self.assertIn("MIZAN-PY-EVAL", ids)
        self.assertIn("MIZAN-SQL-FSTRING", ids)
        self.assertEqual(result["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertTrue(all(finding["verified"] is False for finding in result["findings"]))
        self.assertEqual(result["mode"], "offline-source-text-only")

    def test_javascript_sink_is_reported_as_a_heuristic(self):
        result = static_analysis.analyze_source("element.innerHTML = userInput", "javascript")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["rule_id"], "MIZAN-JS-INNERHTML")
        self.assertEqual(result["findings"][0]["line"], 1)
        self.assertEqual(result["findings"][0]["confidence"], "low")

    def test_generic_language_does_not_apply_language_specific_rules(self):
        result = static_analysis.analyze_source("eval(input)", "generic")
        self.assertEqual(result["finding_count"], 0)

    def test_auto_detection_is_bounded_and_invalid_inputs_are_rejected(self):
        result = static_analysis.analyze_source("def f():\n    return eval(x)", "auto")
        self.assertEqual(result["language"], "python")
        for source, language in (("", "auto"), ("x" * (static_analysis.MAX_SOURCE_CHARS + 1), "python"), ("print(1)", "unknown")):
            with self.subTest(language=language, length=len(source)), self.assertRaises(ValueError):
                static_analysis.analyze_source(source, language)

    def test_finding_count_is_capped(self):
        source = "\n".join("eval(input)" for _ in range(static_analysis.MAX_FINDINGS + 10))
        result = static_analysis.analyze_source(source, "python")
        self.assertEqual(result["finding_count"], static_analysis.MAX_FINDINGS)


if __name__ == "__main__":
    unittest.main()
