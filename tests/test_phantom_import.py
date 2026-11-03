import json
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import phantom_import


class PhantomImportTests(unittest.TestCase):
    def setUp(self):
        self.result = {
            "target": "https://example.test/api/messages",
            "target_type": "code",
            "scan_id": "AB12CD34",
            "timestamp": "2026-11-04T00:00:00Z",
            "risk_rating": "High",
            "tech_stack": ["Python", "Django"],
            "executive_summary": "Potential object-level authorization issue.",
            "technical_details": "The supplied handler loads a record by id.",
            "proof_of_concept": "A reported reproduction outline; not executed.",
            "remediation": "Check participant authorization before returning the record.",
            "estimated_bounty": {"low": 100, "high": 1000},
            "recommended_programs": [{"name": "Example"}],
            "recon": {
                "static_findings": [
                    {
                        "rule_id": "local.rule",
                        "message": "Potential missing access check.",
                        "severity": "WARNING",
                        "line_start": 12,
                        "line_end": 12,
                        "code_snippet": "return Message.objects.get(id=message_id)",
                        "cwe": "CWE-639",
                        "owasp": "A01:2021",
                        "confidence": "MEDIUM",
                    }
                ],
                "open_ports": [22, 443],
            },
            "vulnerabilities": [
                {
                    "id": "V-1",
                    "title": "Possible IDOR",
                    "severity": "High",
                    "cvss_score": 7.5,
                    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    "description": "The lookup uses a caller-controlled id.",
                    "endpoint": "GET /api/messages/{id}",
                    "impact": "Could expose private messages.",
                    "attack_vector": "Authenticated request.",
                    "cwe": "CWE-639",
                    "cve_refs": [],
                    "verified": True,
                    "source_line": 12,
                    "source_snippet": "return Message.objects.get(id=message_id)",
                }
            ],
        }

    def test_preview_labels_phantom_claims_and_preserves_researcher_code_separately(self):
        researcher_code = "def get_message(request, message_id): pass"
        preview = phantom_import.phantom_result_to_preview(
            {"result": self.result}, language="en", user_code=researcher_code
        )
        report = preview["report"]
        self.assertTrue(report.startswith("PHANTOM SCAN IMPORT — UNVERIFIED"))
        self.assertIn('"phantom_verified_flag_claim": true', report)
        self.assertIn('"source_snippet_claim": "return Message.objects.get(id=message_id)"', report)
        self.assertIn("unverified claims", report)
        self.assertIn("call a model", report)
        self.assertIn('"static_findings"', report)
        self.assertNotIn("open_ports", report)
        self.assertNotIn("estimated_bounty", report)
        self.assertNotIn("recommended_programs", report)
        self.assertEqual(preview["code"], researcher_code)
        self.assertEqual(preview["lang"], "en")
        self.assertNotIn("source_snippet", preview["code"])

    def test_invalid_language_falls_back_and_zero_finding_result_is_importable(self):
        result = {
            "target": "example.test",
            "target_type": "web",
            "vulnerabilities": [],
        }
        preview = phantom_import.phantom_result_to_preview(result, language="fr")
        self.assertEqual(preview["lang"], "en")
        self.assertIn('"vulnerabilities": []', preview["report"])

    def test_rejects_bad_root_target_type_and_non_object_findings(self):
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview(["not", "an", "object"])
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview({"target_type": "web"})
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview({"target": "x", "target_type": "unknown"})
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview({
                "target": "x", "target_type": "web", "vulnerabilities": ["not-object"]
            })

    def test_rejects_oversized_findings_invalid_provenance_and_code(self):
        too_many = dict(self.result, vulnerabilities=[{}] * (phantom_import.MAX_FINDINGS + 1))
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview(too_many)
        invalid_verified = dict(self.result)
        invalid_verified["vulnerabilities"] = [dict(self.result["vulnerabilities"][0], verified="yes")]
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview(invalid_verified)
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview(self.result, user_code=object())

    def test_rejects_preview_that_exceeds_mizan_storage_limit_without_truncation(self):
        result = dict(self.result)
        result["technical_details"] = "x" * phantom_import.MAX_FIELD_CHARS
        result["executive_summary"] = "y" * phantom_import.MAX_FIELD_CHARS
        result["proof_of_concept"] = "z" * phantom_import.MAX_FIELD_CHARS
        with self.assertRaises(ValueError):
            phantom_import.phantom_result_to_preview(result)

    def test_import_is_structured_json_data_not_html(self):
        result = dict(self.result)
        result["executive_summary"] = '<img src=x onerror="alert(1)">'
        preview = phantom_import.phantom_result_to_preview(result)
        decoded = json.loads(preview["report"].split("\n\n", 2)[2])
        self.assertEqual(decoded["executive_summary_claim"], '<img src=x onerror="alert(1)">')


if __name__ == "__main__":
    unittest.main()
