"""
Unit tests for the entitlement inspector and security compliance rule engine.
"""

import unittest

from ios_security_recon.entitlements.inspector import EntitlementInspector
from ios_security_recon.entitlements.rules import RuleSeverity


class TestEntitlementsInspector(unittest.TestCase):
    def setUp(self):
        self.inspector = EntitlementInspector()

    def test_clean_entitlements_pass(self):
        clean = {
            "application-identifier": "TEAMID.com.example.secureapp",
            "com.apple.developer.team-identifier": "TEAMID",
        }
        report = self.inspector.inspect(clean)
        self.assertEqual(report.compliance_status, "PASS")
        self.assertEqual(report.score, 100)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(len(report.private_entitlements), 0)

    def test_critical_debugging_entitlement(self):
        bad = {
            "get-task-allow": True,
        }
        report = self.inspector.inspect(bad)
        self.assertEqual(report.compliance_status, "FAIL")
        self.assertLessEqual(report.score, 70)
        severities = [f.severity for f in report.findings]
        self.assertIn(RuleSeverity.CRITICAL, severities)

    def test_task_for_pid_rule(self):
        bad = {
            "task_for_pid-allow": True,
        }
        report = self.inspector.inspect(bad)
        self.assertEqual(report.compliance_status, "FAIL")
        self.assertTrue(any(f.rule_id == "SEC-ENT-002" for f in report.findings))

    def test_sandbox_broad_exception(self):
        bad = {
            "com.apple.security.temporary-exception.files.all-files": True,
        }
        report = self.inspector.inspect(bad)
        self.assertEqual(report.compliance_status, "WARN")
        self.assertTrue(any(f.rule_id == "SEC-ENT-003" for f in report.findings))

    def test_wildcard_keychain_rule(self):
        bad = {
            "keychain-access-groups": ["TEAMID.*"],
        }
        report = self.inspector.inspect(bad)
        self.assertTrue(any(f.rule_id == "SEC-ENT-008" for f in report.findings))

    def test_private_springboard_and_systemstatus(self):
        sample = {
            "com.apple.springboard.status": True,
            "com.apple.systemstatus.publisher": True,
        }
        report = self.inspector.inspect(sample)
        self.assertIn("com.apple.springboard.status", report.private_entitlements)
        self.assertIn("com.apple.systemstatus.publisher", report.private_entitlements)
        self.assertTrue(any(f.rule_id == "SEC-ENT-005" for f in report.findings))
        self.assertTrue(any(f.rule_id == "SEC-ENT-006" for f in report.findings))

    def test_report_serialization(self):
        sample = {"get-task-allow": True}
        report = self.inspector.inspect(sample)
        d = report.to_dict()
        self.assertEqual(d["compliance_status"], "FAIL")
        self.assertIn("findings", d)

        md = report.to_markdown()
        self.assertIn("# Entitlement Security Audit:", md)
        self.assertIn("SEC-ENT-001", md)


if __name__ == "__main__":
    unittest.main()
