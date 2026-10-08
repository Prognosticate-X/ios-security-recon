"""
Unit tests for entitlement diffing and privilege escalation analysis.
"""

import unittest

from ios_security_recon.entitlements.diff import diff_entitlements, is_sensitive_key


class TestEntitlementsDiff(unittest.TestCase):
    def test_identical_entitlements(self):
        base = {"application-identifier": "APP1", "com.apple.security.app-sandbox": True}
        target = {"application-identifier": "APP1", "com.apple.security.app-sandbox": True}

        diff = diff_entitlements(base, target)
        self.assertFalse(diff.has_differences)
        self.assertEqual(len(diff.added), 0)
        self.assertEqual(len(diff.removed), 0)
        self.assertEqual(len(diff.modified), 0)
        self.assertFalse(diff.privilege_escalation_risk)

    def test_added_and_removed(self):
        base = {"key-old": "value1"}
        target = {"key-new": "value2"}

        diff = diff_entitlements(base, target)
        self.assertTrue(diff.has_differences)
        self.assertIn("key-new", diff.added)
        self.assertIn("key-old", diff.removed)

    def test_modified_values(self):
        base = {"allowed-count": 1}
        target = {"allowed-count": 5}

        diff = diff_entitlements(base, target)
        self.assertTrue(diff.has_differences)
        self.assertEqual(diff.modified["allowed-count"]["baseline"], 1)
        self.assertEqual(diff.modified["allowed-count"]["target"], 5)

    def test_sensitive_escalation_detection(self):
        base = {"application-identifier": "APP1"}
        target = {
            "application-identifier": "APP1",
            "task_for_pid-allow": True,
            "com.apple.private.tcc.allow": ["kTCCServiceAll"],
        }

        diff = diff_entitlements(base, target)
        self.assertTrue(diff.privilege_escalation_risk)
        self.assertIn("task_for_pid-allow", diff.sensitive_added)
        self.assertIn("com.apple.private.tcc.allow", diff.sensitive_added)
        self.assertTrue(any("task_for_pid-allow" in r for r in diff.escalation_reasons))

    def test_is_sensitive_key(self):
        self.assertTrue(is_sensitive_key("get-task-allow"))
        self.assertTrue(is_sensitive_key("com.apple.private.security.storage"))
        self.assertTrue(is_sensitive_key("com.apple.springboard.status"))
        self.assertFalse(is_sensitive_key("custom.developer.setting"))

    def test_markdown_and_json_rendering(self):
        base = {"com.apple.security.app-sandbox": True}
        target = {"com.apple.security.app-sandbox": False, "get-task-allow": True}

        diff = diff_entitlements(base, target)
        json_out = diff.to_json()
        self.assertIn("get-task-allow", json_out)
        self.assertIn("privilege_escalation_risk", json_out)

        md_out = diff.to_markdown()
        self.assertIn("# Entitlement Diff:", md_out)
        self.assertIn("HIGH RISK", md_out)


if __name__ == "__main__":
    unittest.main()
