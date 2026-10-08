"""
Unit tests for the device safety gate policy enforcement engine.
"""

import unittest

from ios_security_recon.conduits.safety_gate import (
    PolicyDecision,
    SafetyGate,
    SafetyGateConfig,
)


class TestSafetyGate(unittest.TestCase):
    def setUp(self):
        self.config = SafetyGateConfig(
            blocked_udids={"00008140-001A2B3C4D5E6F7G"},
            allowed_udids={"TEST-UDID-ALPHA-123", "TEST-UDID-BETA-456"},
            tested_builds={"24A435", "24A5390f"},
            strict_version_check=True,
        )
        self.gate = SafetyGate(self.config)

    def test_primary_device_blocklist_enforced(self):
        blocked_udid = "00008140-001A2B3C4D5E6F7G"
        res = self.gate.check_udid(blocked_udid)
        self.assertEqual(res.decision, PolicyDecision.BLOCK)
        self.assertEqual(res.rule_name, "PRIMARY_DEVICE_BLOCKLIST")

    def test_unauthorized_udid_rejected_by_allowlist(self):
        unknown_udid = "RANDOM-UNAUTHORIZED-UDID"
        res = self.gate.check_udid(unknown_udid)
        self.assertEqual(res.decision, PolicyDecision.BLOCK)
        self.assertEqual(res.rule_name, "DEVICE_NOT_ALLOWLISTED")

    def test_authorized_test_udid_accepted(self):
        res = self.gate.check_udid("TEST-UDID-ALPHA-123")
        self.assertEqual(res.decision, PolicyDecision.ALLOW)

    def test_tested_os_build_verified(self):
        res = self.gate.check_version("27.0", "24A435")
        self.assertEqual(res.decision, PolicyDecision.ALLOW)
        self.assertEqual(res.rule_name, "TESTED_BUILD_VERIFIED")

    def test_untested_build_blocked_in_strict_mode(self):
        res = self.gate.check_version("27.0", "99Z999")
        self.assertEqual(res.decision, PolicyDecision.BLOCK)
        self.assertEqual(res.rule_name, "UNTESTED_BUILD_REJECTED")

    def test_protected_preferences_path_blocked(self):
        bad_path = "/var/preferences/FeatureFlags/Global.plist"
        res = self.gate.check_target_path(bad_path)
        self.assertEqual(res.decision, PolicyDecision.BLOCK)
        self.assertEqual(res.rule_name, "SECURITY_STATE_RECOVERY_PROTECTION")

    def test_keychain_path_blocked(self):
        bad_path = "/var/keychains/keychain-2.db"
        res = self.gate.check_target_path(bad_path)
        self.assertEqual(res.decision, PolicyDecision.BLOCK)

    def test_safe_springboard_path_allowed(self):
        safe_path = "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive"
        res = self.gate.check_target_path(safe_path)
        self.assertEqual(res.decision, PolicyDecision.ALLOW)

    def test_full_enforcement_pass(self):
        enf = self.gate.enforce(
            udid="TEST-UDID-ALPHA-123",
            target_path="/var/mobile/Library/SpringBoard/StatusBarOverrides.archive",
            os_version="27.0",
            build_id="24A435",
        )
        self.assertTrue(enf.passed)
        self.assertEqual(enf.decision, PolicyDecision.ALLOW)
        self.assertEqual(len(enf.blockers), 0)

    def test_full_enforcement_fail_on_primary_phone(self):
        enf = self.gate.enforce(
            udid="00008140-001A2B3C4D5E6F7G",
            target_path="/var/mobile/Library/SpringBoard/StatusBarOverrides.archive",
            os_version="27.0",
            build_id="24A435",
        )
        self.assertFalse(enf.passed)
        self.assertEqual(enf.decision, PolicyDecision.BLOCK)
        self.assertTrue(any("PRIMARY_DEVICE_BLOCKLIST" in b or "primary device blocklist" in b for b in enf.blockers))


if __name__ == "__main__":
    unittest.main()
