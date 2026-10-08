"""
Unit tests for the CLI interface (ios-recon).
"""

import io
import json
import plistlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ios_security_recon.cli import main
from tests.test_entitlements_parser import create_synthetic_macho_with_entitlements
from tests.test_xpc_scanner import build_mock_macho_with_cstring


class TestCLI(unittest.TestCase):
    def test_entitlements_diff_cli(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / "base.plist"
            f2 = Path(td) / "target.plist"
            f1.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}, fmt=plistlib.FMT_XML))
            f2.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True, "get-task-allow": True}, fmt=plistlib.FMT_XML))

            buf = io.StringIO()
            with redirect_stdout(buf):
                # Should return code 1 due to get-task-allow privilege escalation risk
                code = main(["entitlements", "diff", str(f1), str(f2), "--format", "json"])

            self.assertEqual(code, 1)
            output = buf.getvalue()
            data = json.loads(output)
            self.assertTrue(data["privilege_escalation_risk"])
            self.assertIn("get-task-allow", data["added"])

    def test_entitlements_inspect_cli(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "app.plist"
            f.write_bytes(plistlib.dumps({"application-identifier": "TEAM.com.app"}, fmt=plistlib.FMT_XML))

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["entitlements", "inspect", str(f), "--format", "json"])

            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["compliance_status"], "PASS")

    def test_conduit_audit_path_cli(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["conduit", "audit", "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["is_safe"])

    def test_conduit_audit_traversal_cli(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["conduit", "audit", "/var/mobile/../../var/preferences", "--format", "json"])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertFalse(data["is_safe"])

    def test_conduit_gate_cli(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([
                "conduit", "gate",
                "--udid", "VALID-TEST-DEVICE-UDID",
                "--target", "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive",
                "--os-version", "27.0",
                "--build", "24A435",
                "--format", "json",
            ])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["passed"])
        self.assertEqual(data["decision"], "ALLOW")

    def test_xpc_scan_cli(self):
        with tempfile.TemporaryDirectory() as td:
            macho_file = Path(td) / "daemon"
            macho_bytes = build_mock_macho_with_cstring([
                "xpc_connection_create_mach_service",
                "SecTaskCreateWithAuditToken",
            ])
            macho_file.write_bytes(macho_bytes)

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["xpc", "scan", str(macho_file), "--format", "json"])

            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertTrue(data["is_xpc_server"])
            self.assertEqual(data["exposure_level"], "GUARDED")

    def test_report_cli(self):
        with tempfile.TemporaryDirectory() as td:
            target_file = Path(td) / "binary"
            target_bytes = create_synthetic_macho_with_entitlements({"com.apple.security.app-sandbox": True})
            target_file.write_bytes(target_bytes)

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["report", "--target", str(target_file), "--format", "markdown"])

            self.assertEqual(code, 0)
            out = buf.getvalue()
            self.assertIn("Apple Platform Security Reconnaissance Report", out)


if __name__ == "__main__":
    unittest.main()
