"""
Unit tests for file transfer conduit surface audit, ATAirlock parsing, and backup domain rules.
"""

import io
import plistlib
import stat
import unittest
import zipfile

from ios_security_recon.conduits.surface_audit import (
    audit_backup_domain_path,
    audit_path_normalization,
    audit_streaming_archive,
)


def create_mock_zip(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    """Builds an in-memory zip archive with optional posix mode attributes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data, mode in entries:
            zinfo = zipfile.ZipInfo(name)
            if mode is not None:
                zinfo.external_attr = (mode & 0xFFFF) << 16
                zinfo.create_system = 3
            zf.writestr(zinfo, data)
    return buf.getvalue()


class TestConduitSurface(unittest.TestCase):
    def test_safe_path_normalization(self):
        safe_path = "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive"
        res = audit_path_normalization(safe_path)
        self.assertTrue(res.is_safe)
        self.assertEqual(len(res.violations), 0)

    def test_directory_traversal_detection(self):
        bad_path = "/var/mobile/Library/SpringBoard/../../preferences/bad.plist"
        res = audit_path_normalization(bad_path)
        self.assertFalse(res.is_safe)
        self.assertTrue(any("parent directory traversal" in v for v in res.violations))

    def test_null_byte_injection(self):
        bad_path = "/var/mobile/Library/SpringBoard\x00/evil.plist"
        res = audit_path_normalization(bad_path)
        self.assertFalse(res.is_safe)
        self.assertTrue(any("Null byte" in v for v in res.violations))

    def test_double_url_encoding(self):
        bad_path = "/var/mobile/%252e%252e/preferences"
        res = audit_path_normalization(bad_path)
        self.assertFalse(res.is_safe)
        self.assertTrue(any("Double URL-encoding" in v for v in res.violations))

    def test_sensitive_system_directory_access(self):
        bad_path = "/var/preferences/FeatureFlags/global.plist"
        res = audit_path_normalization(bad_path, allowed_roots=("/var/preferences",))
        self.assertFalse(res.is_safe)
        self.assertTrue(any("critical protected system zone" in v for v in res.violations))

    def test_streaming_archive_safe(self):
        meta = plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY)
        archive_bytes = create_mock_zip([
            ("META-INF/com.apple.ZipMetadata.plist", meta, stat.S_IFREG | 0o600),
            ("payload", b"safe content", stat.S_IFREG | 0o644),
        ])
        res = audit_streaming_archive(archive_bytes)
        self.assertTrue(res.is_safe)
        self.assertFalse(res.has_zip_slip)
        self.assertFalse(res.has_symlink_breakout)

    def test_streaming_archive_zip_slip(self):
        archive_bytes = create_mock_zip([
            ("../../private/var/root/evil.txt", b"evil", stat.S_IFREG | 0o644),
        ])
        res = audit_streaming_archive(archive_bytes)
        self.assertFalse(res.is_safe)
        self.assertTrue(res.has_zip_slip)

    def test_streaming_archive_symlink_breakout(self):
        # Symlink pointing to /var/preferences
        archive_bytes = create_mock_zip([
            ("p0/p1/p2/link", b"../../../../../../var/preferences/FeatureFlags", stat.S_IFLNK | 0o777),
        ])
        res = audit_streaming_archive(archive_bytes)
        self.assertFalse(res.is_safe)
        self.assertTrue(res.has_symlink_breakout)
        self.assertTrue(any("outside allowed targets" in v for v in res.violations))

    def test_backup_domain_app_domain_blocked(self):
        res = audit_backup_domain_path("AppDomain-com.apple.mobilesafari", "Documents/data.db")
        self.assertFalse(res.is_allowed)
        self.assertEqual(res.rejection_code, "MBErrorDomain/205")

    def test_backup_domain_system_preferences_whitelist(self):
        # Whitelisted
        res_ok = audit_backup_domain_path("SystemPreferencesDomain", "SystemConfiguration/preferences.plist")
        self.assertTrue(res_ok.is_allowed)
        self.assertFalse(res_ok.wipe_hazard)

        # Unlisted (wipe hazard)
        res_bad = audit_backup_domain_path("SystemPreferencesDomain", "FeatureFlags/custom.plist")
        self.assertFalse(res_bad.is_allowed)
        self.assertTrue(res_bad.wipe_hazard)
        self.assertEqual(res_bad.rejection_code, "SEC_RECOVERY_WIPE_RISK")

    def test_backup_domain_root_domain_preferences_block(self):
        res = audit_backup_domain_path("RootDomain", "preferences/bad.plist")
        self.assertFalse(res.is_allowed)
        self.assertTrue(res.wipe_hazard)
        self.assertEqual(res.rejection_code, "ROOTDOMAIN_PREFERENCES_BLOCK")

    def test_backup_domain_home_domain_valid(self):
        res = audit_backup_domain_path("HomeDomain", "Library/SpringBoard/StatusBarOverrides.archive")
        self.assertTrue(res.is_allowed)
        self.assertFalse(res.wipe_hazard)


if __name__ == "__main__":
    unittest.main()
