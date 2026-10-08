"""
Unit tests for the XPC static analyzer and Mach-O scanner.
"""

import struct
import unittest

from ios_security_recon.xpc.parser import LC_SEGMENT_64, MH_MAGIC_64, MachOParser
from ios_security_recon.xpc.scanner import XPCScanner


def build_mock_macho_with_cstring(strings: list[str]) -> bytes:
    """Builds a minimal Mach-O 64-bit binary containing a __TEXT,__cstring section."""
    sect_payload = b"".join(s.encode("utf-8") + b"\x00" for s in strings)

    # Section 64 struct (80 bytes)
    # sectname(16), segname(16), addr(8), size(8), offset(4), align(4), reloff(4), nreloc(4), flags(4), r1(4), r2(4), r3(4)
    sect_header = struct.pack(
        ">16s16sQQIIIIIIII",
        b"__cstring\x00\x00\x00\x00\x00\x00\x00",
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x1000,              # addr
        len(sect_payload),   # size
        184,                 # offset (32 header + 72 seg + 80 sect)
        0, 0, 0, 0, 0, 0, 0,
    )

    # LC_SEGMENT_64 command (72 bytes header + 80 bytes section = 152 bytes)
    # cmd(4), cmdsize(4), segname(16), vmaddr(8), vmsize(8), fileoff(8), filesize(8), maxprot(4), initprot(4), nsects(4), flags(4)
    cmd_header = struct.pack(
        ">II16sQQQQIIII",
        LC_SEGMENT_64,
        72 + 80,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x1000,
        len(sect_payload),
        184,
        len(sect_payload),
        7, 5, 1, 0,
    )

    # Mach-O header (32 bytes)
    macho_header = struct.pack(
        ">IIIIIIII",
        MH_MAGIC_64,
        0x0100000C,  # ARM64
        0,
        2,           # MH_EXECUTE
        1,           # ncmds
        152,         # sizeofcmds
        0, 0,
    )

    return macho_header + cmd_header + sect_header + sect_payload


class TestXPCScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = XPCScanner()

    def test_macho_section_parsing(self):
        strings = ["helloWorld", "anotherString"]
        macho_bytes = build_mock_macho_with_cstring(strings)
        parser = MachOParser(macho_bytes)
        self.assertTrue(parser.is_macho)
        self.assertIn("__TEXT,__cstring", parser.sections)
        extracted = parser.get_section("__TEXT,__cstring").extract_strings()
        self.assertIn("helloWorld", extracted)
        self.assertIn("anotherString", extracted)

    def test_xpc_server_guarded_scan(self):
        strings = [
            "xpc_connection_create_mach_service",
            "listener:shouldAcceptNewConnection:",
            "SecTaskCreateWithAuditToken",
            "SecTaskCopyValueForEntitlement",
            "com.apple.airtraffic.host.service",
            "com.apple.private.carrier.override",
            "setStatusBarOverrides:",
        ]
        macho_bytes = build_mock_macho_with_cstring(strings)
        result = self.scanner.scan(macho_bytes)

        self.assertTrue(result.is_macho)
        self.assertTrue(result.is_xpc_server)
        self.assertEqual(result.exposure_level, "GUARDED")
        self.assertIn("SecTaskCreateWithAuditToken", result.security_checks)
        self.assertIn("com.apple.private.carrier.override", result.referenced_entitlements)
        self.assertIn("com.apple.airtraffic.host.service", result.mach_services)
        self.assertIn("setStatusBarOverrides:", result.xpc_selectors)

    def test_xpc_server_exposed_unverified(self):
        strings = [
            "xpc_connection_create_mach_service",
            "listener:shouldAcceptNewConnection:",
            "setUnrestrictedData:",
        ]
        macho_bytes = build_mock_macho_with_cstring(strings)
        result = self.scanner.scan(macho_bytes)

        self.assertTrue(result.is_xpc_server)
        self.assertEqual(result.exposure_level, "EXPOSED_UNVERIFIED")
        self.assertEqual(len(result.security_checks), 0)

    def test_non_xpc_binary(self):
        strings = [
            "standard_math_library",
            "compute_hash",
        ]
        macho_bytes = build_mock_macho_with_cstring(strings)
        result = self.scanner.scan(macho_bytes)

        self.assertFalse(result.is_xpc_server)
        self.assertEqual(result.exposure_level, "NONE")

    def test_serialization_methods(self):
        strings = [
            "xpc_connection_create_mach_service",
            "SecTaskCreateWithAuditToken",
        ]
        macho_bytes = build_mock_macho_with_cstring(strings)
        result = self.scanner.scan(macho_bytes)

        json_out = result.to_json()
        self.assertIn("exposure_level", json_out)
        self.assertIn("GUARDED", json_out)

        md_out = result.to_markdown()
        self.assertIn("# XPC Static Security Scan:", md_out)
        self.assertIn("GUARDED", md_out)


if __name__ == "__main__":
    unittest.main()
