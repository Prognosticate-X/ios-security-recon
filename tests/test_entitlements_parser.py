"""
Unit tests for the entitlements parser and extractor.
"""

import plistlib
import struct
import tempfile
import unittest
from pathlib import Path

from ios_security_recon.entitlements.parser import (
    CSMAGIC_EMBEDDED_ENTITLEMENTS,
    CSMAGIC_EMBEDDED_SIGNATURE,
    CSSLOT_ENTITLEMENTS,
    FAT_MAGIC,
    LC_CODE_SIGNATURE,
    MH_MAGIC_64,
    EntitlementParserError,
    extract_entitlements,
)


def create_synthetic_macho_with_entitlements(entitlements: dict) -> bytes:
    """Builds a minimal valid Mach-O 64-bit binary with LC_CODE_SIGNATURE."""
    plist_data = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)

    # Entitlements blob
    blob_header = struct.pack(">II", CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(plist_data))
    ent_blob = blob_header + plist_data

    # SuperBlob: 12 bytes header + 8 bytes index + ent_blob
    superblob_len = 12 + 8 + len(ent_blob)
    superblob_header = struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, superblob_len, 1)
    superblob_index = struct.pack(">II", CSSLOT_ENTITLEMENTS, 20)
    superblob = superblob_header + superblob_index + ent_blob

    # Mach-O Header: 32 bytes
    header = struct.pack(
        ">IIIIIIII",
        MH_MAGIC_64,
        0x0100000C,  # ARM64
        0x00000000,
        0x00000002,  # MH_EXECUTE
        1,           # ncmds
        16,          # sizeofcmds
        0x00200085,
        0,           # reserved
    )

    dataoff = 48  # header (32) + cmd (16)
    datasize = len(superblob)
    lc_sig = struct.pack(">IIII", LC_CODE_SIGNATURE, 16, dataoff, datasize)

    return header + lc_sig + superblob


class TestEntitlementsParser(unittest.TestCase):
    def test_extract_from_xml_plist(self):
        sample = {
            "get-task-allow": True,
            "application-identifier": "TEAMID.com.example.app",
        }
        data = plistlib.dumps(sample, fmt=plistlib.FMT_XML)
        res = extract_entitlements(data)
        self.assertEqual(res["get-task-allow"], True)
        self.assertEqual(res["application-identifier"], "TEAMID.com.example.app")

    def test_extract_from_bplist(self):
        sample = {
            "com.apple.springboard.status": True,
            "keychain-access-groups": ["TEAMID.com.example.app"],
        }
        data = plistlib.dumps(sample, fmt=plistlib.FMT_BINARY)
        res = extract_entitlements(data)
        self.assertEqual(res["com.apple.springboard.status"], True)
        self.assertEqual(res["keychain-access-groups"], ["TEAMID.com.example.app"])

    def test_extract_from_synthetic_macho(self):
        sample = {
            "platform-application": True,
            "com.apple.private.tcc.allow": ["kTCCServiceCamera"],
        }
        macho_bytes = create_synthetic_macho_with_entitlements(sample)
        res = extract_entitlements(macho_bytes)
        self.assertEqual(res["platform-application"], True)
        self.assertEqual(res["com.apple.private.tcc.allow"], ["kTCCServiceCamera"])

    def test_extract_from_fat_binary(self):
        sample = {"com.apple.systemstatus.publisher": True}
        macho_slice = create_synthetic_macho_with_entitlements(sample)

        # Build FAT header: magic(4), nfat_arch(4)
        # arch descriptor (20 bytes for 32-bit FAT): cputype(4), cpusubtype(4), offset(4), size(4), align(4)
        fat_header = struct.pack(">II", FAT_MAGIC, 1)
        slice_offset = 28  # 8 + 20
        arch_entry = struct.pack(
            ">IIIII",
            0x0100000C,  # ARM64
            0,
            slice_offset,
            len(macho_slice),
            2,
        )
        fat_bytes = fat_header + arch_entry + macho_slice
        res = extract_entitlements(fat_bytes)
        self.assertEqual(res["com.apple.systemstatus.publisher"], True)

    def test_extract_from_file(self):
        sample = {"com.apple.security.app-sandbox": True}
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as f:
            f.write(plistlib.dumps(sample, fmt=plistlib.FMT_XML))
            tmp_path = Path(f.name)

        try:
            res = extract_entitlements(tmp_path)
            self.assertEqual(res["com.apple.security.app-sandbox"], True)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_empty_source_raises(self):
        with self.assertRaises(EntitlementParserError):
            extract_entitlements(b"")

    def test_invalid_data_raises(self):
        with self.assertRaises(EntitlementParserError):
            extract_entitlements(b"random corrupted binary garbage without entitlements")


if __name__ == "__main__":
    unittest.main()
