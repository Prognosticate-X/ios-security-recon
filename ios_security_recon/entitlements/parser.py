"""
Static parser and extractor for Apple platform entitlements.
Supports raw XML/binary plists, Mach-O 32/64-bit binaries, and Universal (FAT) binaries.
"""

from __future__ import annotations

import os
import plistlib
import re
import struct
import subprocess
from pathlib import Path
from typing import Any, BinaryIO

# Mach-O Magics
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

# Code Signature Commands & Magics
LC_CODE_SIGNATURE = 0x1D
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSSLOT_ENTITLEMENTS = 0x5
CSSLOT_ENTITLEMENTS_DER = 0x7

PLIST_XML_PATTERN = re.compile(b"<\\?xml.*?<plist[\\s\\S]*?<\\/plist>", re.MULTILINE)


class EntitlementParserError(Exception):
    """Raised when extraction or parsing of entitlements fails."""
    pass


def _extract_from_macho_slice(data: bytes, slice_offset: int = 0) -> dict[str, Any] | None:
    """Extract entitlements from a Mach-O slice by parsing LC_CODE_SIGNATURE."""
    if len(data) < slice_offset + 32:
        return None

    magic = struct.unpack(">I", data[slice_offset:slice_offset + 4])[0]
    is_64 = False
    is_big_endian = False

    if magic == MH_MAGIC:
        is_big_endian = True
    elif magic == MH_CIGAM:
        is_big_endian = False
    elif magic == MH_MAGIC_64:
        is_big_endian = True
        is_64 = True
    elif magic == MH_CIGAM_64:
        is_big_endian = False
        is_64 = True
    else:
        return None

    endian_prefix = ">" if is_big_endian else "<"

    if is_64:
        header_fmt = endian_prefix + "IIIIIIII"
        header_size = 32
    else:
        header_fmt = endian_prefix + "IIIIIII"
        header_size = 28

    if len(data) < slice_offset + header_size:
        return None

    header = struct.unpack(header_fmt, data[slice_offset:slice_offset + header_size])
    ncmds = header[4]
    sizeofcmds = header[5]

    cursor = slice_offset + header_size
    end_of_cmds = cursor + sizeofcmds

    while cursor + 8 <= end_of_cmds and cursor + 8 <= len(data):
        cmd, cmdsize = struct.unpack(endian_prefix + "II", data[cursor:cursor + 8])
        if cmdsize < 8:
            break

        if cmd == LC_CODE_SIGNATURE:
            if cursor + 16 > len(data):
                break
            _, _, dataoff, datasize = struct.unpack(endian_prefix + "IIII", data[cursor:cursor + 16])
            abs_sig_offset = slice_offset + dataoff

            if abs_sig_offset + datasize <= len(data) and datasize >= 12:
                sig_data = data[abs_sig_offset:abs_sig_offset + datasize]
                superblob_magic, length, count = struct.unpack(">III", sig_data[:12])
                if superblob_magic == CSMAGIC_EMBEDDED_SIGNATURE:
                    index_offset = 12
                    for _ in range(count):
                        if index_offset + 8 > len(sig_data):
                            break
                        slot_type, slot_offset = struct.unpack(">II", sig_data[index_offset:index_offset + 8])
                        index_offset += 8
                        if slot_type == CSSLOT_ENTITLEMENTS:
                            blob_abs = slot_offset
                            if blob_abs + 8 <= len(sig_data):
                                blob_magic, blob_length = struct.unpack(">II", sig_data[blob_abs:blob_abs + 8])
                                if blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS and blob_length >= 8:
                                    plist_bytes = sig_data[blob_abs + 8:blob_abs + blob_length]
                                    try:
                                        res = plistlib.loads(plist_bytes)
                                        if isinstance(res, dict):
                                            return res
                                    except Exception:
                                        pass

        cursor += cmdsize

    return None


def _extract_from_fat(data: bytes) -> dict[str, Any] | None:
    """Parse Mach-O Universal / FAT binary and inspect internal slices."""
    if len(data) < 8:
        return None

    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        return None

    is_big = magic in (FAT_MAGIC, FAT_MAGIC_64)
    is_64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
    endian_prefix = ">" if is_big else "<"

    nfat_arch = struct.unpack(endian_prefix + "I", data[4:8])[0]
    cursor = 8

    # We prioritize 64-bit arm64 or x86_64 slices
    for _ in range(min(nfat_arch, 16)):
        if is_64:
            if cursor + 32 > len(data):
                break
            cputype, cpusubtype, offset, size, align = struct.unpack(
                endian_prefix + "IIQQII", data[cursor:cursor + 32]
            )
            cursor += 32
        else:
            if cursor + 20 > len(data):
                break
            cputype, cpusubtype, offset, size, align = struct.unpack(
                endian_prefix + "IIIII", data[cursor:cursor + 20]
            )
            cursor += 20

        if offset + size <= len(data):
            res = _extract_from_macho_slice(data, slice_offset=offset)
            if res is not None:
                return res

    return None


def extract_entitlements(source: str | Path | bytes) -> dict[str, Any]:
    """
    Extracts entitlements as a Python dictionary from a file path or raw bytes.

    Supports:
    - Raw XML / bplist files (.plist, .entitlements)
    - Mach-O 32-bit & 64-bit binaries (embedded LC_CODE_SIGNATURE)
    - Mach-O Universal/FAT binaries
    - Regex fallback for embedded XML plist in arbitrary binaries
    - macOS native codesign fallback if executed on macOS
    """
    data: bytes
    file_path: Path | None = None

    if isinstance(source, (str, Path)):
        file_path = Path(source)
        if not file_path.exists():
            raise EntitlementParserError(f"Target file does not exist: {file_path}")
        try:
            data = file_path.read_bytes()
        except OSError as e:
            raise EntitlementParserError(f"Failed to read file {file_path}: {e}") from e
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        raise TypeError(f"Expected source to be str, Path, or bytes, got {type(source)}")

    if not data:
        raise EntitlementParserError("Source is empty (0 bytes)")

    # 1. Attempt standard plist loading (XML or bplist)
    if data.startswith(b"bplist") or data.strip().startswith(b"<?xml") or b"<plist" in data[:300]:
        try:
            parsed = plistlib.loads(data)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    # 2. Attempt Mach-O FAT extraction
    fat_res = _extract_from_fat(data)
    if fat_res is not None:
        return fat_res

    # 3. Attempt Mach-O single slice extraction
    macho_res = _extract_from_macho_slice(data, slice_offset=0)
    if macho_res is not None:
        return macho_res

    # 4. Attempt regex extraction for embedded <plist> ... </plist>
    match = PLIST_XML_PATTERN.search(data)
    if match:
        try:
            parsed = plistlib.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    # 5. Native macOS codesign fallback if a real file path is present
    if file_path is not None and os.name == "posix":
        try:
            proc = subprocess.run(
                ["codesign", "-d", "--entitlements", ":-", str(file_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                check=False,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout:
                parsed = plistlib.loads(proc.stdout)
                if isinstance(parsed, dict):
                    return parsed
        except Exception:
            pass

    raise EntitlementParserError(
        f"Unable to parse or locate valid code signature entitlements in source "
        f"({f'{file_path.name}' if file_path else 'raw bytes'})"
    )
