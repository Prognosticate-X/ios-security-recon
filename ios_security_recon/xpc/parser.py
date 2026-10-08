"""
Mach-O binary parser in pure Python.
Extracts segments, sections, and symbols from 32-bit, 64-bit, and Universal Mach-O files.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19


@dataclass
class MachOSection:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int
    data: bytes

    @property
    def fullname(self) -> str:
        return f"{self.segname},{self.sectname}"

    def extract_strings(self, min_len: int = 3) -> list[str]:
        """Extract null-terminated C-strings from section data."""
        strings: list[str] = []
        raw = self.data
        start = 0
        while start < len(raw):
            null_pos = raw.find(b"\x00", start)
            if null_pos == -1:
                chunk = raw[start:]
                start = len(raw)
            else:
                chunk = raw[start:null_pos]
                start = null_pos + 1

            if len(chunk) >= min_len:
                try:
                    s = chunk.decode("utf-8")
                    if s.isprintable():
                        strings.append(s)
                except UnicodeDecodeError:
                    pass
        return strings


class MachOParser:
    """Parses Mach-O binaries and extracts sections and metadata."""

    def __init__(self, data: bytes):
        self.data = data
        self.sections: dict[str, MachOSection] = {}
        self.is_macho = False
        self._parse()

    @classmethod
    def from_file(cls, path: str | Path) -> MachOParser:
        data = Path(path).read_bytes()
        return cls(data)

    def _parse(self) -> None:
        if len(self.data) < 4:
            return

        magic = struct.unpack(">I", self.data[:4])[0]
        if magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
            self._parse_fat(magic)
        elif magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
            self._parse_slice(0, magic)

    def _parse_fat(self, magic: int) -> None:
        is_big = magic in (FAT_MAGIC, FAT_MAGIC_64)
        is_64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
        endian = ">" if is_big else "<"

        if len(self.data) < 8:
            return

        nfat = struct.unpack(endian + "I", self.data[4:8])[0]
        cursor = 8

        # Locate the first 64-bit architecture slice (e.g. arm64 or x86_64)
        best_offset = 0
        for _ in range(min(nfat, 16)):
            if is_64:
                if cursor + 32 > len(self.data):
                    break
                cputype, cpusubtype, offset, size, align = struct.unpack(
                    endian + "IIQQII", self.data[cursor:cursor + 32]
                )
                cursor += 32
            else:
                if cursor + 20 > len(self.data):
                    break
                cputype, cpusubtype, offset, size, align = struct.unpack(
                    endian + "IIIII", self.data[cursor:cursor + 20]
                )
                cursor += 20

            # cputype 0x0100000C is CPU_TYPE_ARM64, 0x01000007 is CPU_TYPE_X86_64
            if cputype in (0x0100000C, 0x01000007) and offset + 4 <= len(self.data):
                best_offset = offset
                break
            if best_offset == 0 and offset + 4 <= len(self.data):
                best_offset = offset

        if best_offset > 0 and best_offset + 4 <= len(self.data):
            slice_magic = struct.unpack(">I", self.data[best_offset:best_offset + 4])[0]
            if slice_magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
                self._parse_slice(best_offset, slice_magic)

    def _parse_slice(self, slice_offset: int, magic: int) -> None:
        self.is_macho = True
        is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
        is_big = magic in (MH_MAGIC, MH_MAGIC_64)
        endian = ">" if is_big else "<"

        header_size = 32 if is_64 else 28
        if len(self.data) < slice_offset + header_size:
            return

        if is_64:
            header_fmt = endian + "IIIIIIII"
        else:
            header_fmt = endian + "IIIIIII"

        header = struct.unpack(header_fmt, self.data[slice_offset:slice_offset + header_size])
        ncmds = header[4]
        sizeofcmds = header[5]

        cursor = slice_offset + header_size
        end_cmds = cursor + sizeofcmds

        for _ in range(ncmds):
            if cursor + 8 > end_cmds or cursor + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack(endian + "II", self.data[cursor:cursor + 8])
            if cmdsize < 8:
                break

            if cmd == LC_SEGMENT_64:
                self._parse_segment_64(cursor, endian, slice_offset)
            elif cmd == LC_SEGMENT:
                self._parse_segment_32(cursor, endian, slice_offset)

            cursor += cmdsize

    def _parse_segment_64(self, cmd_offset: int, endian: str, slice_offset: int) -> None:
        if cmd_offset + 72 > len(self.data):
            return
        raw_cmd = self.data[cmd_offset:cmd_offset + 72]
        _, _, segname_bytes, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack(
            endian + "II16sQQQQIIII", raw_cmd
        )
        segname = segname_bytes.decode("utf-8", errors="replace").rstrip("\x00")

        sect_cursor = cmd_offset + 72
        for _ in range(nsects):
            if sect_cursor + 80 > len(self.data):
                break
            sect_raw = self.data[sect_cursor:sect_cursor + 80]
            sectname_bytes, s_segname_bytes, addr, size, offset, align, reloff, nreloc, s_flags, r1, r2, r3 = struct.unpack(
                endian + "16s16sQQIIIIIIII", sect_raw
            )
            sectname = sectname_bytes.decode("utf-8", errors="replace").rstrip("\x00")
            s_segname = s_segname_bytes.decode("utf-8", errors="replace").rstrip("\x00")

            abs_offset = slice_offset + offset
            if abs_offset + size <= len(self.data):
                sect_data = self.data[abs_offset:abs_offset + size]
            else:
                sect_data = b""

            section = MachOSection(
                segname=s_segname,
                sectname=sectname,
                addr=addr,
                size=size,
                offset=abs_offset,
                data=sect_data,
            )
            self.sections[section.fullname] = section
            sect_cursor += 80

    def _parse_segment_32(self, cmd_offset: int, endian: str, slice_offset: int) -> None:
        if cmd_offset + 56 > len(self.data):
            return
        raw_cmd = self.data[cmd_offset:cmd_offset + 56]
        _, _, segname_bytes, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack(
            endian + "II16sIIIIIIII", raw_cmd
        )
        segname = segname_bytes.decode("utf-8", errors="replace").rstrip("\x00")

        sect_cursor = cmd_offset + 56
        for _ in range(nsects):
            if sect_cursor + 68 > len(self.data):
                break
            sect_raw = self.data[sect_cursor:sect_cursor + 68]
            sectname_bytes, s_segname_bytes, addr, size, offset, align, reloff, nreloc, s_flags, r1, r2 = struct.unpack(
                endian + "16s16sIIIIIIIII", sect_raw
            )
            sectname = sectname_bytes.decode("utf-8", errors="replace").rstrip("\x00")
            s_segname = s_segname_bytes.decode("utf-8", errors="replace").rstrip("\x00")

            abs_offset = slice_offset + offset
            if abs_offset + size <= len(self.data):
                sect_data = self.data[abs_offset:abs_offset + size]
            else:
                sect_data = b""

            section = MachOSection(
                segname=s_segname,
                sectname=sectname,
                addr=addr,
                size=size,
                offset=abs_offset,
                data=sect_data,
            )
            self.sections[section.fullname] = section
            sect_cursor += 68

    def get_section(self, fullname: str) -> MachOSection | None:
        return self.sections.get(fullname)
