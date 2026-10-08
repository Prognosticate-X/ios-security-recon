"""
Static XPC Interface & Client Entitlement Verification Scanner.
Analyzes Mach-O binaries for XPC listeners, exported selectors, and security audit gates.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .parser import MachOParser

XPC_API_PATTERNS = {
    "xpc_connection_create_mach_service",
    "xpc_connection_set_event_handler",
    "xpc_connection_resume",
    "listener:shouldAcceptNewConnection:",
    "NSXPCListener",
    "NSXPCInterface",
    "interfaceWithProtocol:",
    "setExportedInterface:",
    "setExportedObject:",
}

SECURITY_CHECK_PATTERNS = {
    "SecTaskCreateWithAuditToken",
    "SecTaskCopyValueForEntitlement",
    "SecTaskCopyValuesForEntitlements",
    "xpc_connection_get_audit_token",
    "audit_token_to_pid",
    "checkEntitlement:",
    "hasEntitlement:",
    "hasEntitlement:auditToken:",
    "_hasEntitlement:",
    "clientHasEntitlement:",
}

ENTITLEMENT_STRING_REGEX = re.compile(r"^com\.apple\.[a-zA-Z0-9.\-_]+$")
SELECTOR_REGEX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*:[a-zA-Z0-9_:]*$")


@dataclass
class XPCScanResult:
    target: str
    is_macho: bool
    is_xpc_server: bool
    exposure_level: str  # GUARDED, EXPOSED_UNVERIFIED, NONE
    mach_services: list[str] = field(default_factory=list)
    detected_apis: list[str] = field(default_factory=list)
    security_checks: list[str] = field(default_factory=list)
    referenced_entitlements: list[str] = field(default_factory=list)
    xpc_selectors: list[str] = field(default_factory=list)
    total_strings_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "is_macho": self.is_macho,
            "is_xpc_server": self.is_xpc_server,
            "exposure_level": self.exposure_level,
            "mach_services": self.mach_services,
            "detected_apis": self.detected_apis,
            "security_checks": self.security_checks,
            "referenced_entitlements": self.referenced_entitlements,
            "xpc_selectors": self.xpc_selectors,
            "total_strings_scanned": self.total_strings_scanned,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        badge = {
            "GUARDED": "🟢 GUARDED (Entitlements Enforced)",
            "EXPOSED_UNVERIFIED": "🔴 HIGH RISK (Exposed Without Client Check)",
            "NONE": "⚪ NONE (Client-Only or Non-XPC)",
        }.get(self.exposure_level, self.exposure_level)

        lines = [
            f"# XPC Static Security Scan: `{self.target}`",
            "",
            f"- **Mach-O Binary**: `{'YES' if self.is_macho else 'NO'}`",
            f"- **XPC Server Daemon**: `{'YES' if self.is_xpc_server else 'NO'}`",
            f"- **IPC Exposure Posture**: **{badge}**",
            f"- **Total Strings Scanned**: {self.total_strings_scanned}",
            "",
        ]

        if self.mach_services:
            lines.extend([
                "### Discovered Mach Service Identifiers",
                "",
            ])
            for svc in self.mach_services:
                lines.append(f"- `{svc}`")
            lines.append("")

        if self.security_checks:
            lines.extend([
                "### Client Security Verification Primitives",
                "",
            ])
            for chk in self.security_checks:
                lines.append(f"- `[CHECK]` `{chk}`")
            lines.append("")

        if self.referenced_entitlements:
            lines.extend([
                "### Referenced Client Entitlements",
                "",
            ])
            for ent in self.referenced_entitlements:
                lines.append(f"- `{ent}`")
            lines.append("")

        if self.xpc_selectors:
            lines.extend([
                "### Discovered XPC & IPC Selectors",
                "",
            ])
            for sel in self.xpc_selectors[:25]:
                lines.append(f"- `{sel}`")
            if len(self.xpc_selectors) > 25:
                lines.append(f"- *... and {len(self.xpc_selectors) - 25} more selectors*")
            lines.append("")

        return "\n".join(lines)


class XPCScanner:
    """Statically inspects Mach-O binaries for XPC attack surfaces and client checks."""

    def __init__(self, custom_apis: set[str] | None = None):
        self.xpc_apis = set(XPC_API_PATTERNS) if custom_apis is None else set(custom_apis)
        self.security_checks = set(SECURITY_CHECK_PATTERNS)

    def scan(self, target: str | Path | bytes) -> XPCScanResult:
        target_name = "in-memory-binary"
        if isinstance(target, (str, Path)):
            target_name = str(target)
            data = Path(target).read_bytes()
        elif isinstance(target, (bytes, bytearray)):
            data = bytes(target)
        else:
            raise TypeError(f"Expected target to be str, Path, or bytes, got {type(target)}")

        macho = MachOParser(data)
        all_strings: list[str] = []

        if macho.is_macho and macho.sections:
            # Extract high-value strings from specific sections
            for fullname in ("__TEXT,__cstring", "__TEXT,__objc_methname", "__DATA,__objc_selrefs"):
                sec = macho.get_section(fullname)
                if sec is not None:
                    all_strings.extend(sec.extract_strings())

        # If strings are still sparse or non-macho, fallback to raw scan
        if len(all_strings) < 10:
            all_strings.extend(self._extract_raw_strings(data))

        unique_strings = set(all_strings)

        detected_apis = sorted([s for s in unique_strings if s in self.xpc_apis])
        detected_checks = sorted([s for s in unique_strings if s in self.security_checks])

        is_server = any(
            api in detected_apis
            for api in ("xpc_connection_create_mach_service", "listener:shouldAcceptNewConnection:", "NSXPCListener")
        )

        # Detect candidate Mach service names
        mach_services: list[str] = []
        for s in unique_strings:
            if s.startswith("com.apple.") and ("service" in s.lower() or "daemon" in s.lower() or "status" in s.lower() or "airtraffic" in s.lower()):
                mach_services.append(s)

        # Detect referenced entitlements
        entitlements_found: list[str] = []
        for s in unique_strings:
            if ENTITLEMENT_STRING_REGEX.match(s):
                if any(k in s for k in ("private", "springboard", "systemstatus", "security", "tcc", "rootless")):
                    entitlements_found.append(s)

        # Discovered selectors
        discovered_selectors: list[str] = []
        for s in unique_strings:
            if SELECTOR_REGEX.match(s) and any(kw in s.lower() for kw in ("listener", "connection", "status", "override", "asset", "carrier", "sync", "service")):
                discovered_selectors.append(s)

        # Posture evaluation
        if is_server:
            if detected_checks or entitlements_found:
                exposure = "GUARDED"
            else:
                exposure = "EXPOSED_UNVERIFIED"
        else:
            exposure = "NONE"

        return XPCScanResult(
            target=target_name,
            is_macho=macho.is_macho,
            is_xpc_server=is_server,
            exposure_level=exposure,
            mach_services=sorted(mach_services),
            detected_apis=detected_apis,
            security_checks=detected_checks,
            referenced_entitlements=sorted(entitlements_found),
            xpc_selectors=sorted(discovered_selectors),
            total_strings_scanned=len(unique_strings),
        )

    def _extract_raw_strings(self, data: bytes, min_len: int = 4) -> list[str]:
        """Fallback printable ASCII string extractor."""
        strings: list[str] = []
        pattern = re.compile(b"[A-Za-z0-9_.:/\\-]{4,}")
        for match in pattern.finditer(data):
            try:
                s = match.group(0).decode("ascii")
                strings.append(s)
            except UnicodeDecodeError:
                pass
        return strings
