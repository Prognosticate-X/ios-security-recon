"""
Defensive static audit of file transfer conduits and synchronization surfaces.
Audits path normalization, directory traversal, symlink breakout (ATAirlock),
and MobileBackup2 domain path validation for iOS 27 / macOS platforms.
"""

from __future__ import annotations

import io
import os
import plistlib
import posixpath
import stat
import struct
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Default allowed SpringBoard targets for AirTraffic / status bar overrides
DEFAULT_ALLOWED_SPRINGBOARD_TARGETS = (
    "/var/mobile/Library/SpringBoard",
    "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive",
)

# Standard iOS 27 SystemPreferencesDomain hardcoded whitelist
IOS27_ALLOWED_SYSTEM_PREFERENCES_PATHS = frozenset({
    "SystemConfiguration/preferences.plist",
    "SystemConfiguration/NetworkInterfaces.plist",
    "SystemConfiguration/com.apple.nat.plist",
    "SystemConfiguration/com.apple.radios.plist",
    "SystemConfiguration/com.apple.wifi.plist",
    "SystemConfiguration/com.apple.mobilegestalt.plist",
    "SystemConfiguration/com.apple.captive.plist",
    "SystemConfiguration/com.apple.PowerManagement.plist",
    "SystemConfiguration/com.apple.accounts.plist",
    "SystemConfiguration/com.apple.networkextension.plist",
})

SZ_EXTRA_ID = 0x5A53


@dataclass
class PathAuditResult:
    original_path: str
    normalized_path: str
    is_safe: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_path": self.original_path,
            "normalized_path": self.normalized_path,
            "is_safe": self.is_safe,
            "violations": self.violations,
            "warnings": self.warnings,
        }


@dataclass
class ArchiveAuditResult:
    source_name: str
    total_entries: int
    is_safe: bool
    has_zip_slip: bool
    has_symlink_breakout: bool
    symlinks_detected: list[dict[str, str]] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata_info: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "total_entries": self.total_entries,
            "is_safe": self.is_safe,
            "has_zip_slip": self.has_zip_slip,
            "has_symlink_breakout": self.has_symlink_breakout,
            "symlinks_detected": self.symlinks_detected,
            "violations": self.violations,
            "warnings": self.warnings,
            "metadata_info": self.metadata_info,
        }


@dataclass
class BackupPathAuditResult:
    domain: str
    relative_path: str
    is_allowed: bool
    wipe_hazard: bool
    rejection_code: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "relative_path": self.relative_path,
            "is_allowed": self.is_allowed,
            "wipe_hazard": self.wipe_hazard,
            "rejection_code": self.rejection_code,
            "reason": self.reason,
        }


def audit_path_normalization(
    target_path: str,
    allowed_roots: tuple[str, ...] | list[str] = DEFAULT_ALLOWED_SPRINGBOARD_TARGETS,
) -> PathAuditResult:
    """
    Audits a path for directory traversal patterns, null bytes, encoding attacks,
    and containment within allowed root boundaries.
    """
    violations: list[str] = []
    warnings: list[str] = []

    # 1. Null byte detection
    if "\x00" in target_path or "%00" in target_path.lower():
        violations.append("Null byte character detected in path (poison null byte attack).")

    # 2. URL decoding checks (detect double or single encoding)
    decoded_path = target_path
    try:
        url_decoded = urllib.parse.unquote(target_path)
        if url_decoded != target_path:
            warnings.append("URL-encoded sequences detected in path.")
            # Test double decoding
            double_decoded = urllib.parse.unquote(url_decoded)
            if double_decoded != url_decoded:
                violations.append("Double URL-encoding detected in path.")
            decoded_path = url_decoded
    except Exception:
        pass

    # 3. Path separators and traversal detection
    if "\\" in decoded_path:
        warnings.append("Windows-style backslash separator detected in POSIX path.")
        decoded_path = decoded_path.replace("\\", "/")

    segments = decoded_path.split("/")
    if ".." in segments:
        violations.append("Explicit parent directory traversal ('..') segment detected.")

    # 4. Canonical Posix Normalization
    normalized = posixpath.normpath(decoded_path)

    # 5. Root containment validation
    allowed_roots_tuple = tuple(allowed_roots)
    is_contained = any(
        normalized == root or normalized.startswith(root.rstrip("/") + "/")
        for root in allowed_roots_tuple
    )

    if not is_contained:
        violations.append(
            f"Normalized path '{normalized}' escapes designated allowed roots: {allowed_roots_tuple}"
        )

    # 6. Sensitive system directories check
    sensitive_prefixes = ("/var/preferences", "/var/keychains", "/System", "/private/var/root")
    for pref in sensitive_prefixes:
        if normalized == pref or normalized.startswith(pref + "/"):
            violations.append(f"Target path enters critical protected system zone '{pref}'.")

    is_safe = len(violations) == 0
    return PathAuditResult(
        original_path=target_path,
        normalized_path=normalized,
        is_safe=is_safe,
        violations=violations,
        warnings=warnings,
    )


def audit_streaming_archive(
    source: Path | str | bytes,
    allowed_targets: tuple[str, ...] = DEFAULT_ALLOWED_SPRINGBOARD_TARGETS,
) -> ArchiveAuditResult:
    """
    Statically analyzes an AirTraffic / ATAirlock streaming zip package
    for Zip Slip, symlink breakout targets, and metadata anomalies without executing extraction.
    """
    violations: list[str] = []
    warnings: list[str] = []
    symlinks: list[dict[str, str]] = []
    has_zip_slip = False
    has_symlink_breakout = False
    source_name = "in-memory-archive"

    if isinstance(source, (str, Path)):
        source_name = str(source)
        try:
            zip_bytes = Path(source).read_bytes()
        except OSError as e:
            violations.append(f"Failed to read archive file: {e}")
            return ArchiveAuditResult(
                source_name=source_name,
                total_entries=0,
                is_safe=False,
                has_zip_slip=False,
                has_symlink_breakout=False,
                violations=violations,
            )
    elif isinstance(source, (bytes, bytearray)):
        zip_bytes = bytes(source)
    else:
        raise TypeError(f"Expected source to be Path, str, or bytes, got {type(source)}")

    try:
        archive_io = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(archive_io, "r") as zf:
            infolist = zf.infolist()
            total_entries = len(infolist)
            metadata_info = None

            for entry in infolist:
                # 1. Zip Slip check
                entry_name = entry.filename
                if entry_name.startswith("/") or "\\\\" in entry_name or ".." in entry_name.split("/"):
                    has_zip_slip = True
                    violations.append(f"Zip slip entry detected: '{entry_name}'")

                # Check com.apple.ZipMetadata.plist
                if entry_name == "META-INF/com.apple.ZipMetadata.plist":
                    try:
                        meta_bytes = zf.read(entry)
                        metadata_info = plistlib.loads(meta_bytes)
                    except Exception as e:
                        warnings.append(f"Failed to parse ZipMetadata.plist: {e}")

                # 2. Symlink detection via external_attr mode
                mode = entry.external_attr >> 16
                is_symlink = stat.S_ISLNK(mode)

                if is_symlink:
                    link_target_bytes = zf.read(entry)
                    link_target = link_target_bytes.decode("utf-8", errors="replace")
                    symlinks.append({
                        "entry": entry_name,
                        "target": link_target,
                    })

                    # Analyze symlink escape
                    # Typically ATAirlock uses entry like 'p0/p1/p2/link' -> '../../../target_tail'
                    # Base extraction is inside /var/mobile/Media/Airlock/Book/<UUID>
                    entry_dir = posixpath.dirname(entry_name)
                    resolved_rel = posixpath.normpath(posixpath.join(entry_dir, link_target))

                    if resolved_rel.startswith("../"):
                        has_symlink_breakout = True
                        warnings.append(
                            f"Symlink entry '{entry_name}' targets parent traversal: '{link_target}'"
                        )

                    # Check if the target leads to allowed SpringBoard target or illegal paths
                    # Strip leading ../ to see what absolute or pseudo-absolute path it targets
                    clean_target = "/" + resolved_rel.lstrip("./")
                    target_contained = any(
                        clean_target == allowed or clean_target.startswith(allowed.rstrip("/") + "/")
                        for allowed in allowed_targets
                    )

                    if not target_contained:
                        violations.append(
                            f"Symlink '{entry_name}' points to '{link_target}' which resolves outside allowed targets {allowed_targets}"
                        )

    except zipfile.BadZipFile as e:
        violations.append(f"Invalid or corrupted zip archive: {e}")
        return ArchiveAuditResult(
            source_name=source_name,
            total_entries=0,
            is_safe=False,
            has_zip_slip=False,
            has_symlink_breakout=False,
            violations=violations,
        )

    is_safe = (not violations) and (not has_zip_slip)
    return ArchiveAuditResult(
        source_name=source_name,
        total_entries=total_entries,
        is_safe=is_safe,
        has_zip_slip=has_zip_slip,
        has_symlink_breakout=has_symlink_breakout,
        symlinks_detected=symlinks,
        violations=violations,
        warnings=warnings,
        metadata_info=metadata_info,
    )


def audit_backup_domain_path(domain: str, relative_path: str) -> BackupPathAuditResult:
    """
    Evaluates backup domain operations against iOS 27 BackupAgent2 & MobileBackup2 rules.
    Detects sparse restore wipe hazards and disallowed domains.
    """
    clean_path = posixpath.normpath(relative_path.lstrip("/"))

    # 1. AppDomain sparse restore prohibition (iOS 27 beta 6+ / Release)
    if domain == "AppDomain" or domain.startswith("AppDomain-"):
        return BackupPathAuditResult(
            domain=domain,
            relative_path=relative_path,
            is_allowed=False,
            wipe_hazard=False,
            rejection_code="MBErrorDomain/205",
            reason="iOS 27 rejects direct sparse restoration to AppDomain paths.",
        )

    # 2. SystemPreferencesDomain whitelist verification
    if domain == "SystemPreferencesDomain":
        if clean_path in IOS27_ALLOWED_SYSTEM_PREFERENCES_PATHS:
            return BackupPathAuditResult(
                domain=domain,
                relative_path=relative_path,
                is_allowed=True,
                wipe_hazard=False,
                reason="Path belongs to the iOS 27 hardcoded SystemPreferencesDomain whitelist.",
            )
        else:
            return BackupPathAuditResult(
                domain=domain,
                relative_path=relative_path,
                is_allowed=False,
                wipe_hazard=True,
                rejection_code="SEC_RECOVERY_WIPE_RISK",
                reason=f"Path '{clean_path}' is not in the iOS 27 SystemPreferencesDomain whitelist. Touching unlisted preferences triggers Security State Recovery Wipe.",
            )

    # 3. RootDomain restrictions
    if domain == "RootDomain":
        if clean_path.startswith("preferences/") or clean_path == "preferences":
            return BackupPathAuditResult(
                domain=domain,
                relative_path=relative_path,
                is_allowed=False,
                wipe_hazard=True,
                rejection_code="ROOTDOMAIN_PREFERENCES_BLOCK",
                reason="RootDomain writes into preferences/ are strictly blocked and trigger recovery reset.",
            )

    # 4. HomeDomain verification
    if domain == "HomeDomain":
        # Disallow writing directly to Library/Preferences or sensitive system roots
        if clean_path.startswith("Library/Preferences/"):
            return BackupPathAuditResult(
                domain=domain,
                relative_path=relative_path,
                is_allowed=False,
                wipe_hazard=True,
                rejection_code="HOMEDOMAIN_PREFERENCES_TAMPER",
                reason="Direct tampering with HomeDomain Library/Preferences risks security self-healing wipe.",
            )
        return BackupPathAuditResult(
            domain=domain,
            relative_path=relative_path,
            is_allowed=True,
            wipe_hazard=False,
            reason="Path within HomeDomain conforms to allowable user file boundaries.",
        )

    # 5. Shared system containers (e.g. SysSharedContainerDomain-...)
    if domain.startswith("SysSharedContainerDomain"):
        return BackupPathAuditResult(
            domain=domain,
            relative_path=relative_path,
            is_allowed=True,
            wipe_hazard=False,
            reason="Shared system container domain with legitimate configuration profile/device scope.",
        )

    return BackupPathAuditResult(
        domain=domain,
        relative_path=relative_path,
        is_allowed=True,
        wipe_hazard=False,
        reason="Domain accepted under default platform rules.",
    )
