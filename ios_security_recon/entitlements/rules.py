"""
Defensive security rules and best practices for Apple platform entitlements auditing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class RuleSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleCategory(str, Enum):
    DEBUGGING = "Debugging & Instrumentation"
    MEMORY_INTEGRITY = "Memory & Code Signing"
    SANDBOX_EXEMPTION = "Sandbox Exemption"
    STORAGE_SIP = "Storage & SIP Bypass"
    SPRINGBOARD_STATUS = "SpringBoard & SystemStatus"
    PRIVILEGED_IPC = "Privileged IPC & Daemons"
    KEYCHAIN = "Keychain & Credential Isolation"
    SYSTEM_IDENTITY = "Platform Identity & TCC"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    category: RuleCategory
    key: str
    value: Any
    description: str
    remediation: str


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: RuleSeverity
    category: RuleCategory
    description: str
    remediation: str
    checker: Callable[[dict[str, Any]], list[Finding]]


def _check_get_task_allow(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    val = entitlements.get("get-task-allow")
    if val is True:
        findings.append(
            Finding(
                rule_id="SEC-ENT-001",
                rule_name="Production Debugging Allowed (get-task-allow)",
                severity=RuleSeverity.CRITICAL,
                category=RuleCategory.DEBUGGING,
                key="get-task-allow",
                value=val,
                description="Binary allows debugger attachment (task_for_pid) in production, exposing runtime memory to inspection.",
                remediation="Ensure 'get-task-allow' is set to false or removed in release and production builds.",
            )
        )
    return findings


def _check_task_for_pid_allow(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    val = entitlements.get("task_for_pid-allow")
    if val is True:
        findings.append(
            Finding(
                rule_id="SEC-ENT-002",
                rule_name="Arbitrary Process Task Port Access (task_for_pid-allow)",
                severity=RuleSeverity.CRITICAL,
                category=RuleCategory.DEBUGGING,
                key="task_for_pid-allow",
                value=val,
                description="Binary requests capability to obtain task ports of arbitrary processes without restriction.",
                remediation="Remove task_for_pid-allow unless developing privileged developer tools signed with specialized Apple provisions.",
            )
        )
    return findings


def _check_all_files_sandbox(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    suspicious_keys = [
        "com.apple.security.temporary-exception.files.all-files",
        "com.apple.security.temporary-exception.files.absolute-path.read-write",
        "com.apple.security.temporary-exception.files.home-relative-path.read-write",
    ]
    for k in suspicious_keys:
        if k in entitlements:
            findings.append(
                Finding(
                    rule_id="SEC-ENT-003",
                    rule_name="Broad Sandbox File Exception",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SANDBOX_EXEMPTION,
                    key=k,
                    value=entitlements[k],
                    description=f"Entitlement '{k}' escapes default App Sandbox filesystem boundaries.",
                    remediation="Narrow down filesystem access to App Sandbox container or explicit App Group directories.",
                )
            )
    return findings


def _check_storage_sip_bypass(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    for k, v in entitlements.items():
        if k.startswith("com.apple.rootless.storage") or k.startswith("com.apple.private.security.storage"):
            findings.append(
                Finding(
                    rule_id="SEC-ENT-004",
                    rule_name="Rootless / SIP Storage Class Bypass",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.STORAGE_SIP,
                    key=k,
                    value=v,
                    description=f"Entitlement '{k}' requests access to SIP-protected filesystem storage classes.",
                    remediation="Restrict system storage operations to user container boundaries.",
                )
            )
    return findings


def _check_springboard_capabilities(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    sb_keys = [k for k in entitlements.keys() if k.startswith("com.apple.springboard.")]
    if sb_keys:
        findings.append(
            Finding(
                rule_id="SEC-ENT-005",
                rule_name="SpringBoard Private Capabilities",
                severity=RuleSeverity.MEDIUM,
                category=RuleCategory.SPRINGBOARD_STATUS,
                key="com.apple.springboard.*",
                value=sb_keys,
                description=f"Binary requests {len(sb_keys)} private SpringBoard service capabilities.",
                remediation="Audit necessity of direct SpringBoard IPC; prefer official UserNotifications or WidgetKit APIs.",
            )
        )
    return findings


def _check_systemstatus_capabilities(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    sys_status_keys = [k for k in entitlements.keys() if k.startswith("com.apple.systemstatus.")]
    if sys_status_keys:
        findings.append(
            Finding(
                rule_id="SEC-ENT-006",
                rule_name="SystemStatus Publisher Capability",
                severity=RuleSeverity.MEDIUM,
                category=RuleCategory.SPRINGBOARD_STATUS,
                key="com.apple.systemstatus.*",
                value=sys_status_keys,
                description=f"Binary requests {len(sys_status_keys)} private SystemStatus publish/subscribe capabilities.",
                remediation="Ensure client process is properly isolated and only authenticated daemons claim publisher roles.",
            )
        )
    return findings


def _check_unsigned_memory(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    val = entitlements.get("com.apple.security.cs.allow-unsigned-executable-memory")
    if val is True:
        findings.append(
            Finding(
                rule_id="SEC-ENT-007",
                rule_name="Unsigned Executable Memory Allowed",
                severity=RuleSeverity.HIGH,
                category=RuleCategory.MEMORY_INTEGRITY,
                key="com.apple.security.cs.allow-unsigned-executable-memory",
                value=val,
                description="Binary allows execution of unsigned memory pages, weakening Hardened Runtime code integrity protections.",
                remediation="Avoid runtime code generation without strict W^X enforcement or Apple JIT entitlements.",
            )
        )
    return findings


def _check_keychain_access(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    val = entitlements.get("keychain-access-groups")
    if isinstance(val, list):
        for item in val:
            if item == "*" or item.endswith(".*"):
                findings.append(
                    Finding(
                        rule_id="SEC-ENT-008",
                        rule_name="Wildcard Keychain Access Group",
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.KEYCHAIN,
                        key="keychain-access-groups",
                        value=val,
                        description=f"Keychain access group specifies overly broad wildcard pattern '{item}'.",
                        remediation="Explicitly specify exact App Identifier Keychain Access Groups.",
                    )
                )
    return findings


def _check_tcc_bypass(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    val = entitlements.get("com.apple.private.tcc.allow")
    if val:
        findings.append(
            Finding(
                rule_id="SEC-ENT-009",
                rule_name="Private TCC Permission Bypass",
                severity=RuleSeverity.HIGH,
                category=RuleCategory.SYSTEM_IDENTITY,
                key="com.apple.private.tcc.allow",
                value=val,
                description="Binary requests pre-granted TCC privacy permissions without user prompt consent.",
                remediation="Use standard public Info.plist usage descriptions (e.g. NSCameraUsageDescription) rather than private TCC bypasses.",
            )
        )
    return findings


def _check_seatbelt_profiles(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    if "seatbelt-profiles" in entitlements:
        findings.append(
            Finding(
                rule_id="SEC-ENT-010",
                rule_name="Custom Seatbelt Profile Injection",
                severity=RuleSeverity.HIGH,
                category=RuleCategory.SANDBOX_EXEMPTION,
                key="seatbelt-profiles",
                value=entitlements["seatbelt-profiles"],
                description="Binary defines custom Seatbelt sandbox profiles loaded directly by kernel sandbox.",
                remediation="Rely on standard system platform sandbox profiles rather than custom seatbelt definitions.",
            )
        )
    return findings


def _check_platform_application(entitlements: dict[str, Any]) -> list[Finding]:
    findings = []
    val = entitlements.get("platform-application")
    if val is True:
        findings.append(
            Finding(
                rule_id="SEC-ENT-011",
                rule_name="Platform Application Capability Claim",
                severity=RuleSeverity.CRITICAL,
                category=RuleCategory.SYSTEM_IDENTITY,
                key="platform-application",
                value=val,
                description="Binary claims to be an Apple first-party platform application, granting elevated daemon trust.",
                remediation="Only Apple system components should claim platform-application.",
            )
        )
    return findings


DEFAULT_RULES: list[Rule] = [
    Rule(
        id="SEC-ENT-001",
        name="Production Debugging Allowed",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.DEBUGGING,
        description="Binary enables get-task-allow in production builds.",
        remediation="Disable get-task-allow in release configurations.",
        checker=_check_get_task_allow,
    ),
    Rule(
        id="SEC-ENT-002",
        name="Arbitrary Process Task Port Access",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.DEBUGGING,
        description="Binary requests task_for_pid-allow.",
        remediation="Remove task_for_pid-allow.",
        checker=_check_task_for_pid_allow,
    ),
    Rule(
        id="SEC-ENT-003",
        name="Broad Sandbox File Exception",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SANDBOX_EXEMPTION,
        description="Binary requests broad filesystem sandbox bypass.",
        remediation="Restrict filesystem access to App Sandbox container.",
        checker=_check_all_files_sandbox,
    ),
    Rule(
        id="SEC-ENT-004",
        name="Rootless / SIP Storage Class Bypass",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.STORAGE_SIP,
        description="Binary requests rootless or SIP storage bypass.",
        remediation="Isolate storage to permitted container paths.",
        checker=_check_storage_sip_bypass,
    ),
    Rule(
        id="SEC-ENT-005",
        name="SpringBoard Private Capabilities",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SPRINGBOARD_STATUS,
        description="Binary requests com.apple.springboard.* private capabilities.",
        remediation="Audit SpringBoard capabilities.",
        checker=_check_springboard_capabilities,
    ),
    Rule(
        id="SEC-ENT-006",
        name="SystemStatus Publisher Capability",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SPRINGBOARD_STATUS,
        description="Binary requests com.apple.systemstatus.* publisher capabilities.",
        remediation="Ensure proper daemon isolation for status publishing.",
        checker=_check_systemstatus_capabilities,
    ),
    Rule(
        id="SEC-ENT-007",
        name="Unsigned Executable Memory Allowed",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.MEMORY_INTEGRITY,
        description="Binary enables allow-unsigned-executable-memory.",
        remediation="Enforce W^X memory discipline and signed code.",
        checker=_check_unsigned_memory,
    ),
    Rule(
        id="SEC-ENT-008",
        name="Wildcard Keychain Access Group",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.KEYCHAIN,
        description="Binary uses wildcard in keychain access groups.",
        remediation="Specify explicit keychain access groups.",
        checker=_check_keychain_access,
    ),
    Rule(
        id="SEC-ENT-009",
        name="Private TCC Permission Bypass",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SYSTEM_IDENTITY,
        description="Binary requests com.apple.private.tcc.allow.",
        remediation="Rely on standard user-facing privacy consents.",
        checker=_check_tcc_bypass,
    ),
    Rule(
        id="SEC-ENT-010",
        name="Custom Seatbelt Profile Injection",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SANDBOX_EXEMPTION,
        description="Binary specifies custom seatbelt-profiles.",
        remediation="Use standard platform sandbox profiles.",
        checker=_check_seatbelt_profiles,
    ),
    Rule(
        id="SEC-ENT-011",
        name="Platform Application Capability Claim",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SYSTEM_IDENTITY,
        description="Binary claims platform-application status.",
        remediation="Only Apple system binaries should claim platform-application.",
        checker=_check_platform_application,
    ),
]
