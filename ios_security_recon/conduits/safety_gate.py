"""
Safety Gate Engine: Policy enforcement, device UDID allowlisting/blocklisting,
and system directory isolation rules to prevent bricking or accidental device wipes.
"""

from __future__ import annotations

import json
import os
import posixpath
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


# Standard tested build numbers for iOS 27.x
TESTED_IOS27_BUILDS = frozenset({
    "24A435",     # 27.0 Release candidate
    "24A5390f",   # 27.0 beta 6
    "24A434",     # 27.0 GM seed
    "24A437",     # 27.0.1 hotfix
    "24A300",     # 27.0 internal engineering
})

# Dangerous directories that trigger iOS 27 Security State Recovery or brick risk
PROTECTED_SYSTEM_PATHS = (
    "/var/preferences",
    "/var/preferences/FeatureFlags",
    "/var/keychains",
    "/var/containers/Data/System",
    "/System",
    "/Library",
    "/usr",
    "/private/var/root",
    "/private/var/preferences",
)


@dataclass
class PolicyResult:
    decision: PolicyDecision
    rule_name: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class GateEnforcementResult:
    passed: bool
    decision: PolicyDecision
    udid: str
    target_path: str
    os_version: str
    build_id: str
    policy_results: list[PolicyResult] = field(default_factory=list)

    @property
    def blockers(self) -> list[str]:
        return [r.message for r in self.policy_results if r.decision == PolicyDecision.BLOCK]

    @property
    def warnings(self) -> list[str]:
        return [r.message for r in self.policy_results if r.decision == PolicyDecision.WARN]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "decision": self.decision.value,
            "udid": self.udid,
            "target_path": self.target_path,
            "os_version": self.os_version,
            "build_id": self.build_id,
            "blockers": self.blockers,
            "warnings": self.warnings,
            "results": [
                {
                    "decision": r.decision.value,
                    "rule": r.rule_name,
                    "message": r.message,
                    "context": r.context,
                }
                for r in self.policy_results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        status_badge = "🟢 PASSED" if self.passed else "🔴 BLOCKED"
        lines = [
            f"# Safety Gate Enforcement: {status_badge}",
            "",
            f"- **Final Decision**: `{self.decision.value}`",
            f"- **Target UDID**: `{self.udid}`",
            f"- **Target Path**: `{self.target_path}`",
            f"- **Platform Version**: iOS `{self.os_version}` (Build `{self.build_id}`)",
            "",
        ]

        if self.blockers:
            lines.extend([
                "### Blocking Violations",
                "",
            ])
            for b in self.blockers:
                lines.append(f"- ⛔ **{b}**")
            lines.append("")

        if self.warnings:
            lines.extend([
                "### Warnings",
                "",
            ])
            for w in self.warnings:
                lines.append(f"- ⚠️ {w}")
            lines.append("")

        return "\n".join(lines)


@dataclass
class SafetyGateConfig:
    blocked_udids: set[str] = field(default_factory=set)
    allowed_udids: set[str] | None = None
    tested_builds: set[str] = field(default_factory=lambda: set(TESTED_IOS27_BUILDS))
    protected_paths: tuple[str, ...] = PROTECTED_SYSTEM_PATHS
    strict_version_check: bool = True

    @classmethod
    def from_env(cls) -> SafetyGateConfig:
        env_blocked = os.environ.get("AIRLIFT_BLOCKED_UDIDS", "")
        blocked = {u.strip() for u in env_blocked.split(",") if u.strip()}

        env_allowed = os.environ.get("AIRLIFT_ALLOWED_UDIDS", "")
        allowed = {u.strip() for u in env_allowed.split(",") if u.strip()} if env_allowed else None

        return cls(blocked_udids=blocked, allowed_udids=allowed)


class SafetyGate:
    """Enforces safety rules to isolate protected devices and sensitive OS paths."""

    def __init__(self, config: SafetyGateConfig | None = None):
        self.config = config if config is not None else SafetyGateConfig.from_env()

    def check_udid(self, udid: str) -> PolicyResult:
        cleaned = udid.strip().upper()
        norm_blocked = {b.strip().upper() for b in self.config.blocked_udids}

        # 1. Blocklist check (primary phone protection)
        if cleaned in norm_blocked:
            return PolicyResult(
                decision=PolicyDecision.BLOCK,
                rule_name="PRIMARY_DEVICE_BLOCKLIST",
                message=f"Device UDID '{udid}' is on the protected primary device blocklist.",
                context={"udid": udid},
            )

        # 2. Allowlist check if configured
        if self.config.allowed_udids is not None:
            norm_allowed = {a.strip().upper() for a in self.config.allowed_udids}
            if cleaned not in norm_allowed:
                return PolicyResult(
                    decision=PolicyDecision.BLOCK,
                    rule_name="DEVICE_NOT_ALLOWLISTED",
                    message=f"Device UDID '{udid}' is not in the authorized test allowlist.",
                    context={"udid": udid, "allowed": list(self.config.allowed_udids)},
                )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            rule_name="DEVICE_POLICY_PASSED",
            message=f"Device UDID '{udid}' passed all device access policies.",
            context={"udid": udid},
        )

    def check_version(self, os_version: str, build_id: str) -> PolicyResult:
        build_clean = build_id.strip()
        if build_clean in self.config.tested_builds:
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                rule_name="TESTED_BUILD_VERIFIED",
                message=f"Build '{build_id}' (iOS {os_version}) is confirmed in the tested verified matrix.",
                context={"version": os_version, "build": build_id},
            )

        if self.config.strict_version_check:
            return PolicyResult(
                decision=PolicyDecision.BLOCK,
                rule_name="UNTESTED_BUILD_REJECTED",
                message=f"Build '{build_id}' (iOS {os_version}) has not been tested in research lab matrix.",
                context={"version": os_version, "build": build_id, "tested": list(self.config.tested_builds)},
            )
        else:
            return PolicyResult(
                decision=PolicyDecision.WARN,
                rule_name="UNTESTED_BUILD_WARNING",
                message=f"Build '{build_id}' is untested. Proceed with caution.",
                context={"version": os_version, "build": build_id},
            )

    def check_target_path(self, target_path: str) -> PolicyResult:
        normalized = posixpath.normpath(target_path)
        for protected in self.config.protected_paths:
            if normalized == protected or normalized.startswith(protected.rstrip("/") + "/"):
                return PolicyResult(
                    decision=PolicyDecision.BLOCK,
                    rule_name="SECURITY_STATE_RECOVERY_PROTECTION",
                    message=(
                        f"Target path '{normalized}' enters protected system directory '{protected}'. "
                        "Modifications here trigger iOS 27 Security State Recovery (all data wiped)."
                    ),
                    context={"path": target_path, "protected_root": protected},
                )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            rule_name="PATH_ISOLATION_PASSED",
            message=f"Path '{normalized}' is isolated from critical system wiping hazard zones.",
            context={"path": normalized},
        )

    def enforce(
        self,
        udid: str,
        target_path: str,
        os_version: str = "27.0",
        build_id: str = "24A435",
    ) -> GateEnforcementResult:
        results = [
            self.check_udid(udid),
            self.check_version(os_version, build_id),
            self.check_target_path(target_path),
        ]

        has_block = any(r.decision == PolicyDecision.BLOCK for r in results)
        has_warn = any(r.decision == PolicyDecision.WARN for r in results)

        if has_block:
            decision = PolicyDecision.BLOCK
            passed = False
        elif has_warn:
            decision = PolicyDecision.WARN
            passed = True
        else:
            decision = PolicyDecision.ALLOW
            passed = True

        return GateEnforcementResult(
            passed=passed,
            decision=decision,
            udid=udid,
            target_path=target_path,
            os_version=os_version,
            build_id=build_id,
            policy_results=results,
        )
