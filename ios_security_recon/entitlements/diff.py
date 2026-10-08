"""
Static entitlement differ between Apple platform binaries or plist profiles.
Detects added, removed, and modified entitlements with privilege escalation analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .parser import extract_entitlements


SENSITIVE_PREFIXES = (
    "com.apple.private.",
    "com.apple.rootless.",
    "com.apple.springboard.",
    "com.apple.systemstatus.",
    "com.apple.security.temporary-exception.",
)

SENSITIVE_EXACT_KEYS = frozenset({
    "get-task-allow",
    "task_for_pid-allow",
    "platform-application",
    "seatbelt-profiles",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.private.tcc.allow",
    "keychain-access-groups",
})


def is_sensitive_key(key: str) -> bool:
    if key in SENSITIVE_EXACT_KEYS:
        return True
    return any(key.startswith(p) for p in SENSITIVE_PREFIXES)


@dataclass
class EntitlementDiff:
    baseline_target: str
    target: str
    added: dict[str, Any]
    removed: dict[str, Any]
    modified: dict[str, dict[str, Any]]  # key -> {"baseline": v1, "target": v2}
    unchanged: dict[str, Any]
    sensitive_added: list[str]
    privilege_escalation_risk: bool
    escalation_reasons: list[str]

    @property
    def has_differences(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline_target,
            "target": self.target,
            "has_differences": self.has_differences,
            "counts": {
                "added": len(self.added),
                "removed": len(self.removed),
                "modified": len(self.modified),
                "unchanged": len(self.unchanged),
                "sensitive_added": len(self.sensitive_added),
            },
            "privilege_escalation_risk": self.privilege_escalation_risk,
            "escalation_reasons": self.escalation_reasons,
            "sensitive_added": self.sensitive_added,
            "added": self.added,
            "removed": self.removed,
            "modified": self.modified,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        lines = [
            f"# Entitlement Diff: `{self.baseline_target}` vs `{self.target}`",
            "",
            f"- **Differences Found**: `{'YES' if self.has_differences else 'NO'}`",
            f"- **Privilege Escalation Risk**: `{'HIGH RISK' if self.privilege_escalation_risk else 'LOW'}`",
            f"- **Added**: {len(self.added)} (Sensitive: {len(self.sensitive_added)})",
            f"- **Removed**: {len(self.removed)}",
            f"- **Modified**: {len(self.modified)}",
            f"- **Unchanged**: {len(self.unchanged)}",
            "",
        ]

        if self.escalation_reasons:
            lines.extend([
                "### Privilege Escalation Alerts",
                "",
            ])
            for r in self.escalation_reasons:
                lines.append(f"- ⚠️ **{r}**")
            lines.append("")

        if self.added:
            lines.extend([
                "### Added Entitlements",
                "",
                "| Entitlement Key | Value | Sensitive |",
                "|---|---|---|",
            ])
            for k, v in sorted(self.added.items()):
                sens = "YES" if k in self.sensitive_added else "NO"
                lines.append(f"| `{k}` | `{v}` | `{sens}` |")
            lines.append("")

        if self.modified:
            lines.extend([
                "### Modified Entitlements",
                "",
                "| Entitlement Key | Baseline Value | Target Value |",
                "|---|---|---|",
            ])
            for k, diff_vals in sorted(self.modified.items()):
                lines.append(f"| `{k}` | `{diff_vals['baseline']}` | `{diff_vals['target']}` |")
            lines.append("")

        if self.removed:
            lines.extend([
                "### Removed Entitlements",
                "",
                "| Entitlement Key | Previous Baseline Value |",
                "|---|---|",
            ])
            for k, v in sorted(self.removed.items()):
                lines.append(f"| `{k}` | `{v}` |")
            lines.append("")

        return "\n".join(lines)


def diff_entitlements(
    baseline: str | Path | dict[str, Any] | bytes,
    target: str | Path | dict[str, Any] | bytes,
) -> EntitlementDiff:
    """Computes the difference between two entitlement sets."""
    b_name = str(baseline) if isinstance(baseline, (str, Path)) else "baseline"
    t_name = str(target) if isinstance(target, (str, Path)) else "target"

    b_dict = extract_entitlements(baseline) if not isinstance(baseline, dict) else baseline
    t_dict = extract_entitlements(target) if not isinstance(target, dict) else target

    added: dict[str, Any] = {}
    removed: dict[str, Any] = {}
    modified: dict[str, dict[str, Any]] = {}
    unchanged: dict[str, Any] = {}

    all_keys = set(b_dict.keys()) | set(t_dict.keys())

    for k in sorted(all_keys):
        in_b = k in b_dict
        in_t = k in t_dict

        if in_t and not in_b:
            added[k] = t_dict[k]
        elif in_b and not in_t:
            removed[k] = b_dict[k]
        else:
            if b_dict[k] == t_dict[k]:
                unchanged[k] = b_dict[k]
            else:
                modified[k] = {
                    "baseline": b_dict[k],
                    "target": t_dict[k],
                }

    sensitive_added = [k for k in sorted(added.keys()) if is_sensitive_key(k)]

    escalation_reasons: list[str] = []
    if "get-task-allow" in added and added["get-task-allow"] is True:
        escalation_reasons.append("Added 'get-task-allow' grants runtime process debugging.")
    if "task_for_pid-allow" in added and added["task_for_pid-allow"] is True:
        escalation_reasons.append("Added 'task_for_pid-allow' grants process task port acquisition.")
    if "platform-application" in added and added["platform-application"] is True:
        escalation_reasons.append("Added 'platform-application' elevates daemon to platform trust.")
    for k in sensitive_added:
        if k.startswith("com.apple.private."):
            escalation_reasons.append(f"Added Apple private capability '{k}'.")
        elif k.startswith("com.apple.rootless."):
            escalation_reasons.append(f"Added rootless/SIP storage exception '{k}'.")
        elif k.startswith("com.apple.security.temporary-exception."):
            escalation_reasons.append(f"Added sandbox filesystem exception '{k}'.")

    privilege_escalation_risk = len(escalation_reasons) > 0

    return EntitlementDiff(
        baseline_target=b_name,
        target=t_name,
        added=added,
        removed=removed,
        modified=modified,
        unchanged=unchanged,
        sensitive_added=sensitive_added,
        privilege_escalation_risk=privilege_escalation_risk,
        escalation_reasons=escalation_reasons,
    )
