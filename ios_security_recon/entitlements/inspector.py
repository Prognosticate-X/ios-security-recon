"""
Entitlement Inspector for static audit of Apple platform binaries.
Evaluates security posture against platform permissions and sandbox rules.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .parser import extract_entitlements
from .rules import DEFAULT_RULES, Finding, Rule, RuleSeverity


@dataclass
class InspectorReport:
    target: str
    total_entitlements: int
    score: int
    compliance_status: str  # PASS, WARN, FAIL
    findings: list[Finding]
    private_entitlements: list[str]
    all_entitlements: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total_entitlements": self.total_entitlements,
            "score": self.score,
            "compliance_status": self.compliance_status,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "key": f.key,
                    "value": f.value,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
            "private_entitlements": self.private_entitlements,
            "all_entitlements": self.all_entitlements,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        lines = [
            f"# Entitlement Security Audit: `{self.target}`",
            "",
            f"- **Compliance Status**: `{self.compliance_status}`",
            f"- **Security Score**: **{self.score}/100**",
            f"- **Total Entitlements**: {self.total_entitlements}",
            f"- **Total Findings**: {len(self.findings)}",
            f"- **Private Apple Entitlements**: {len(self.private_entitlements)}",
            "",
        ]

        if self.findings:
            lines.extend([
                "## Security Findings",
                "",
                "| Severity | Rule ID | Title | Key | Remediation |",
                "|---|---|---|---|---|",
            ])
            for f in self.findings:
                lines.append(
                    f"| **{f.severity.value}** | `{f.rule_id}` | {f.rule_name} | `{f.key}` | {f.remediation} |"
                )
            lines.append("")

        if self.private_entitlements:
            lines.extend([
                "## Private System Entitlements Detected",
                "",
            ])
            for p in self.private_entitlements:
                lines.append(f"- `{p}`")
            lines.append("")

        return "\n".join(lines)


class EntitlementInspector:
    """Audits target binaries or plists against defensive security rules."""

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else list(DEFAULT_RULES)

    def inspect(self, target: str | Path | dict[str, Any] | bytes) -> InspectorReport:
        target_name = "in-memory-entitlements"
        if isinstance(target, (str, Path)):
            target_name = str(target)
            entitlements = extract_entitlements(target)
        elif isinstance(target, (bytes, bytearray)):
            entitlements = extract_entitlements(target)
        elif isinstance(target, dict):
            entitlements = target
        else:
            raise TypeError(f"Unsupported target type: {type(target)}")

        findings: list[Finding] = []
        for rule in self.rules:
            rule_findings = rule.checker(entitlements)
            findings.extend(rule_findings)

        # Detect all private apple keys
        private_keys = [
            k for k in sorted(entitlements.keys())
            if k.startswith("com.apple.private.")
            or k.startswith("com.apple.rootless.")
            or k.startswith("com.apple.springboard.")
            or k.startswith("com.apple.systemstatus.")
        ]

        # Calculate penalty score
        score = 100
        critical_count = 0
        high_count = 0

        for f in findings:
            if f.severity == RuleSeverity.CRITICAL:
                score -= 30
                critical_count += 1
            elif f.severity == RuleSeverity.HIGH:
                score -= 15
                high_count += 1
            elif f.severity == RuleSeverity.MEDIUM:
                score -= 5
            elif f.severity == RuleSeverity.LOW:
                score -= 2

        score = max(0, score)

        if critical_count > 0 or score < 70:
            compliance = "FAIL"
        elif high_count > 0 or score < 90:
            compliance = "WARN"
        else:
            compliance = "PASS"

        return InspectorReport(
            target=target_name,
            total_entitlements=len(entitlements),
            score=score,
            compliance_status=compliance,
            findings=findings,
            private_entitlements=private_keys,
            all_entitlements=entitlements,
        )
