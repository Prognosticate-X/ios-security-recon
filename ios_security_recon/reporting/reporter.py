"""
Structured report generation engine for ios-security-recon.
Outputs terminal ANSI colored summaries, Markdown documents, and machine-readable JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..conduits.safety_gate import GateEnforcementResult
from ..conduits.surface_audit import ArchiveAuditResult, PathAuditResult
from ..entitlements.diff import EntitlementDiff
from ..entitlements.inspector import InspectorReport
from ..xpc.scanner import XPCScanResult


class SecurityReporter:
    """Consolidates and renders security recon results into multiple output formats."""

    @staticmethod
    def render_json(payload: dict[str, Any], indent: int = 2) -> str:
        return json.dumps(payload, indent=indent, default=str)

    @staticmethod
    def render_table(headers: list[str], rows: list[list[str]]) -> str:
        if not rows:
            return ""
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        fmt = " | ".join(f"{{:<{w}}}" for w in widths)
        separator = "-+-".join("-" * w for w in widths)

        lines = [
            fmt.format(*headers),
            separator,
        ]
        for row in rows:
            # pad row if needed
            padded = row + [""] * (len(headers) - len(row))
            lines.append(fmt.format(*[str(c) for c in padded]))

        return "\n".join(lines)

    @classmethod
    def generate_full_report(
        cls,
        target_name: str,
        inspector_report: InspectorReport | None = None,
        diff_report: EntitlementDiff | None = None,
        path_audit: PathAuditResult | None = None,
        archive_audit: ArchiveAuditResult | None = None,
        xpc_scan: XPCScanResult | None = None,
        gate_result: GateEnforcementResult | None = None,
    ) -> dict[str, Any]:
        """Creates a unified JSON-serializable report dictionary."""
        return {
            "meta": {
                "tool": "ios-security-recon",
                "target": target_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "entitlements_inspection": inspector_report.to_dict() if inspector_report else None,
            "entitlements_diff": diff_report.to_dict() if diff_report else None,
            "conduit_path_audit": path_audit.to_dict() if path_audit else None,
            "conduit_archive_audit": archive_audit.to_dict() if archive_audit else None,
            "xpc_scan": xpc_scan.to_dict() if xpc_scan else None,
            "safety_gate": gate_result.to_dict() if gate_result else None,
        }

    @classmethod
    def generate_full_markdown(
        cls,
        target_name: str,
        inspector_report: InspectorReport | None = None,
        diff_report: EntitlementDiff | None = None,
        path_audit: PathAuditResult | None = None,
        archive_audit: ArchiveAuditResult | None = None,
        xpc_scan: XPCScanResult | None = None,
        gate_result: GateEnforcementResult | None = None,
    ) -> str:
        """Renders a comprehensive markdown security analysis report."""
        sections = [
            f"# Apple Platform Security Reconnaissance Report",
            f"**Target**: `{target_name}`  ",
            f"**Generated**: `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
            "---",
        ]

        if gate_result:
            sections.append(gate_result.to_markdown())
            sections.append("---")

        if inspector_report:
            sections.append(inspector_report.to_markdown())
            sections.append("---")

        if diff_report:
            sections.append(diff_report.to_markdown())
            sections.append("---")

        if path_audit:
            status = "🟢 SAFE" if path_audit.is_safe else "🔴 VIOLATIONS"
            sections.append(
                f"## Path Normalization Audit: {status}\n\n"
                f"- **Input**: `{path_audit.original_path}`\n"
                f"- **Normalized**: `{path_audit.normalized_path}`\n"
            )
            if path_audit.violations:
                sections.append("\n### Violations:")
                for v in path_audit.violations:
                    sections.append(f"- ⛔ {v}")
            sections.append("\n---")

        if archive_audit:
            status = "🟢 SAFE" if archive_audit.is_safe else "🔴 HIGH RISK"
            sections.append(
                f"## Conduit Archive Security Audit: {status}\n\n"
                f"- **Archive**: `{archive_audit.source_name}`\n"
                f"- **Total Entries**: {archive_audit.total_entries}\n"
                f"- **Zip Slip**: `{'YES' if archive_audit.has_zip_slip else 'NO'}`\n"
                f"- **Symlink Breakout**: `{'YES' if archive_audit.has_symlink_breakout else 'NO'}`\n"
            )
            if archive_audit.violations:
                sections.append("\n### Violations:")
                for v in archive_audit.violations:
                    sections.append(f"- ⛔ {v}")
            sections.append("\n---")

        if xpc_scan:
            sections.append(xpc_scan.to_markdown())
            sections.append("---")

        return "\n\n".join(sections)
