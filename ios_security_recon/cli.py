"""
Command-line interface for ios-security-recon (ios-recon).
Unified tooling for entitlement diffing, inspection, conduit auditing, and XPC analysis.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .conduits.safety_gate import SafetyGate
from .conduits.surface_audit import (
    DEFAULT_ALLOWED_SPRINGBOARD_TARGETS,
    audit_path_normalization,
    audit_streaming_archive,
)
from .entitlements.diff import diff_entitlements
from .entitlements.inspector import EntitlementInspector
from .reporting.reporter import SecurityReporter
from .xpc.scanner import XPCScanner


def _output_result(content: str, output_path: str | None = None) -> None:
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        print(f"[*] Report saved to {output_path}")
    else:
        print(content)


def handle_entitlements_diff(args: argparse.Namespace) -> int:
    try:
        diff_res = diff_entitlements(args.file1, args.file2)
    except Exception as e:
        print(f"[!] Error performing entitlement diff: {e}", file=sys.stderr)
        return 1

    fmt = args.format.lower()
    if fmt == "json":
        _output_result(diff_res.to_json(), args.output)
    elif fmt == "markdown":
        _output_result(diff_res.to_markdown(), args.output)
    else:
        # Text output
        lines = [
            f"=== Entitlements Diff ===",
            f"Baseline: {args.file1}",
            f"Target:   {args.file2}",
            f"Differences: {'YES' if diff_res.has_differences else 'NO'}",
            f"Privilege Escalation Risk: {'HIGH' if diff_res.privilege_escalation_risk else 'LOW'}",
            f"Added:    {len(diff_res.added)}",
            f"Removed:  {len(diff_res.removed)}",
            f"Modified: {len(diff_res.modified)}",
        ]
        if diff_res.escalation_reasons:
            lines.append("\n[!] Privilege Escalation Warnings:")
            for r in diff_res.escalation_reasons:
                lines.append(f"  * {r}")
        if diff_res.added:
            lines.append("\n[+] Added Entitlements:")
            rows = [[k, str(v)] for k, v in sorted(diff_res.added.items())]
            lines.append(SecurityReporter.render_table(["Key", "Value"], rows))
        if diff_res.modified:
            lines.append("\n[*] Modified Entitlements:")
            rows = [[k, str(v["baseline"]), str(v["target"])] for k, v in sorted(diff_res.modified.items())]
            lines.append(SecurityReporter.render_table(["Key", "Baseline", "Target"], rows))
        if diff_res.removed:
            lines.append("\n[-] Removed Entitlements:")
            for k in sorted(diff_res.removed.keys()):
                lines.append(f"  - {k}")
        _output_result("\n".join(lines), args.output)

    return 1 if diff_res.privilege_escalation_risk else 0


def handle_entitlements_inspect(args: argparse.Namespace) -> int:
    inspector = EntitlementInspector()
    try:
        rep = inspector.inspect(args.file)
    except Exception as e:
        print(f"[!] Error inspecting entitlements: {e}", file=sys.stderr)
        return 1

    fmt = args.format.lower()
    if fmt == "json":
        _output_result(rep.to_json(), args.output)
    elif fmt == "markdown":
        _output_result(rep.to_markdown(), args.output)
    else:
        status_symbol = {"PASS": "[PASS]", "WARN": "[WARN]", "FAIL": "[FAIL]"}.get(rep.compliance_status, "")
        lines = [
            f"=== Entitlement Security Audit ===",
            f"Target:             {args.file}",
            f"Compliance Status:  {status_symbol} {rep.compliance_status}",
            f"Security Score:     {rep.score} / 100",
            f"Total Entitlements: {rep.total_entitlements}",
            f"Findings:           {len(rep.findings)}",
            f"Private Apple Keys: {len(rep.private_entitlements)}",
        ]
        if rep.findings:
            lines.append("\n[!] Findings:")
            rows = [
                [f.severity.value, f.rule_id, f.key, f.description[:50] + "..." if len(f.description) > 50 else f.description]
                for f in rep.findings
            ]
            lines.append(SecurityReporter.render_table(["Severity", "Rule", "Key", "Description"], rows))

        if rep.private_entitlements:
            lines.append("\n[*] Private Apple Entitlements:")
            for p in rep.private_entitlements:
                lines.append(f"  * {p}")

        _output_result("\n".join(lines), args.output)

    if args.strict and rep.compliance_status != "PASS":
        return 1
    return 1 if rep.compliance_status == "FAIL" else 0


def handle_conduit_audit(args: argparse.Namespace) -> int:
    path_arg = args.path
    roots = tuple(r.strip() for r in args.roots.split(",")) if args.roots else DEFAULT_ALLOWED_SPRINGBOARD_TARGETS
    fmt = args.format.lower()

    # Determine if target is a file or string path
    is_zip = False
    p = Path(path_arg)
    if p.is_file():
        try:
            with open(p, "rb") as f:
                header = f.read(4)
                if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
                    is_zip = True
        except Exception:
            pass

    if is_zip:
        res = audit_streaming_archive(p, allowed_targets=roots)
        if fmt == "json":
            _output_result(json.dumps(res.to_dict(), indent=2), args.output)
        elif fmt == "markdown":
            md = [
                f"# Conduit Archive Audit: `{p.name}`",
                "",
                f"- **Safe**: `{'YES' if res.is_safe else 'NO'}`",
                f"- **Zip Slip**: `{'YES' if res.has_zip_slip else 'NO'}`",
                f"- **Symlink Breakout**: `{'YES' if res.has_symlink_breakout else 'NO'}`",
                f"- **Entries**: {res.total_entries}",
                "",
            ]
            if res.violations:
                md.append("### Violations:\n")
                for v in res.violations:
                    md.append(f"- ⛔ {v}")
            _output_result("\n".join(md), args.output)
        else:
            lines = [
                f"=== Conduit Streaming Archive Audit ===",
                f"Archive:          {p}",
                f"Status:           {'[PASS] SAFE' if res.is_safe else '[FAIL] VULNERABLE'}",
                f"Zip Slip:         {'YES' if res.has_zip_slip else 'NO'}",
                f"Symlink Breakout: {'YES' if res.has_symlink_breakout else 'NO'}",
                f"Total Entries:    {res.total_entries}",
            ]
            if res.violations:
                lines.append("\n[!] Violations:")
                for v in res.violations:
                    lines.append(f"  * {v}")
            if res.symlinks_detected:
                lines.append("\n[*] Symlinks:")
                for s in res.symlinks_detected:
                    lines.append(f"  * {s['entry']} -> {s['target']}")
            _output_result("\n".join(lines), args.output)

        return 0 if res.is_safe else 1
    else:
        # Standard path normalization audit
        p_res = audit_path_normalization(path_arg, allowed_roots=roots)
        if fmt == "json":
            _output_result(json.dumps(p_res.to_dict(), indent=2), args.output)
        elif fmt == "markdown":
            md = [
                f"# Conduit Path Audit: `{path_arg}`",
                "",
                f"- **Safe**: `{'YES' if p_res.is_safe else 'NO'}`",
                f"- **Normalized**: `{p_res.normalized_path}`",
                "",
            ]
            if p_res.violations:
                md.append("### Violations:\n")
                for v in p_res.violations:
                    md.append(f"- ⛔ {v}")
            _output_result("\n".join(md), args.output)
        else:
            lines = [
                f"=== Conduit Path Normalization Audit ===",
                f"Input Path:      {p_res.original_path}",
                f"Normalized:      {p_res.normalized_path}",
                f"Status:          {'[PASS] SAFE' if p_res.is_safe else '[FAIL] REJECTED'}",
            ]
            if p_res.violations:
                lines.append("\n[!] Violations:")
                for v in p_res.violations:
                    lines.append(f"  * {v}")
            _output_result("\n".join(lines), args.output)

        return 0 if p_res.is_safe else 1


def handle_conduit_gate(args: argparse.Namespace) -> int:
    gate = SafetyGate()
    result = gate.enforce(
        udid=args.udid,
        target_path=args.target,
        os_version=args.os_version,
        build_id=args.build,
    )
    fmt = args.format.lower()
    if fmt == "json":
        _output_result(result.to_json(), args.output)
    elif fmt == "markdown":
        _output_result(result.to_markdown(), args.output)
    else:
        lines = [
            f"=== Conduit Safety Gate Enforcement ===",
            f"UDID:         {result.udid}",
            f"Target:       {result.target_path}",
            f"OS Version:   iOS {result.os_version} (Build {result.build_id})",
            f"Gate Passed:  {'YES' if result.passed else 'NO'}",
            f"Decision:     {result.decision.value}",
        ]
        if result.blockers:
            lines.append("\n[!] Blockers:")
            for b in result.blockers:
                lines.append(f"  * ⛔ {b}")
        if result.warnings:
            lines.append("\n[*] Warnings:")
            for w in result.warnings:
                lines.append(f"  * ⚠️ {w}")
        _output_result("\n".join(lines), args.output)

    return 0 if result.passed else 1


def handle_xpc_scan(args: argparse.Namespace) -> int:
    scanner = XPCScanner()
    try:
        res = scanner.scan(args.file)
    except Exception as e:
        print(f"[!] Error scanning Mach-O binary: {e}", file=sys.stderr)
        return 1

    fmt = args.format.lower()
    if fmt == "json":
        _output_result(res.to_json(), args.output)
    elif fmt == "markdown":
        _output_result(res.to_markdown(), args.output)
    else:
        lines = [
            f"=== XPC Static Security Scan ===",
            f"Target:           {res.target}",
            f"Mach-O Binary:    {'YES' if res.is_macho else 'NO'}",
            f"XPC Server:       {'YES' if res.is_xpc_server else 'NO'}",
            f"Exposure Level:   {res.exposure_level}",
            f"Strings Analyzed: {res.total_strings_scanned}",
        ]
        if res.mach_services:
            lines.append("\n[*] Mach Services:")
            for s in res.mach_services:
                lines.append(f"  * {s}")
        if res.security_checks:
            lines.append("\n[+] Security Checks Detected:")
            for c in res.security_checks:
                lines.append(f"  * {c}")
        if res.referenced_entitlements:
            lines.append("\n[*] Referenced Entitlements:")
            for ent in res.referenced_entitlements:
                lines.append(f"  * {ent}")
        if res.xpc_selectors:
            lines.append(f"\n[*] XPC Selectors ({len(res.xpc_selectors)}):")
            for sel in res.xpc_selectors[:15]:
                lines.append(f"  * {sel}")
            if len(res.xpc_selectors) > 15:
                lines.append(f"  * ... ({len(res.xpc_selectors) - 15} more)")
        _output_result("\n".join(lines), args.output)

    return 0


def handle_report(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"[!] Target not found: {target}", file=sys.stderr)
        return 1

    # Run automated inspector and XPC scan
    inspector_report = None
    xpc_report = None
    archive_report = None
    path_report = None

    try:
        inspector_report = EntitlementInspector().inspect(target)
    except Exception:
        pass

    try:
        xpc_report = XPCScanner().scan(target)
    except Exception:
        pass

    fmt = args.format.lower()
    if fmt == "json":
        data = SecurityReporter.generate_full_report(
            target_name=str(target),
            inspector_report=inspector_report,
            xpc_scan=xpc_report,
        )
        _output_result(SecurityReporter.render_json(data), args.output)
    else:
        md = SecurityReporter.generate_full_markdown(
            target_name=str(target),
            inspector_report=inspector_report,
            xpc_scan=xpc_report,
        )
        _output_result(md, args.output)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ios-recon",
        description="Defensive Platform Security & Entitlement Audit Toolchain for iOS 27 & macOS",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # entitlements
    p_ent = subparsers.add_parser("entitlements", help="Entitlement auditing and comparison")
    ent_sub = p_ent.add_subparsers(dest="ent_command", required=True)

    p_diff = ent_sub.add_parser("diff", help="Diff entitlements between two binaries or plists")
    p_diff.add_argument("file1", help="Baseline binary or plist file")
    p_diff.add_argument("file2", help="Target binary or plist file")
    p_diff.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="Output format")
    p_diff.add_argument("--output", "-o", help="Write report to output file")

    p_insp = ent_sub.add_parser("inspect", help="Inspect binary or plist for security compliance")
    p_insp.add_argument("file", help="Target binary or plist file")
    p_insp.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="Output format")
    p_insp.add_argument("--strict", action="store_true", help="Fail if not completely passing")
    p_insp.add_argument("--output", "-o", help="Write report to output file")

    # conduit
    p_conduit = subparsers.add_parser("conduit", help="Audit file transfer conduits and safety gates")
    conduit_sub = p_conduit.add_subparsers(dest="conduit_command", required=True)

    p_c_audit = conduit_sub.add_parser("audit", help="Audit path normalization or streaming zip archive")
    p_c_audit.add_argument("path", help="Target path string or streaming zip archive file")
    p_c_audit.add_argument("--roots", help="Comma-separated allowed root directory prefixes")
    p_c_audit.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p_c_audit.add_argument("--output", "-o", help="Write report to output file")

    p_c_gate = conduit_sub.add_parser("gate", help="Enforce deployment safety gate on UDID and target path")
    p_c_gate.add_argument("--udid", required=True, help="Target device UDID")
    p_c_gate.add_argument("--target", required=True, help="Target path on device")
    p_c_gate.add_argument("--os-version", default="27.0", help="Target iOS version (default: 27.0)")
    p_c_gate.add_argument("--build", default="24A435", help="Target build number (default: 24A435)")
    p_c_gate.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p_c_gate.add_argument("--output", "-o", help="Write report to output file")

    # xpc
    p_xpc = subparsers.add_parser("xpc", help="Analyze Mach-O binaries for XPC protocols and security checks")
    xpc_sub = p_xpc.add_subparsers(dest="xpc_command", required=True)
    p_xpc_scan = xpc_sub.add_parser("scan", help="Scan Mach-O binary for XPC interfaces and entitlement checks")
    p_xpc_scan.add_argument("file", help="Target Mach-O binary file")
    p_xpc_scan.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p_xpc_scan.add_argument("--output", "-o", help="Write report to output file")

    # report
    p_rep = subparsers.add_parser("report", help="Generate comprehensive security reconnaissance report")
    p_rep.add_argument("--target", "-t", required=True, help="Target binary or package to audit")
    p_rep.add_argument("--format", choices=["json", "markdown"], default="markdown")
    p_rep.add_argument("--output", "-o", help="Write report to output file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "entitlements":
        if args.ent_command == "diff":
            return handle_entitlements_diff(args)
        elif args.ent_command == "inspect":
            return handle_entitlements_inspect(args)
    elif args.command == "conduit":
        if args.conduit_command == "audit":
            return handle_conduit_audit(args)
        elif args.conduit_command == "gate":
            return handle_conduit_gate(args)
    elif args.command == "xpc":
        if args.xpc_command == "scan":
            return handle_xpc_scan(args)
    elif args.command == "report":
        return handle_report(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
