"""
Entitlements module for static extraction, diffing, and security posture auditing.
"""

from .parser import extract_entitlements, EntitlementParserError
from .diff import EntitlementDiff, diff_entitlements
from .inspector import EntitlementInspector, InspectorReport
from .rules import DEFAULT_RULES, Rule, RuleSeverity

__all__ = [
    "extract_entitlements",
    "EntitlementParserError",
    "EntitlementDiff",
    "diff_entitlements",
    "EntitlementInspector",
    "InspectorReport",
    "DEFAULT_RULES",
    "Rule",
    "RuleSeverity",
]
