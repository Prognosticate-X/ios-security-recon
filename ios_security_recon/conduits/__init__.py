"""
Conduits module for auditing file transfer surfaces, backup domains, and deployment safety gates.
"""

from .surface_audit import (
    PathAuditResult,
    ArchiveAuditResult,
    BackupPathAuditResult,
    audit_path_normalization,
    audit_streaming_archive,
    audit_backup_domain_path,
)
from .safety_gate import (
    SafetyGate,
    SafetyGateConfig,
    PolicyDecision,
    PolicyResult,
    GateEnforcementResult,
)

__all__ = [
    "PathAuditResult",
    "ArchiveAuditResult",
    "BackupPathAuditResult",
    "audit_path_normalization",
    "audit_streaming_archive",
    "audit_backup_domain_path",
    "SafetyGate",
    "SafetyGateConfig",
    "PolicyDecision",
    "PolicyResult",
    "GateEnforcementResult",
]
