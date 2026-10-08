"""
XPC static analysis module for Apple platform Mach-O binaries and system daemons.
"""

from .parser import MachOParser, MachOSection
from .scanner import XPCScanner, XPCScanResult

__all__ = [
    "MachOParser",
    "MachOSection",
    "XPCScanner",
    "XPCScanResult",
]
