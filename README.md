# ios-security-recon

> **Defensive Platform Security & Entitlement Audit Toolchain for iOS 27 & macOS**

[English](README.md) | [简体中文](README_ZH.md)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Security Focus](https://img.shields.io/badge/focus-Defensive%20Security%20%26%20Audit-red.svg)](#security-and-responsible-disclosure)

---

## 1. Project Philosophy & Notice

**`ios-security-recon`** is an open-source, defensive static analysis and compliance auditing toolchain engineered for Apple platforms (iOS 27 and macOS). It enables security engineers, system administrators, and mobile security researchers to:
- Audit and diff code signature entitlements across system binaries, profiles, and Mach-O executables.
- Statically evaluate file transfer conduits (`MobileBackup2`, `AirTraffic`, `ATAirlock`) against path normalization vulnerabilities and iOS 27 Security State Recovery (SSR) wipe triggers.
- Enforce strict pre-deployment hardware safety gates (UDID allowlists/blocklists) to guarantee daily driver devices are never subject to experimental procedures.
- Extract XPC service interfaces, Objective-C selectors, and client entitlement verification checks from Mach-O system daemons.

> [!IMPORTANT]
> **Defensive & Educational Security Research Only**: This repository does NOT contain exploits, jailbreak payloads, or weaponized bypasses. All utilities are strictly static inspection and policy enforcement tools designed to uphold platform security boundaries and adhere to the [Apple Security Bounty](https://security.apple.com/bounty) guidelines.

---

## 2. Key Modules & Capabilities

```text
ios_security_recon/
├── entitlements/        # Static extraction, diffing, and compliance audit engine
│   ├── parser.py        # Mach-O (32/64-bit & FAT) & plist parser
│   ├── diff.py          # Entitlement differ with privilege escalation detection
│   ├── inspector.py     # Posture scoring & compliance rule engine
│   └── rules.py         # Standard Apple security best practice rules
├── conduits/            # File transfer & synchronization surface analysis
│   ├── surface_audit.py # Path traversal, Zip Slip, ATAirlock symlink analysis
│   └── safety_gate.py   # UDID protection, OS build matrix, & wipe isolation
├── xpc/                 # Static Mach-O analyzer
│   ├── parser.py        # Pure-Python Mach-O section & symbol parser
│   └── scanner.py       # XPC listeners, selectors & audit token checker
├── reporting/           # Report generation (Markdown, ANSI Terminal, JSON)
└── cli.py               # Unified CLI: `ios-recon`
```

### Module Highlights

| Module | Core Functionality | Primary Use Case |
|---|---|---|
| **`entitlements`** | Extracts embedded code signature entitlements from XML, bplist, and Mach-O slices. | Detects `get-task-allow`, `task_for_pid-allow`, private `com.apple.springboard.*` capabilities, and sandbox exemptions. |
| **`conduits`** | Audits file paths and streaming ZIP archives used in device synchronization. | Verifies path normalization, guards against Zip Slip / symlink escapes, and enforces iOS 27 `BackupAgent2` whitelists. |
| **`safety_gate`** | Hardware and version compliance gate. | Blocks accidental operations on designated primary phones (`AIRLIFT_BLOCKED_UDIDS`) and prevents touching wipe-sensitive directories (`/var/preferences`). |
| **`xpc`** | Static Mach-O binary analysis. | Discovers registered Mach services, exported selectors, and confirms whether services verify client audit tokens (`SecTaskCreateWithAuditToken`). |

---

## 3. Quickstart & Installation

### Requirements
- Python 3.9 or newer (tested with Python 3.12).
- Zero external dependencies required (built entirely with the Python standard library).

### Installation
Clone the repository and install in editable mode:
```bash
git clone https://github.com/Prognosticate-X/ios-security-recon.git
cd ios-security-recon
pip install -e .
```
Or run directly via Python without installation:
```bash
python3 -m ios_security_recon.cli --help
```

---

## 4. CLI Usage Guide

The unified CLI tool is `ios-recon`.

### 4.1 Entitlement Auditing & Diffing

#### Inspect a binary or plist for security compliance:
```bash
ios-recon entitlements inspect /path/to/binary_or_plist
```
```bash
# Output in JSON format
ios-recon entitlements inspect /path/to/AppBinary --format json
```

#### Diff entitlements between two binaries:
```bash
ios-recon entitlements diff /path/to/baseline.plist /path/to/target.plist --format markdown
```
Flags newly added private capabilities (`com.apple.private.*`) and privilege escalation risks (e.g. `task_for_pid-allow`).

---

### 4.2 File Transfer & Conduit Auditing

#### Audit path normalization & traversal:
```bash
ios-recon conduit audit "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive"
```

#### Audit an ATAirlock streaming ZIP archive for breakout & Zip Slip:
```bash
ios-recon conduit audit /path/to/streaming_package.zip
```

#### Evaluate safety gate policies before executing deployment:
```bash
ios-recon conduit gate \
  --udid "00008140-001A2B3C4D5E6F7G" \
  --target "/var/mobile/Library/SpringBoard/StatusBarOverrides.archive" \
  --os-version "27.0" \
  --build "24A435"
```

---

### 4.3 Static XPC Mach-O Scanning

Extract registered services, selectors, and client entitlement verification:
```bash
ios-recon xpc scan /path/to/SystemDaemon --format markdown
```

---

### 4.4 Comprehensive Security Reconnaissance Report

Generate a unified markdown security report for a given target:
```bash
ios-recon report --target /path/to/target_binary --output report.md
```

---

## 5. Technical Documentation

Detailed architectural and empirical research documentation is located in [`docs/`](docs/):
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**: Deep dive into iOS 27 SpringBoard, `SystemStatus` publish-subscribe model, and `StatusBarOverrides.archive` deserialization security.
- **[`docs/RESPONSIBLE_DISCLOSURE.md`](docs/RESPONSIBLE_DISCLOSURE.md)**: Guidelines for safe research, test hardware isolation, and reporting to Apple Product Security.
- **[`docs/RESEARCH_NOTES.md`](docs/RESEARCH_NOTES.md)**: Empirical notes on `MobileBackup2` whitelist changes, Security State Recovery (SSR) triggers, and ATAirlock streaming limitations on physical iPhone 16 Pro Max (A18 Pro) hardware.

---

## 6. Running Tests

Run the full automated test suite:
```bash
python3 -m unittest discover -s tests -v
```
All 54 unit tests run in less than 0.05 seconds with zero external dependencies.

---

## 7. License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
