# Responsible Disclosure Policy & Apple Security Research Guidelines

## 1. Commitment to Defensive Research

The `ios-security-recon` project is dedicated strictly to defensive platform security analysis, system entitlement auditing, and educational research. Our goal is to assist developers, platform engineers, and security researchers in understanding Apple platform trust boundaries and preventing inadvertent privilege escalations.

All research activities and tooling associated with this project adhere strictly to industry-standard Coordinated Vulnerability Disclosure (CVD) principles and the **Apple Security Bounty** research guidelines.

---

## 2. Safe Research Red Lines & Operating Rules

To protect device integrity and personal privacy, researchers utilizing this toolchain MUST adhere to the following mandatory operational rules:

1. **Dedicated Hardware Only (No Daily Drivers)**:
   - Security auditing and conduit experiments must NEVER be conducted on primary daily driver devices.
   - Experiments must be restricted to designated secondary test devices or Apple Silicon Simulator environments.
2. **Automated Safety Gate Enforcement**:
   - Researchers must populate the `AIRLIFT_BLOCKED_UDIDS` environment variable with the UDID of all primary personal hardware.
   - The built-in `SafetyGate` engine will block any write or deployment attempt directed toward blocked UDIDs.
3. **Zero High-Risk Directory Writing**:
   - Never write to or tamper with `/var/preferences`, `/var/keychains`, or `/System` on iOS 27 devices.
   - Tampering with these directories activates iOS 27 **Security State Recovery (SSR)**, triggering an automated system wipe.
4. **Mandatory Full Backups & Rollback Plans**:
   - Before executing any device-level test, generate a complete unencrypted or encrypted local backup via Finder/Apple Configurator.
   - Maintain cryptographic hashes (SHA-256) of all modified files and establish an immediate, verified rollback workflow.
5. **No Harm Principle**:
   - Do not degrade platform availability, bypass activation locks, or attempt data exfiltration.

---

## 3. Vulnerability Reporting Protocol (Apple Product Security)

If security analysis using this toolchain uncovers an undocumented sandbox bypass, privilege escalation vector, or parsing vulnerability in an Apple platform component:

### Step 1: Verification & Isolation
- Verify the issue on the latest publicly available iOS release (iOS 27.0+) or beta seed.
- Isolate the minimal reproducible test case.
- Confirm that no third-party data or services are impacted.

### Step 2: Confidential Notification
- Transmit the complete advisory to Apple Product Security:
  - **Email**: `product-security@apple.com`
  - **PGP Key**: Encrypt all submissions using Apple Product Security's official PGP key (available at [Apple Security Research](https://security.apple.com)).
  - **Web Portal**: Alternatively, submit via the Apple Security Bounty research portal at `security.apple.com/bounty`.

### Step 3: Information Required in Submission
Your advisory should include:
- **Product & Version**: e.g., iOS 27.0 (Build 24A435), iPhone 16 Pro Max
- **Component**: e.g., `SpringBoard`, `BackupAgent2`, `AirTraffic`, `SystemStatus`
- **Impact Assessment**: Privileged IPC exposure, entitlement mismatch, or filesystem boundary escape
- **Proof of Concept**: Step-by-step reproduction instructions and minimal test scripts
- **Remediation Suggestion**: Recommended code-level fixes or entitlement schema tightening

### Step 4: Coordinated Embargo Period
- Observe a standard **90-day embargo period** from initial acknowledgment to allow Apple engineering adequate time to develop, test, and distribute security patches across all supported hardware configurations.
- Do not publish functional weaponized exploits, public write-ups, or binary patches before the official security advisory is released in Apple's Security Releases documentation.
