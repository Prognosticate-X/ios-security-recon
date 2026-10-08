# iOS 27 Backup Mechanisms & Synchronization Protocols Research Notes

## 1. Context & Research Scope

During the analysis of iOS 27.0 Release customization pipelines, two primary transport channels were evaluated for deploying verified configuration metadata to physical devices without jailbreaking:
1. **The MobileBackup2 Pipeline (`Manifest.db` In-Place Injection)**
2. **The AirTraffic / ATAirlock Streaming Conduit**

This document summarizes defensive research insights regarding the filesystem sandbox boundaries, protocol quirks, and platform hardening introduced in iOS 27.

---

## 2. MobileBackup2 Security Boundary Hardening in iOS 27

Historical customization utilities (such as Nugget, CowabungaLite, and TrollRestore) relied heavily on MobileBackup2 "Sparse Restores" (partial backup restoration) to insert arbitrary files into system directories.

### 2.1 The Four Defense Tiers in iOS 27
In iOS 27.0 Release, Apple closed several historical sparse restore vectors:

1. **Security State Recovery (SSR) Self-Healing**:
   - iOS 27 introduces automated boot-time integrity checks for `/var/preferences`.
   - If files in `/var/preferences` do not match the expected cryptographic baseline or contain unexpected sparse restore artifacts, `init` / `launchd` triggers an automated factory reset wipe.
2. **Hardcoded Whitelist in `BackupAgent2`**:
   - `SystemPreferencesDomain` is restricted to exactly 10 whitelisted files (primarily network, radio, and power configuration plists).
   - Any attempt to write outside these 10 paths fails immediately.
3. **RootDomain Isolation**:
   - `RootDomain` is prohibited from modifying `preferences/*`.
4. **AppDomain Sparse Restore Denial**:
   - Starting in iOS 27 beta 6, requests to perform sparse restores against `AppDomain` yield error code `MBErrorDomain/205`.

### 2.2 Viable Non-Jailbreak Delivery Channel: In-Place `HomeDomain` Injection
- Standard backup restoration targeting `HomeDomain` (such as `HomeDomain/Library/SpringBoard/StatusBarOverrides.archive`) remains officially supported because it resides within the user's unprivileged home directory (`/var/mobile`).
- When executed through an in-place backup restore (`Manifest.db` modification of an existing valid device backup), the operation succeeds without triggering SSR or recovery wipes.

---

## 3. AirTraffic / ATAirlock Streaming Protocol Analysis

### 3.1 Streaming Zip Structure
AirTraffic uses the Book synchronization dataclass to stream assets over USB multiplexed sockets (`usbmuxd`). The transport package uses a specialized streaming ZIP format:
- **Metadata**: `META-INF/com.apple.ZipMetadata.plist`
- **Extra Field Tag**: `0x5A53` (`SZ_EXTRA_ID`) specifying permissions and POSIX mode bits
- **Directory Hierarchy**: Nested subdirectories `p0/`, `p0/p1/`, `p0/p1/p2/`
- **Symlink Bridge**: A symlink entry `p0/p1/p2/link` pointing back through traversal (`../../../target_path`)

### 3.2 ATAirlock Quarantine & Renaming Behavior
1. Files transmitted via AirTraffic are received by the `atc` daemon and extracted into a sandboxed staging directory:
   `/var/mobile/Media/Airlock/Book/<Asset-UUID>/`
2. Once verified, `atc` attempts an atomic rename (`renameat`) of the unzipped payload into the destination path indicated by the symlink.
3. **iOS 27 Renaming Guard**: In iOS 27.0 physical builds, kernel-level sandbox profiles for `atc` restrict `renameat` crossing from `Media/` into `Library/SpringBoard/`. Thus, attempts to atomically overwrite `StatusBarOverrides.archive` via the AirTraffic conduit fail silently or result in sandbox violations unless paired with standard backup restoration.

---

## 4. Empirical Test Matrix (iPhone 16 Pro Max, iOS 27.0)

| Vector | Transport | Target File | Physical A18 Pro Outcome | Defensive Risk Level |
|---|---|---|---|---|
| **Footnote Text** | MDM Profile | `SharedDeviceConfiguration.plist` | ✅ **Success** (Instant apply, zero reboot) | **Zero** |
| **Footnote Text** | HomeDomain Backup | `SharedDeviceConfiguration.plist` | ✅ **Success** (Applied on reboot) | **Low** |
| **Carrier Override** | GoldenNugget 9.5+ | `StatusBarOverrides.archive` | ✅ **Success** (Dynamic Island verified) | **Low** |
| **Carrier Override** | AirLift Conduit | `StatusBarOverrides.archive` | ⚠️ **Blocked by ATAirlock sandbox** | **Low (Non-destructive)** |
| **FeatureFlags** | Sparse Restore | `/var/preferences/FeatureFlags` | ❌ **Triggered Security State Wipe** | **Critical (Prohibited)** |

---

## 5. Defensive Guidance for Researchers

- **Always verify paths against `SafetyGate`** before sending commands over `usbmuxd`.
- **Never attempt writes to `preferences` or `keychains`** via partial backups.
- **Utilize official Configuration Profiles (`.mobileconfig`)** whenever possible for lock screen customization.
