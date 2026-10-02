
# LEDGERASE

## Unified Storage Sanitization and Forensic Recovery Platform

LEDGERASE is a Linux-first storage security and digital forensics platform that combines secure data sanitization, forensic file carving, verification, validation, and evidence generation into a unified workflow.

## Overview

Deleting a file or formatting a storage device does not necessarily mean that its underlying data has been securely removed. At the same time, recovering deleted or damaged data often requires a separate set of forensic tools.

LEDGERASE brings both sides of the storage lifecycle into one platform.
---

# Current Prototype Capabilities

The current prototype provides:

- Secure sanitization of supported storage devices and disk images
- File and folder erasure with recursive handling
- Filesystem capability detection and safety-based refusal
- Device identification and sanitization capability analysis
- Sanitization planning with assurance levels
- Host-visible overwrite with read-back verification
- SHA-256 hashing and integrity verification
- PASS, FAIL, and INCONCLUSIVE validation outcomes
- Hash-chained evidence records
- Persistent sanitization evidence and audit reporting
- Signature-based forensic file carving
- Format-specific structural validation
- File-type classification
- Recovery confidence scoring
- Linux command-line interface
- Automated test coverage across 16 test suites

---

# Complete End-to-end Tool Overview 

The complete LEDGERASE platform is planned as a unified GUI and CLI forensic storage lifecycle covering:

**Secure Drive Erasure + File and Folder Erasure + Advanced File Recovery + File Carving + Verification + Validation + Evidence + Reporting**

Future development includes Windows support, expanded filesystem support, advanced structure-aware recovery, fragmented-file reconstruction, additional device-level sanitization mechanisms, and an integrated GUI.

---

# Sanitization Commands

```bash
# 1. List Available Devices
./build/bin/ledgerase-cli list-devices

# 2. Inspect the Target
./build/bin/ledgerase-cli inspect /dev/sdX

# 3. Check Sanitization Capabilities
./build/bin/ledgerase-cli capabilities /dev/sdX

# 4. Create a Sanitization Plan
./build/bin/ledgerase-cli plan /dev/sdX --assurance clear

# 5. Execute Sanitization
sudo ./build/bin/ledgerase-cli sanitize /dev/sdX --assurance clear

# 6. Get CLI Help
./build/bin/ledgerase-cli --help

Warning: Sanitization is destructive. Always verify the target device before executing the operation.
