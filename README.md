
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
- Durable SQLite evidence index with permanent Evidence IDs
- Searchable evidence descriptions with change history
- Verify and fetch evidence by ID, with integrity checks before export
- Evidence index backup, restore and consistency checking
- Signature-based forensic file carving
- Format-specific structural validation
- File-type classification
- Recovery confidence scoring
- Linux command-line interface
- Automated test coverage across 20 test suites

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

# Evidence Management

Every sanitization, erasure and carving run writes a verifiable evidence bundle.
LEDGERASE also indexes those bundles in a local SQLite database so they can be
found by a permanent ID, a description or the operation that produced them. The
bundle remains the record; the database is an index of it.

```bash
# Create and inspect the index.
./build/bin/ledgerase-cli evidence db init
./build/bin/ledgerase-cli evidence db status

# Find evidence.
./build/bin/ledgerase-cli evidence list
./build/bin/ledgerase-cli evidence search --query "college lab"
./build/bin/ledgerase-cli evidence search --operation drive-erasure --status SUCCESS

# Describe, verify and retrieve.
./build/bin/ledgerase-cli evidence show EV-00001
./build/bin/ledgerase-cli evidence describe EV-00001 --description "Lab USB, rack 4"
./build/bin/ledgerase-cli evidence verify EV-00001
./build/bin/ledgerase-cli evidence fetch EV-00001 --output ./exported
./build/bin/ledgerase-cli --fetch EV-00001 --output ./exported

# Check, back up and restore the index.
./build/bin/ledgerase-cli evidence check
./build/bin/ledgerase-cli evidence backup ./evidence-backup
./build/bin/ledgerase-cli evidence restore ./evidence-backup --db ./restored.db
```

The index defaults to `/var/lib/ledgerase/ledgerase.db` for root and a per-user
state directory otherwise. Set `LEDGERASE_DB` or pass `--db PATH` to choose
another location. See `docs/EVIDENCE-DATABASE.md` for the schema, the search
filters, the verification steps before export, and the backup manifest.
