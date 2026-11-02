# The Evidence Database

LEDGERASE writes an evidence bundle for every sanitization, erasure and carving
run. The database described here is an **index of those bundles**, not a second
copy of the evidence and not a replacement for the files. A third party can
verify a bundle with the bundle and its hash chain alone; the database only makes
the bundle easier to find.

The direction of trust is deliberate:

```
operation -> bundle written and verified -> database row registered
```

A registration that fails leaves a valid bundle and a stale index, which
`ledgerase-cli evidence check` reports. A database row whose bundle is missing or
altered is reported the same way and is never presented as verified evidence.

## Where it lives

| Setting | Default |
| --- | --- |
| `LEDGERASE_DB` | unset |
| `--db PATH` | overrides `LEDGERASE_DB` |
| Default path | `/var/lib/ledgerase/ledgerase.db` (root), `$XDG_STATE_HOME/ledgerase/ledgerase.db`, or `$HOME/.local/state/ledgerase/ledgerase.db` |

The database directory is created mode `0700` and the database file mode `0600`.
Only the artifacts it references are copied during a backup; no device serial
numbers are indexed.

## Evidence IDs

Every registered bundle receives a permanent, human-readable ID:

```
EV-00001
EV-00002
```

An ID is allocated once and never reused. Descriptions can change; the ID cannot.
IDs are allocated inside a `BEGIN IMMEDIATE` transaction, so two concurrent
registrations cannot receive the same value.

Registration is idempotent by job ID: re-registering the same job returns the
existing row instead of allocating a second ID.

## Descriptions

A description is metadata, not an edit of the evidence. `evidence describe`
writes an `evidence_annotations` row containing the previous value, the new
value, the time and the operator. The bundle's bytes, and therefore its hash, do
not change. This is why a signed bundle remains verifiable after a description
update.

Descriptions are searchable, as are the operation, status, target type, device
model, job ID and evidence ID.

## Commands

```bash
# First use: create the index (subsequent writes create it automatically).
ledgerase-cli evidence db init

# Find records.
ledgerase-cli evidence list
ledgerase-cli evidence list --page 2 --limit 20

# Search. All filters combine. Dates are YYYY-MM-DD.
ledgerase-cli evidence search --query "college lab"
ledgerase-cli evidence search --operation drive-erasure --status SUCCESS
ledgerase-cli evidence search --from 2026-01-01 --to 2026-06-30
ledgerase-cli evidence search --target-type USB --model "Example Stick"
ledgerase-cli evidence search --sort date-asc

# Select a result without a menu.
ledgerase-cli evidence search --query laptop --select 2 --no-interactive

# Inspect, describe and verify.
ledgerase-cli evidence show EV-00001
ledgerase-cli evidence describe EV-00001 --description "Lab USB, rack 4"
ledgerase-cli evidence verify EV-00001
ledgerase-cli evidence verify EV-00001 --public-key lab.pub

# Retrieve a verified copy of the bundle.
ledgerase-cli evidence fetch EV-00001 --output ./exported
ledgerase-cli --fetch EV-00001 --output ./exported

# Index health, backup and restore.
ledgerase-cli evidence check
ledgerase-cli evidence db status
ledgerase-cli evidence backup ./evidence-backup
ledgerase-cli evidence restore ./evidence-backup --db ./restored.db
```

### Search and pagination

Search is parameterised SQL; no value is interpolated into the statement. `LIKE`
patterns are escaped so a `%` in a description is matched literally. Pagination
is `LIMIT`/`OFFSET` with defaults of 10 records per page, and the list footer says
whether there is a next page.

On a terminal with multiple matches, the command shows a numbered menu. Setting
`--select N` (or `--no-interactive`) makes the same choice without a menu, which
is what scripts should use. Selecting the only match prints its detail directly.

### Verification before export

`evidence fetch` does not simply copy the file named in the database. It:

1. hashes the raw bytes and compares them with the recorded SHA-256;
2. runs the schema-specific structural verifier for the bundle type;
3. checks for an existing destination and refuses to overwrite without `--force`;
4. writes the copy mode `0600` and records a `verification_results` row.

If any step fails, no export is produced. The output distinguishes **integrity**
from **authentication**: hashes prove the bytes are the registered ones, but only
a signature check with `--public-key` proves who produced them.

### Consistency check

`evidence check` reports:

- a registered artifact that is missing;
- a registered artifact whose SHA-256 no longer matches;
- a record with no artifact reference;
- an evidence file in the store that is not registered in the selected database
  (for example, after a registration failure, or a bundle belonging to another
  database).

Findings are surfaced, not repaired silently. Reconciliation is an explicit
operator action.

### Backup and restore

`evidence backup DIR` produces:

```
DIR/
  ledgerase.db
  backup.json
  artifacts/<artifact-id>-<name>
```

The SQLite copy is made with the online backup API, so it is consistent even
while the database is open. `backup.json` lists every artifact and its hash. If
an artifact is missing, the backup is refused or reported as incomplete: a
database-only copy is not an evidence backup.

`evidence restore` verifies the manifest and hashes **every** artifact copy before
installing the database. A truncated or altered backup is refused, and an
existing target is not overwritten without `--force`.

## Schema (version 1)

| Table | Purpose |
| --- | --- |
| `schema_migrations` | Applied migration versions |
| `devices` | Device descriptions captured during sanitization (no serial numbers) |
| `jobs` | One row per operation, unique by `job_id` |
| `evidence_records` | The evidence ID, description, target and bundle reference |
| `evidence_annotations` | Description history (previous and new value) |
| `evidence_artifacts` | Files that make up the evidence and their SHA-256 |
| `audit_events` | A copy of the bundle's hash-chain events for review |
| `verification_results` | Every verify/fetch outcome |
| `evidence_migrations` | Bundle format migrations, when they occur |

The connection enables `PRAGMA foreign_keys = ON`, WAL journaling, a busy
timeout, and `synchronous = FULL`. Constraints hold the index together; the
database never edits an evidence file.

## Concurrency

WAL allows a reader to run while a write is in progress. Writers serialise on a
short `BEGIN IMMEDIATE` transaction, so ID allocation and registration are
atomic. A lock held longer than the busy timeout returns an error rather than
silently dropping a record.

## What the database does not do

- It does not sign anything. Signatures belong to the bundle.
- It does not decide whether evidence is authentic; verification reads the file.
- It does not store device serial numbers.
- It does not repair or delete evidence during `check`.
- It does not replace the bundle. Deleting the database loses discovery, not
  evidence.
