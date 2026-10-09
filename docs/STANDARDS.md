# Standards mapping and evidence model

## Read this first

This document maps what the software does to the process described in
**NIST SP 800-88 Rev. 2, Guidelines for Media Sanitization**. It is written by
the tool's authors, not by an assessor, and it is not legal or compliance
advice.

Three things this document deliberately does **not** do:

1. **It does not claim certification or conformance.** The software is
   *designed with reference to* the standard. Whether a given sanitization
   program conforms is decided by an assessor against the standard itself and
   the applicable organizational policy. Every evidence bundle carries this
   statement in its `standard.conformance_statement` field.
2. **It does not claim clause-level conformance.** A section number next to a
   statement identifies *where* a requirement is written, not that the software
   satisfies it, and conformance is an assessor's judgement. Where a clause is
   named it is because the exact wording matters and paraphrase would drift;
   a reader must still read the licensed standard. Requirements are otherwise
   expressed in terms of the standard's named process elements.
3. **It does not reproduce standard text at length.** Requirements are
   paraphrased. Short quotations appear only where the precise wording carries
   the rule - a paraphrase that said "multi-pass is discouraged on SSDs" would
   not record that the standard says it "should be avoided", and would not
   record that it is advice rather than a prohibition.

Rev. 2 is the current revision. Rev. 1's assumption of a universal fixed
overwrite pass count is obsolete; the sanitization method must be justified by
the device's actual capabilities and the requested assurance level, which is the
approach this tool takes.

### What Rev. 2 does and does not prescribe about pass counts

Rev. 2 prescribes **no** pass count. Section 3.1.1 records the historical
practice and stops there: "The number of passes ranged from a single pass to as
high as 39." It then cautions against the practice on flash: "For certain ISM
(e.g., SSDs with overprovisioning), such practices should be avoided as very
little confidentiality protection is achieved." And it points at a different
lever for more assurance: "If additional assurances are needed, a more secure
sanitization method in the form of purge (see Sec. 3.1.2) or destroy (see
Sec. 3.1.3) should be used."

So this tool's single-pass default is a **local choice, not a NIST
prescription**, and the source says so. When more than one pass is requested for
SSD or hybrid media, the plan attaches the 3.1.1 caution as a risk and a
limitation, and recommends a purge technique rather than more passes. On
rotational or unknown media no caution is attached, because 3.1.1's advice is
specifically about overprovisioned flash.

### Verification in Rev. 2 is not content sampling

Section 4.5.1 grounds verification in the operation's outcome, not in reading
the media back: "Clear and logical purge sanitization techniques that involve
tools and systems can be verified by checking the completion status of the
tools and identifying errors, anomalies, and the health of the ISM." It goes
further and says sampling is usually unnecessary: "Unless explicitly required by
organizational policy, elaborate sampling of an ISM's contents (e.g., full or
representative) after clear or purge sanitization techniques is not necessary."

This tool performs read-back and a residual content search anyway. That is
**beyond the baseline the standard requires**, chosen because an operator
sanitizing media cannot inspect it independently. It is recorded as such: the
sample count, the fraction covered, and the explicit list of what a sample
cannot speak for all travel in the evidence. No document in this repository
should imply the standard requires the sampling.

## The two categories the standard uses, and how they map

The standard distinguishes sanitization *levels* (Clear, Purge, Destroy) from
sanitization *verification*. This tool keeps them separate everywhere, because
collapsing them is how a completed overwrite gets reported as a completed
"purge".

| Sanitization level | What it means | How this tool treats it |
|---|---|---|
| **Clear** | Logical techniques addressing the user-accessible address space, appropriate where the risk does not warrant stronger methods. | Reachable via device-level block erase, or host overwrite as a last resort. `SanitizationCategory::CLEAR` |
| **Purge** | Stronger techniques intended to make recovery infeasible for the relevant effort, using device-supported mechanisms where available. | Device-level mechanisms only. Host overwrite is **refused** for Purge rather than silently substituted, because a logical overwrite cannot reach controller-managed areas. `SanitizationCategory::PURGE` |
| **Destroy** | Physical destruction of the media. Outside what software can perform. | Represented as an operator disposition workflow. The tool records who destroyed the media, when, how, and under what authorization. It does not pretend to destroy anything. `SanitizationMethod::DESTROY_MANUAL` |

## The standard's process, and where each step lives in the code

| Process step | What the standard asks for | Implementation | Recorded in evidence as |
|---|---|---|---|
| Categorization and decision | Decide the sanitization level from the information's sensitivity, and record why that level was chosen. | `SanitizationPolicyEngine::createPlan`, `selectMethod` — `src/erasure/policy.cpp` | `decision.requested_category`, `decision.rationale` |
| Method justification | Choose a method appropriate to the device and the level; do not silently downgrade. | `selectMethod` refuses rather than downgrading; `assessCandidates` records every candidate considered and the reason for each decision — `src/erasure/policy.cpp` | `decision.alternatives_considered[]` with `device_supported`, `permitted_by_policy`, `selected`, `reason` |
| Media identification | Establish exactly what is being sanitized, unambiguously, before acting. | `DeviceManager::inspectDevice`, `DeviceInfo` — `src/device/device.cpp` | `media.device` (path, model, serial, capacity, transport, media type) |
| Scope: all copies | Sanitization is meaningless if other copies of the same information remain. All copies must be considered. | **Not discoverable by the tool.** Operator attestation via `--all-copies`, `--scope-note`, `--copies-not-addressed`. | `media.scope.all_copies_accounted_for`, `copies_addressed[]`, `copies_not_addressed[]`, `rationale`, `attestation_type` |
| Pre-execution verification | Confirm the target is the intended media and is safe to destroy before destroying it. | `SafetyManager::checkDeviceSafety`, `ConfirmationManager::requireSerialConfirmation` — `src/device/safety.cpp` | `pre_execution.checks[]` (each with pass/fail/warning), `device_identity_confirmed` |
| Authorization | Sanitization is a disposition of organizational information and should be traceable to an approval. | Operator attestation via `--authorization`, `--authorized-by`, `--authorization-basis` | `pre_execution.authorization_reference`, `authorized_by`, `authorization_basis` |
| Execution | Perform the operation, monitor it, and distinguish "command accepted" from "operation completed". | `SanitizationExecutor::runMethod`, `ISanitizationMethod::execute` — `src/erasure/sanitization.cpp` | `execution.status` (state machine, start, end, elapsed, device-reported result) |
| Post-execution verification | Gather evidence about what actually happened, appropriate to the technology used. | `VerificationEngine` — `src/erasure/verification.cpp`. Per-technology: NVMe Sanitize Status log, ATA status, read-back where meaningful. | `verification.report` with per-item `passed`, `scope`, `limitations` |
| Verification independence | Verification by the party that performed the operation is weaker than independent verification. | `VerificationIndependence` — `include/sanitizer/evidence.hpp` | `verification.independence.level` ∈ {none, self, observed, independent} |
| Validation | Decide whether the outcome should be accepted, given policy, evidence and limitations. Separate from verification. | `ValidationEngine` — `src/erasure/verification.cpp` | `validation.result` ∈ {ACCEPTED, ACCEPTED_WITH_LIMITATIONS, REJECTED, INCONCLUSIVE}, plus `reasoning`, `accepted_criteria[]`, `rejected_criteria[]` |
| Certificate | Produce a record of the sanitization sufficient for a third party to review. | `EvidenceBuilder` — `src/evidence/audit/evidence.cpp` | The whole `sanitizer.evidence_bundle/1` document |
| Retention | Evidence must be retained for a defined period. | `--retention`, `--retain-until` | `retention.policy`, `retain_until` |

### One record, always produced

There is exactly one record per sanitization: the evidence bundle. It is written
to `<evidence dir>/audit/<job-id>.json` by default, and `--evidence` overrides
the location, not whether a record is made. Reports rendered from a bundle (for
example a PDF certificate) are kept apart in `<evidence dir>/reports/`; they
state the bundle's canonical hash and are never read back as a record. Bundles
written before the split, directly in the evidence directory, are still found. Recording is not opt-in, and the run
aborts before touching the media if the path cannot be written.

An earlier version carried a second, volatile operational log in `mlock`ed RAM
with `ret-log` and `give-log`. It was removed. A record that is destroyed at
session end, lost on `SIGKILL`, and silently drops entries when its fixed-size
buffer fills is not an audit trail, and having two systems of record meant the
durable one was not trusted to be the only one. Every question about a past job
— verification, validation, report, audit — is answered from the bundle on disk,
so it works across sessions, processes and machines.

## What this tool will not assert

The standard is explicit that sanitization effectiveness is bounded by what can
be established. These limits are structural, and the evidence bundle states them
in `residual_risk` rather than burying them:

- **Residual data is always possible.** Set unconditionally in
  `EvidenceBundle::residualDataPossible`. Host software cannot observe NAND
  overprovisioning, wear-levelled or retired blocks, spare media, or areas
  reached through a USB bridge. Crypto erase leaves ciphertext; block erase
  leaves unallocated and retired blocks; overwrite cannot reach controller-managed
  areas at all.
- **Device-reported completion is not physical proof.** It is evidence, and it is
  labelled as device-reported self-reporting.
- **Unknown is never treated as supported.** A capability that cannot be
  established is `UNKNOWN` and cannot be selected.
- **Inconclusive is never converted to pass.** If verification did not pass, the
  builder forces `INCONCLUSIVE` regardless of what the validation engine
  reported.
- **Simulation is never evidence of sanitization.** A run against a mock device
  is stamped `simulated: true`, carries an explicit warning in
  `residual_risk.limitations`, and can never be a clean `ACCEPTED`.

## Outcome gates in the evidence builder

`EvidenceBuilder::build` can only move an outcome **downwards**. These conditions
each force a downgrade and are recorded as limitations:

| Condition | Effect on outcome |
|---|---|
| `all_copies_accounted_for` not attested | `ACCEPTED` → `ACCEPTED_WITH_LIMITATIONS` |
| No `authorization_reference` | `ACCEPTED` → `ACCEPTED_WITH_LIMITATIONS` |
| `device_identity_confirmed` not asserted | `ACCEPTED` → `ACCEPTED_WITH_LIMITATIONS` |
| Verification level is `self` or `none` | `ACCEPTED` → `ACCEPTED_WITH_LIMITATIONS` |
| Verification result is not `PASS` | `ACCEPTED` → `INCONCLUSIVE` |
| Run was simulated | `ACCEPTED` → `ACCEPTED_WITH_LIMITATIONS` |
| Retention policy `undefined` | Disclosed as a limitation only — retention does not change whether the sanitization succeeded, so it is not an outcome gate |

## Integrity model

The evidence bundle is built to be checkable by someone who was not present and
does not trust the producing machine.

**Hash chain.** Every event is a record `{sequence, timestamp, type, job_id,
payload, prev_hash, record_hash}` where `record_hash` is SHA-256 over the
canonical JSON of the record including `prev_hash`. Editing, reordering or
removing an interior record breaks verification. The full chain is embedded in
the bundle, and `chain_length` and `chain_head` are recorded as a cross-check,
so removing records from the end is detected as a length mismatch.

**Canonical hash.** SHA-256 over the canonical JSON of the whole bundle, with
`canonical_hash` and `signatures` excluded so that attaching a signature does
not invalidate what was signed. Keys are serialised in sorted order and the
encoding is compact, so the bytes are reproducible.

**Signature.** Optional Ed25519 over the canonical hash, using a PEM key
supplied by the operator. The signature is verified against the stored hash;
combined with the content check, a hand-edited document fails. The private key
is never copied into the bundle, the log, or any error message. Generate one
with:

```sh
openssl genpkey -algorithm ed25519 -out evidence-key.pem
openssl pkey -in evidence-key.pem -pubout -out evidence-key.pub
```

**What integrity does not give you.** A valid signature proves the document was
produced by the holder of that key and has not been altered since. It does not
prove the recorded events occurred, that the device was what it claimed to be,
or that the operator was who they said they were. It is not an independent audit
of the sanitization. Verification output says so on every run.

**Write safety.** Evidence files are written to a `0600` temporary file in the
target directory, fsynced, then `link()`ed into place. `link()` fails if the
destination exists, so creation is atomic and refuses to clobber without
`--force`, with no check-then-write race. Symlinks are refused (`O_NOFOLLOW`).

## Verifying evidence

```sh
# Structural check: schema, content hash, chain. No key needed.
ledgerase-cli verify-log evidence.json

# Full check including the signature.
ledgerase-cli verify-log evidence.json --public-key evidence-key.pub
```

Output is a single verdict (`VERIFIED`, `ALTERED`, `INCOMPLETE`, `BAD
SIGNATURE`, `UNSIGNED`, `UNRECOGNISED`) plus the individual findings, and a
non-zero exit code unless the document verifies.

## Other references

These are recorded in the bundle as `standard.additional_references` and are
**not** claimed as conformance:

- **IEEE 2883-2022** — sanitization of information security technology.
- **NVMe Base Specification** — Sanitize command and Sanitize Status log
  (LID 0x81), used as the authority for what a device-reported completion means.
- **ATA/ACS** — SECURITY ERASE UNIT, ENHANCED SECURITY ERASE UNIT, and SANITIZE.

## Known gaps against the standard

Stated plainly so they are not mistaken for implemented:

- **DESTROY is a workflow, not an operation.** The tool records a disposition
  record. Physical destruction, and any evidence of it (mass, serialisation
  record), must be supplied by the operator.
- **Forensic post-sanitization validation is not implemented.** `recover-test`
  reports that plainly and exits non-zero. No recovery metric appears in any
  record. Until it exists, no before/after recovery comparison can support an
  effectiveness argument.
- **Independent verification cannot be established by the tool.** It is an
  operator attestation (`--independent-verification`). The tool labels
  self-verification as self-verification.
- **Scope cannot be enumerated by the tool.** Backups, replicas, snapshots and
  cloud copies are outside its view. The attestation records the operator's
  statement, not a verified fact.
- **No organisational policy file.** The policy engine uses built-in defaults
  (`createDefaultPolicy`, `createStrictPolicy`, `createPermissivePolicy`). There
  is no loader for an organisation's own rules.
- **Single-host assumption.** Verification is device-reported. An assessor
  requiring physical inspection, witnessed destruction, or laboratory analysis
  must obtain that separately.


## Device support, and what each transport can actually do

The standard requires the method to be justified by the device's own reported
capabilities. What follows is what this implementation can and cannot establish,
stated plainly rather than implied by the absence of an error.

| Transport | Device-level mechanism | Reachable in this build? |
|---|---|---|
| NVMe | Sanitize: Block Erase, Crypto Erase, Overwrite | Yes, when `OACS` bit 13 and the `SANICAP` action bits say so |
| SATA / SCSI | ATA Security Feature Set (Secure Erase, Enhanced Secure Erase) | **No.** Needs SG_IO ATA PASS-THROUGH |
| SATA / SCSI | ATA Sanitize feature set | **No.** Needs SG_IO ATA PASS-THROUGH |
| USB | Anything reached through the bridge | **Not confirmed.** The bridge decides what arrives |
| Any | Host overwrite of the logical block address space | Yes. Clear only |

**The ATA refusals are deliberate.** `HDIO_DRIVE_CMD` accepts a 4-byte taskfile
header (`HDIO_DRIVE_CMD_HDR_SIZE`). The ATA Security Feature Set commands are
non-data commands whose entire argument is the security identifier spread across
the 28-bit taskfile, with no data phase to carry a 32-byte password. There is
therefore no argument structure that makes the old call correct. Issuing one
anyway risks leaving the drive's security state frozen, which needs a power cycle
and can block any future erase. Capability detection reports these mechanisms as
`UNKNOWN` — not `UNSUPPORTED` — so the policy engine cannot select a method that
can only fail.

**The USB position follows from the same principle.** A USB bridge is a command
processor between the host and the media. It may pass a command through, drop it,
or reinterpret it, and the host cannot tell without sending one. Since sending a
security command is itself destructive, the probe issues only identity requests
and the device-level mechanisms stay `UNKNOWN`. Host overwrite is offered, and
only for Clear. A Purge request is refused.

## Verification, and what read-back does and does not establish

The standard asks for evidence appropriate to the technology used. This tool
uses three kinds:

| Mechanism | Evidence used |
|---|---|
| NVMe Sanitize | The Sanitize Status log (LID 0x81), polled to a terminal state |
| ATA device-level | The command's completion status |
| Host overwrite (any transport, and always USB) | **Read-back of the overwrite pattern** |

Read-back is the only kind of evidence available where there is no status log,
and it is the only thing that catches a bridge which accepts every write,
reports success and erases nothing. The result reports the sample count and the
fraction of the device covered, because coverage is what determines how much the
result is worth.

A passing read-back establishes that the sampled sectors hold the pattern. It
does **not** establish that unsampled sectors do, that the flash translation
layer mapped the writes where the host asked, or that a device reporting a
successful write to a different physical location is not doing so. Those are
recorded as limitations on the evidence item and in `residual_risk`.

The `INCONCLUSIVE`-never-becomes-`PASS` rule applies to read-back as everywhere
else: if the media cannot be read back, verification is `INCONCLUSIVE` and
validation is `INCONCLUSIVE`. A completed write with no inspection of the result
is not a pass.

## File-level erasure is a technique, not a sanitization of the ISM

This matters for `erase-file` and `erase-folder`, and the distinction is not
pedantic.

The glossary defines clear as sanitizing "**all user-addressable storage
locations**" - the whole ISM, not a file within it. Section 3.1.1 adds that
overwriting "cannot address all areas of the ISM where sensitive data may be
retained", and that on flash devices which "contain spare cells and perform
wear levelling" it is "infeasible for a user to sanitize all previous data
using this approach".

So overwriting one file is a **clear-style technique applied to one file**. It
is not a Clear, Purge or Destroy sanitization of the medium, and the tool does
not label it as one. What it guarantees is narrower and is stated as such:

> After a successful file erase, the file's content is no longer readable
> through the filesystem.

What it does not claim, and what the residual search exists to measure, is that
the content is gone from the medium. For that, the operation is
`ledgerase-cli sanitize <device>`, whose scope is the ISM.

This is also why the file erase is permitted on every writable filesystem rather
than only the ones with a clean matrix row. Refusing on btrfs would have meant
refusing to write to storage whose residue the tool has not characterised - and
residue is a question the residual search answers by looking, not by guessing.
The residue each filesystem leaves is disclosed per filesystem in
[FILESYSTEMS.md](FILESYSTEMS.md) and reported by the search.

## The assurance level is chosen by local policy, not by this standard

The tool can derive a sanitization level from three inputs —
`--security-categorization`, `--reuse-media` and `--leaving-org-control` — and
`--assurance` overrides the result. **The mapping between those inputs and a
level is this project's own policy design.** It is not derived from, required by,
or endorsed by NIST SP 800-88 Rev. 2, and no record produced by this tool may be
read as saying the standard selected a level.

Why a policy-driven input mechanism is appropriate at all, and why the specific
mapping is not claimed to come from the standard:

Rev. 2 §4.3.6 requires a decision to be made and describes what must be settled
before it can be — "an assessment of its system confidentiality, … the need for
information sanitization, … appropriate time frames for sanitization, and …
the types of media used and the media disposition" — and then says only that
"an effective, risk-based decision can be made on the appropriate and needed
level of sanitization", pointing to IEEE 2883.1 for the mapping. Rev. 2 §2.4
lists what an organisation "should consider" — media type and capacity,
confidentiality requirement, controlled area, in-house or third party, on-site or
off-site, volume, equipment, training, duration and cost — as considerations to
weigh, not as a rule to apply. Neither section is a decision procedure, and
Rev. 2 contains no decision tree, diagram, or categorization-to-method table.

So the standard supplies the three **levels** (clear, purge and destroy, defined
in §3.1.1, §3.1.2 and §3.1.3) and requires that a **decision** be made and
recorded, while leaving the decision itself to the organisation. A tool that
takes three operator-supplied inputs and applies a documented, auditable rule
is filling that gap, not claiming to implement the standard's method. Each
derived level is recorded in the plan, the CLI report and the evidence bundle
with its inputs, the rule that fired, and this provenance:

> local policy - this project's own design, not a NIST SP 800-88 Rev. 2
> requirement

Three inputs only, deliberately. An adversary-capability axis (novice, expert,
virtuoso) and a system-lifecycle-stage axis would model §4.3.6 more closely,
but neither is available here from a primary document, and a vocabulary that
cannot be checked against a source does not belong in a tool whose central
claim is that its statements can be checked. A further input can be added when it
can be sourced.

Two properties of the policy are worth stating because they are easy to get
wrong:

- **Partial input derives nothing.** "Reuse = yes" alone does not say whether
  the data is sensitive. Rather than filling the gap with a default — which
  would be indistinguishable in the record from a considered decision — the
  policy declines to answer and `--assurance` governs.
- **A derived DESTROY is not a downgrade opportunity.** Destruction is outside
  what software can perform, so a derived DESTROY is refused with advice to
  record a destruction disposition. It is explicitly *not* answered with "use
  `--assurance clear`", which would hand the operator a one-flag bypass of a
  requirement their own policy had just made.
