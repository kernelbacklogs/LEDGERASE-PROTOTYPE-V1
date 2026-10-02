#pragma once

// Sanitization evidence: a durable, tamper-evident record of one sanitization
// event, structured around the process that NIST SP 800-88 Rev. 2 describes.
//
// What this is for
// ----------------
// An evidence bundle answers "what was decided, on what media, by whom, under
// what authorization, using which mechanism, what evidence was collected, and
// what remains unproven". It is durable, hash-chained, and can be verified by a
// third party who was not present.
//
// It is the tool's only record. An earlier version also kept a volatile
// operational log in process memory, with `ret-log` and `give-log` commands.
// Both were removed: a record that is lost on crash, on SIGKILL and at session
// end is not an audit trail, and two systems of record meant the durable one was
// not trusted to be the only one. See audit.md.
//
// Honesty constraints, from CLAUDE.md s3/s42/s45/s57
// ---------------------------------------------------
// This software maps its categories onto NIST SP 800-88 Rev. 2. It is
// not certified, it does not confer compliance, and conformance of a specific
// sanitization program is decided by an assessor against the standard itself.
// The bundle therefore records the standard as a reference and states that
// mapping explicitly. It never asserts that data was physically erased, that
// every copy was sanitized, or that verification was independent when it was
// not.
//
// The design deliberately refuses to certify what it cannot know:
//   * The tool cannot enumerate the operator's backups, replicas or cloud
//     copies. Scope is an operator attestation, and an unattested scope
//     downgrades the outcome instead of being silently assumed complete.
//   * The tool cannot inspect controller-managed media. Residual risk is
//     carried in the bundle as a first-class field, not as a footnote.
//   * Verification performed by this tool, in this session, about an operation
//     this tool just performed is self-verification. It is labelled as such and
//     cannot produce a clean acceptance on its own.
//
// Retention is deliberately NOT an outcome gate. How long a record is kept does
// not change whether a sanitization succeeded, so an undefined retention policy
// is disclosed as a limitation rather than used to downgrade the result.

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/safety.hpp"
#include "ledgerase/json_adapters.hpp"

#include <cstdint>
#include <memory>
#include <string>

#include <nlohmann/json_fwd.hpp>

#include "ledgerase/limitations.hpp"
#include <vector>

namespace ledgerase {

// SHA-256 of a raw byte range, hex encoded. The reference takes a std::string
// because every evidence field is text; carving hashes extracted bytes, which
// are not, and copying a whole recovered file into a string to hash it would
// put the file size back on the heap.
Result<std::string> sha256HexBytes(const uint8_t* data, size_t length);

// A digest fed in pieces.
//
// Hashing a multi-gigabyte file or a whole device has to be done in blocks, and
// calling sha256HexBytes once per block would produce a hash of each block
// rather than of the file. This holds one context across every update.
class Sha256Stream {
public:
    Sha256Stream();
    ~Sha256Stream();

    Sha256Stream(const Sha256Stream&) = delete;
    Sha256Stream& operator=(const Sha256Stream&) = delete;

    void update(const uint8_t* data, size_t length);
    // Finalises and returns the hex digest. Further updates are not allowed.
    Result<std::string> finalHex();
    bool finalised() const { return finalised_; }

private:
    void* context_ = nullptr;   // EVP_MD_CTX*
    bool finalised_ = false;
};

// ---------------------------------------------------------------------------
// Operator attestations. These are claims, not measurements, and the bundle
// labels them as such.
// ---------------------------------------------------------------------------

// Which copies of the information the sanitization applies to. Sanitizing a
// drive while leaving a backup intact has sanitized nothing; the standard is
// explicit that all copies must be considered, and the tool cannot discover
// them on the operator's behalf.
struct MediaScopeAttestation {
    // True only when the operator asserts that every copy holding this
    // information is covered by this sanitization event.
    bool allCopiesAccountedFor = false;
    std::vector<std::string> copiesAddressed;
    std::vector<std::string> copiesNotAddressed;
    std::string rationale;
    std::string attestedBy;
};

// What was checked before the media was touched, and who authorized it.
struct PreExecutionAttestation {
    std::vector<SafetyCheck> checks;
    bool deviceIdentityConfirmed = false;
    std::string authorizationReference;   // change ticket, disposition order, ...
    std::string authorizedBy;
    std::string authorizationBasis;      // organizational policy, contract, ...
};

// Verification independence. Verification performed by the same operator on
// the same host immediately after the operation is not independent
// verification, and the bundle must not let it be read as such.
struct VerificationIndependence {
    enum class Level {
        NONE,        // not performed
        SELF,        // performed by this tool, same session
        OBSERVED,    // witnessed by a second party
        INDEPENDENT  // performed by a separate party or team
    };

    Level level = Level::NONE;
    std::string performedBy;
    std::string notes;
};

std::string verificationIndependenceToString(VerificationIndependence::Level level);

// How long the evidence must be kept. "undefined" is a legitimate and
// meaningful answer; leaving the field out is not.
struct RetentionAttestation {
    enum class Policy {
        UNDEFINED,
        ORGANIZATION_DEFINED,
        CONTRACTUAL,
        LEGAL_HOLD
    };

    Policy policy = Policy::UNDEFINED;
    std::string retainUntil;   // free text or ISO date, per policy
};

std::string retentionPolicyToString(RetentionAttestation::Policy policy);

// ---------------------------------------------------------------------------
// Hash-chained journal
// ---------------------------------------------------------------------------

// One link in an append-only chain. Each record commits to its predecessor, so
// editing, reordering or removing an interior record is detectable, and the
// chain head commits to the chain length so truncation of the tail is
// detectable too.
struct EvidenceRecord {
    uint64_t sequence = 0;
    std::string timestamp;    // ISO-8601 UTC, second precision
    std::string type;         // event type, see kEvidenceEventTypes
    std::string jobId;
    nlohmann::json payload;
    std::string prevHash;     // 64 hex chars; all-zero for the genesis record
    std::string recordHash;   // SHA-256 over the canonical form of this record
};

struct ChainVerification {
    bool intact = false;
    uint64_t recordsChecked = 0;
    std::string headHash;
    std::string failureReason;
    std::string failureAtSequence;   // empty when intact
};

class EvidenceJournal {
public:
    static constexpr const char* kGenesisHash =
        "0000000000000000000000000000000000000000000000000000000000000000";

    EvidenceJournal();
    ~EvidenceJournal();

    EvidenceJournal(const EvidenceJournal&) = delete;
    EvidenceJournal& operator=(const EvidenceJournal&) = delete;

    // Appends a record and links it to the current head.
    Result<EvidenceRecord> append(const std::string& type,
                                  const std::string& jobId,
                                  nlohmann::json payload);

    const std::vector<EvidenceRecord>& records() const noexcept;
    uint64_t count() const noexcept;
    std::string head() const;

    // Recomputes every link and hash. Detects edits, reordering and interior
    // deletion. Does not by itself detect tail truncation, which is why the
    // bundle also records the count and head.
    Result<ChainVerification> verifyChain() const;

    // Canonical JSON of a record excluding its own hash field. Exposed because
    // the bundle and the tests need the exact pre-image.
    static Result<std::string> canonicalRecordJson(const EvidenceRecord& record);
    static Result<std::string> recordHash(const EvidenceRecord& record);

    void clear() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ---------------------------------------------------------------------------
// Carve evidence
//
// A recovery run produces no sanitization certificate, because it sanitizes
// nothing. It does produce claims that a third party would want checked the
// same way: that a particular source, in a particular state, was read; that
// reading it did not change it; and that each recovered file has a specific
// digest. So it goes into the same hash-chained system, as its own record
// types and its own schema, rather than as a bare JSON dump on the terminal.
//
// The chain is the point. "The carver says it found 40 files" is not evidence;
// "these 40 digests, over this source digest, under this parameter set, and the
// source digest was the same before and after" is.
// ---------------------------------------------------------------------------

// What was read, and proof that reading it did not change it.
struct CarveSourceRecord {
    std::string path;
    std::string kind;            // "file" or "block device"
    uint64_t sizeBytes = 0;
    // Both are recorded, and both are in the chain. Two digests that agree are
    // a claim that the scan did not disturb the medium; one digest is not.
    std::string sha256BeforeScan;
    std::string sha256AfterScan;
    bool unchanged = false;
    // True only because the source is opened O_RDONLY and no code path opens
    // it for writing. Recorded as a property of the code, not a promise.
    bool openedReadOnly = true;
};

// The settings the run actually used, not the ones it was asked for. The
// Carver clamps them at construction, so these are the effective values.
struct CarveParameters {
    uint64_t chunkSize = 0;
    uint64_t overlap = 0;
    uint64_t maxCandidates = 0;
    uint64_t maxTotalOutputBytes = 0;
    uint64_t maxInferredLength = 0;
    double minimumScore = 0.0;
    std::string categoryFilter;      // comma-joined, empty when unset
    std::string outputDirectory;     // empty when only a report was produced
};

struct CarveRecoveredEntry {
    uint64_t offset = 0;
    uint64_t length = 0;
    std::string signatureName;
    std::string extension;
    std::string category;
    std::string confidence;
    double score = 0.0;
    // Of the extracted bytes. This is the digest that makes a recovery
    // reproducible: anyone can re-hash the carved file and compare.
    std::string sha256;
    bool truncated = false;
    bool lengthInferred = false;
    // False when the format's structure walk failed, which is how a fragmented
    // or interleaved file is distinguished from a recovered one.
    bool structureValid = true;
    std::vector<std::string> reasons;
    // Where the bytes were written, and how many. Empty when nothing was
    // extracted: a report-only run writes nothing and says so.
    std::string extractedPath;
    uint64_t extractedBytes = 0;
};

struct CarveEvidenceBundle {
    // A distinct schema from the sanitization bundle. A reader that only
    // understands sanitization certificates must reject this rather than read
    // the wrong fields out of it.
    // Written under the new name; the old spelling is still read, for the
    // reason in EvidenceBundle::kSupportedSchemas.
    static constexpr const char* kSchema = "ledgerase.carve_bundle/1";
    static constexpr const char* kLegacySchemas[] = {"sanitizer.carve_bundle/1"};
    std::string schema = kSchema;

    std::string jobId;
    std::string generatedAt;

    // Which build and which carve engine produced this, so a result can be
    // compared against another run of the same code rather than against an
    // unnamed tool.
    std::string applicationVersion;
    std::string carverVersion;

    std::string operatorName;
    std::string invokingUser;
    uint32_t invokingUid = 0;
    std::string effectiveUser;
    uint32_t effectiveUid = 0;
    bool elevated = false;

    CarveSourceRecord source;
    CarveParameters parameters;

    uint64_t candidatesExamined = 0;
    uint64_t filesRecovered = 0;
    uint64_t bytesRecovered = 0;
    uint64_t filesExtracted = 0;
    uint64_t bytesExtracted = 0;
    // Files that were found but not written, and why. Silent omission would
    // make the recovered count look complete when it is not.
    uint64_t filesNotExtracted = 0;
    std::vector<std::string> extractionFailures;

    std::vector<CarveRecoveredEntry> recovered;
    std::vector<std::string> notes;

    uint64_t chainLength = 0;
    std::string chainHead;
    std::vector<EvidenceRecord> eventChain;
    std::string canonicalHash;
};

void to_json(nlohmann::json& j, const CarveSourceRecord& s);
void from_json(const nlohmann::json& j, CarveSourceRecord& s);
void to_json(nlohmann::json& j, const CarveParameters& p);
void from_json(const nlohmann::json& j, CarveParameters& p);
void to_json(nlohmann::json& j, const CarveRecoveredEntry& e);
void from_json(const nlohmann::json& j, CarveRecoveredEntry& e);
void to_json(nlohmann::json& j, const CarveEvidenceBundle& b);
void from_json(const nlohmann::json& j, CarveEvidenceBundle& b);

class CarveEvidenceBuilder {
public:
    // Builds the bundle and its chain. The chain is assembled here rather than
    // at the call site so that the digests it commits to are the ones actually
    // stored.
    //
    // `extraction` maps a recovered offset to what happened to it, because
    // "recovered" and "written somewhere" are different facts and a bundle
    // that implies they are the same is misleading.
    static Result<CarveEvidenceBundle> build(
        const CarveEvidenceBundle& inputs,
        const std::vector<std::string>& extractionFailures);

    static Result<std::string> canonicalJson(const CarveEvidenceBundle& bundle);
    static Result<std::string> canonicalHash(const CarveEvidenceBundle& bundle);
    static Result<std::string> canonicalHashOfDocument(const nlohmann::json& document);

    static std::string generateJobId();
};

class CarveEvidenceWriter {
public:
    // Same write discipline as the sanitization bundle: 0600, atomic, no
    // clobber without --force, directory fsync.
    static Result<void> write(const CarveEvidenceBundle& bundle,
                              const std::string& path,
                              bool overwrite = false);
    static Result<CarveEvidenceBundle> read(const std::string& path);
};


// ---------------------------------------------------------------------------
// Evidence bundle
// ---------------------------------------------------------------------------

struct EvidenceSignature {
    std::string algorithm;    // "Ed25519"
    std::string keyId;        // SHA-256 of the public key, first 32 hex chars
    std::string signedField;  // what was signed, e.g. "canonical_hash"
    std::string valueBase64;
    std::string signedAt;
};

struct EvidenceBundle {
    // Schema 2 stores limitations as objects carrying a stable ID, so a reader
    // can tell which fact a line refers to. Schema 1 stored bare sentences;
    // bundles written then still load and still verify (see the reader in
    // json_adapters.hpp, which accepts both shapes).
    // Schema 3 stores each fact once. Schema 2 and 1 kept the decision, the
    // verification report and the validation in both the top-level sections and
    // the event chain payloads, so the `decision` object appeared twice,
    // byte-identical. In schema 3 the chain records reference their section by
    // name and carry the section's SHA-256, which the record hash covers, so the
    // chain still commits to the content without copying it.
    //
    // Bundles written as 1, 2 or 3 still read and still verify: the chain
    // verification recomputes each record hash from whatever payload is stored,
    // and the old payloads are self-contained.
    //
    // The schema identifier carries the tool's name, so this build writes
    // "ledgerase." and still reads every "sanitizer." bundle ever written. That
    // is deliberate in both directions: a record's schema string is part of the
    // bytes its canonical hash covers, so renaming it on an existing bundle
    // would invalidate that bundle's own hash; and a reader that stopped
    // recognising the old string would declare real audit history unreadable.
    // The name lives in a string, not in a format, so both are the same format.
    std::string schema = "ledgerase.evidence_bundle/3";

    // Every schema version this build can read, newest first. verify-log uses
    // it to tell "old but readable" apart from "not something I understand".
    static constexpr const char* kSupportedSchemas[] = {
        "ledgerase.evidence_bundle/3",
        "ledgerase.evidence_bundle/2",
        "sanitizer.evidence_bundle/3",
        "sanitizer.evidence_bundle/2",
        "sanitizer.evidence_bundle/1",
    };
    std::string jobId;
    std::string certificateId;
    std::string generatedAt;

    // What standard this record is written against, and what that does and
    // does not mean.
    std::string standardName = "NIST SP 800-88 Rev. 2";
    std::string standardRole = "policy basis";
    std::string conformanceStatement;
    std::vector<std::string> additionalReferences;

    // Media identity and scope.
    DeviceInfo device;
    MediaScopeAttestation scope;

    // The decision: category requested, method chosen, alternatives rejected.
    SanitizationCategory requestedCategory = SanitizationCategory::PURGE;
    // How the requested category was arrived at: "local-policy" (derived from
    // the organisation's documented policy), "operator" (--assurance), or
    // "default". Carries the inputs and the policy's own rationale. This is a
    // plain struct with std::string fields rather than the plan's nested one, so
    // the evidence schema does not change shape when the plan's does.
    struct {
        std::string source = "default";
        std::string categorization = "unset";     // Low/Moderate/High/unset
        std::string reuseMedia = "unset";         // yes/no/unset
        std::string leavingOrgControl = "unset";  // yes/no/unset
        std::string provenance;
        std::string rationale;
    } assuranceBasis;
    SanitizationMethod selectedMethod = SanitizationMethod::NONE;
    std::string decisionRationale;
    std::vector<MethodAssessment> alternativesConsidered;
    std::vector<std::string> standardReferences;

    // What was checked and who authorized it.
    PreExecutionAttestation preExecution;
    // Who asked for the job, and who the process actually ran as. Under sudo
    // these differ, and the difference is the point: a certificate that names
    // only "root" cannot say which person authorised the destruction.
    std::string operatorName;
    // The real user behind the invocation, from SUDO_USER / SUDO_UID, or equal
    // to operatorName when the process was not run under sudo.
    std::string invokingUser;
    uint32_t invokingUid = 0;
    // The effective user, from geteuid(). Recorded so a reader can tell a
    // deliberate root run from a sudo-elevated one.
    std::string effectiveUser;
    uint32_t effectiveUid = 0;
    // True when the effective user differs from the invoking user, i.e. sudo
    // or an equivalent was used.
    bool elevated = false;
    std::string applicationVersion;

    // What happened.
    JobStatus execution;
    bool simulated = false;

    // What evidence supports the outcome, and how independent it is.
    VerificationReport verification;
    VerificationIndependence verificationIndependence;

    // Whether the outcome should be accepted.
    ValidationReport validation;

    // Residual risk: what is still not proven.
    std::vector<std::string> residualRiskLimitations;
    bool residualDataPossible = true;
    std::string residualRiskStatement;

    // Integrity and retention.
    std::string hashAlgorithm = "SHA-256";
    uint64_t chainLength = 0;
    std::string chainHead;
    // The full event chain is embedded so a third party can walk it without
    // access to the runtime. chainLength and chainHead are the cross-check: if
    // a verifier walks fewer records, or ends on a different head, records were
    // removed from the end.
    std::vector<EvidenceRecord> eventChain;
    std::string canonicalHash;   // SHA-256 of the canonical bundle, pre-signature
    std::vector<EvidenceSignature> signatures;
    RetentionAttestation retention;
};

// nlohmann::json adapters for the evidence types.
//
// Declared here, not only defined in evidence.cpp, because the CLI serialises
// bundles in its own translation units. ADL finds these through namespace
// this library only if the declarations are visible there, so leaving them
// file-local would make `nlohmann::json j = bundle;` fail to compile in every
// other file that touches a bundle.
void to_json(nlohmann::json& j, const MediaScopeAttestation& s);
void from_json(const nlohmann::json& j, MediaScopeAttestation& s);
void to_json(nlohmann::json& j, const PreExecutionAttestation& p);
void from_json(const nlohmann::json& j, PreExecutionAttestation& p);
void to_json(nlohmann::json& j, const VerificationIndependence& v);
void from_json(const nlohmann::json& j, VerificationIndependence& v);
void to_json(nlohmann::json& j, const RetentionAttestation& r);
void from_json(const nlohmann::json& j, RetentionAttestation& r);
void to_json(nlohmann::json& j, const EvidenceRecord& r);
void from_json(const nlohmann::json& j, EvidenceRecord& r);
void to_json(nlohmann::json& j, const EvidenceSignature& s);
void from_json(const nlohmann::json& j, EvidenceSignature& s);
void to_json(nlohmann::json& j, const EvidenceBundle& b);
void from_json(const nlohmann::json& j, EvidenceBundle& b);

class EvidenceBuilder {
public:
    // Builds a bundle from the artefacts of one sanitization event.
    //
    // The builder will not report a stronger outcome than its inputs support:
    // an unattested scope or unverified operation forces the validation result
    // down and records why.
    static Result<EvidenceBundle> build(
        const AuditRecord& record,
        const VerificationReport& verification,
        const ValidationReport& validation,
        const MediaScopeAttestation& scope,
        const PreExecutionAttestation& preExecution,
        const VerificationIndependence& independence,
        const RetentionAttestation& retention);

    // Deterministic canonical JSON: sorted keys, no insignificant whitespace.
    // This is the pre-image for canonicalHash and for the signature. The
    // "canonical_hash" and "signatures" members are excluded from it, so that
    // adding a signature does not invalidate the hash that was signed.
    static Result<std::string> canonicalJson(const EvidenceBundle& bundle);

    // SHA-256 of canonicalJson(), lowercase hex.
    static Result<std::string> canonicalHash(const EvidenceBundle& bundle);
    // Hash of an already-stored document. This is what a file on disk is
    // checked against, so the result depends only on the bytes present and not
    // on the shape of the C++ struct used to read them.
    static Result<std::string> canonicalHashOfDocument(const nlohmann::json& document);

    static std::string generateCertificateId();
};

class EvidenceWriter {
public:
    // Writes a bundle to disk atomically: a 0600 temporary file in the target
    // directory, fsync, then rename. Refuses to follow symlinks and refuses to
    // clobber an existing file unless explicitly allowed. The document is
    // self-contained so a verifier needs nothing else.
    static Result<void> write(const EvidenceBundle& bundle,
                              const std::string& path,
                              bool overwrite = false);

    // Loads a bundle from disk. Used by the verifier, not by the runtime.
    static Result<EvidenceBundle> read(const std::string& path);
};

struct EvidenceVerification {
    bool schemaRecognised = false;
    bool canonicalHashMatches = false;
    bool signatureValid = false;
    bool signaturePresent = false;
    bool chainConsistent = false;
    uint64_t chainLength = 0;
    std::vector<std::string> findings;
    LimitationSet limitations;
};

// Structural verification of a carve record: schema, canonical hash, chain.
// Carve records are not signed - nothing in the recovery path produces a
// signature - so `signaturePresent` is always false and the verdict stops at
// "intact", which is what it can honestly say.
class CarveEvidenceVerifier {
public:
    static Result<EvidenceVerification> verifyStructure(const std::string& path);
};

class EvidenceVerifier {
public:
    // Structural verification: schema, canonical hash, declared chain length
    // and head. Requires nothing but the file itself.
    static Result<EvidenceVerification> verifyStructure(const std::string& path);

    // The same checks against a bundle already in memory. Used by the CLI,
    // which has just read the file and must not report anything from a document
    // that does not verify.
    // `document` is the stored JSON, when the caller has it. Passing it makes
    // the canonical-hash check run against the bytes on disk rather than
    // against a re-serialisation of this build's structs, which is what lets a
    // bundle written by an older schema still verify.
    static Result<EvidenceVerification> verifyStructureFromBundle(
        const EvidenceBundle& bundle, const nlohmann::json* document = nullptr);

    // Full verification: structure plus Ed25519 signature against a public key
    // file in PEM form. A missing or wrong key yields signatureValid=false with
    // an explanation, never a pass.
    static Result<EvidenceVerification> verify(const std::string& path,
                                               const std::string& publicKeyPath);

    // Signs the canonical hash of a bundle with an Ed25519 private key in PEM
    // form. The key material is never copied into the bundle or the log.
    static Result<EvidenceSignature> sign(EvidenceBundle& bundle,
                                          const std::string& privateKeyPath);

    // Recomputes a bundle's canonical hash and compares it with the stored one.
    static Result<bool> verifyCanonicalHash(const EvidenceBundle& bundle);
    // Preferred when checking a file: hashes the stored document itself.
    static Result<bool> verifyCanonicalHashOfDocument(
        const nlohmann::json& document, const std::string& storedHash);
};

} // namespace ledgerase
