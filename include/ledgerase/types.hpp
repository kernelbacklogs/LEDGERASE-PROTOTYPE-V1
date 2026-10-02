#pragma once

#include <string>

#include "ledgerase/limitations.hpp"
#include "ledgerase/target.hpp"
#include <vector>
#include <optional>
#include <chrono>
#include <cstdint>
#include <memory>

namespace ledgerase {

enum class TransportType {
    UNKNOWN,
    SATA,
    NVME,
    USB,
    SCSI,
    VIRTIO,
    MMC,
    NVME_OVER_FABRICS
};

enum class MediaType {
    UNKNOWN,
    HDD,
    SSD,
    HYBRID,
    REMOVABLE,
    OPTICAL
};

enum class SanitizationCategory {
    CLEAR,
    PURGE,
    DESTROY
};

// ---------------------------------------------------------------------------
// Local assurance policy
//
// The three sanitization levels above are the standard's, and they are real
// (NIST SP 800-88 Rev. 2 defines clear, purge and destroy in 3.1.1, 3.1.2 and
// 3.1.3). Choosing *which* one applies to a particular job is not something the
// standard specifies. Rev. 2 4.3.6 describes a "risk-based decision" and defers
// the mapping to IEEE 2883.1, and 2.4 lists considerations to weigh rather than
// a rule to apply. So the mapping below is this project's own policy, not a NIST
// requirement, and it is labelled as such everywhere it appears - in the CLI,
// in the plan, and in the evidence. Nothing here may be described as something
// "NIST says".
//
// Deliberately three inputs and no more. An adversary-capability tier
// (novice/expert/virtuoso) and a system-lifecycle stage would both be more
// faithful to the decision 4.3.6 describes, but both were traced to a secondary
// summary rather than to a primary document, and an unverified vocabulary is
// worse than an acknowledged simple one. A third input can be added when it is
// backed by a source that can be checked.
// ---------------------------------------------------------------------------

// How sensitive the data is. Named for the property being decided, not for a
// source, because the values are this project's.
enum class SecurityCategorization {
    UNSET,
    LOW,
    MODERATE,
    HIGH,
};

// Whether the media will be reused, and whether it leaves organizational
// control. Both are booleans with a third state, because "not stated" and
// "no" are different answers and the second must not be assumed from the first.
enum class TriState {
    UNSET,
    YES,
    NO,
};

std::string securityCategorizationToString(SecurityCategorization c);
std::string triStateToString(TriState t);

// The inputs a policy decision is made from, and the decision. Recorded whole,
// so the certificate shows what was decided and from what, not just the answer.
struct AssurancePolicyDecision {
    // True when all three inputs were supplied, i.e. the policy actually ran.
    // False means no decision was derived and --assurance governs.
    bool derived = false;
    SecurityCategorization categorization = SecurityCategorization::UNSET;
    TriState reuseMedia = TriState::UNSET;
    TriState leavingOrgControl = TriState::UNSET;
    SanitizationCategory tier = SanitizationCategory::PURGE;
    // One line naming the rule that fired, in the policy's own terms.
    std::string rationale;
    // Present in every place the tier is displayed, so the answer is never read
    // as a standard's requirement. Never empty when derived.
    std::string provenance =
        "local policy (this project's design, not a NIST requirement)";
};

// The project's documented policy. Pure, total, and free of I/O so the rule
// itself can be tested without a device.
//
// The shape of the rule, and why:
//   * Leaving organizational control is the strongest signal. Media that leaves
//     the organisation cannot be tracked, so it is destroyed.
//   * Reuse is the second signal, and it interacts with sensitivity: a reused
//     medium with a new owner is a disclosure risk, so the stronger level is
//     required.
//   * Sensitivity alone has a floor, so a low-sensitivity record that is reused
//     internally is not destroyed over it.
//   * Anything not high is a single lower level, so a low-sensitivity record
//     leaving the organisation is not escalated to destruction on that basis
//     alone; the confidentiality categorisation is what distinguishes it.
AssurancePolicyDecision deriveAssuranceTier(SecurityCategorization categorization,
                                            TriState reuseMedia,
                                            TriState leavingOrgControl);

enum class SanitizationMethod {
    NONE,
    NVME_BLOCK_ERASE,
    NVME_CRYPTO_ERASE,
    NVME_OVERWRITE,
    ATA_SECURE_ERASE,
    ATA_ENHANCED_SECURE_ERASE,
    ATA_SANITIZE_BLOCK_ERASE,
    ATA_SANITIZE_CRYPTO_ERASE,
    ATA_SANITIZE_OVERWRITE,
    CRYPTO_ERASE_HOST,
    OVERWRITE_HOST,
    UNSUPPORTED,
    DESTROY_MANUAL
};

enum class CapabilityStatus {
    UNKNOWN,
    SUPPORTED,
    UNSUPPORTED
};

enum class JobState {
    DISCOVERING,
    PLANNING,
    AWAITING_CONFIRMATION,
    EXECUTING,
    MONITORING,
    VERIFYING,
    VALIDATING,
    COMPLETED,
    FAILED,
    REJECTED,
    BLOCKED,
    UNKNOWN
};

enum class VerificationResult {
    PASS,
    FAIL,
    INCONCLUSIVE
};

enum class ValidationResult {
    ACCEPTED,
    REJECTED,
    ACCEPTED_WITH_LIMITATIONS,
    INCONCLUSIVE
};

enum class EncryptionStatus {
    UNKNOWN,
    ENCRYPTED,
    NOT_ENCRYPTED
};

struct PartitionInfo {
    std::string path;
    uint64_t startSector = 0;
    uint64_t sizeSectors = 0;
    uint64_t sizeBytes = 0;
    std::string filesystemType;
    std::string label;
    std::string uuid;
    bool mounted = false;
    std::string mountPoint;
    bool isBoot = false;
    bool isSystem = false;
};

struct FilesystemInfo {
    std::string type;
    std::string label;
    std::string uuid;
    uint64_t totalBytes = 0;
    uint64_t freeBytes = 0;
    std::string mountPoint;
};

struct DeviceInfo {
    std::string path;
    std::string model;
    std::string vendor;
    std::string serial;
    std::string firmware;
    std::string wwn;
    // Where model/serial/firmware came from: "sysfs", the device-reported
    // interface name, or an "unavailable:" explanation. Recorded so a reader of
    // a certificate can tell a value the device reported from one this tool
    // filled in, and can see when a serial could not be established at all.
    std::string identitySource;
    uint64_t capacityBytes = 0;
    uint32_t logicalBlockSize = 512;
    uint32_t physicalBlockSize = 512;
    TransportType transport = TransportType::UNKNOWN;
    MediaType mediaType = MediaType::UNKNOWN;
    // The kernel's queue/rotational, reported as read and never overwritten.
    //
    // It is not a statement about the medium for every device: a USB
    // mass-storage bridge commonly reports 1 whatever is inside it, so a flash
    // pen drive reads as rotational here while mediaType says Removable and
    // lsblk agrees. The raw value is kept because an assessor reading the
    // evidence wants what the kernel said; `rotationalDisputed` says whether to
    // believe it. Correcting the flag in place would hide a real disagreement
    // between the kernel and everything else this tool knows.
    bool rotational = false;
    // True when `rotational` contradicts the derived media type - the flag says
    // spinning and the device is removable or already classified as flash. Set
    // rather than inferred at the display layer, so the disagreement travels
    // with the identity into the evidence.
    bool rotationalDisputed = false;
    bool removable = false;
    bool readOnly = false;
    bool mounted = false;
    bool systemDisk = false;
    bool bootDisk = false;
    std::vector<PartitionInfo> partitions;
    std::vector<FilesystemInfo> filesystems;
    std::string sysfsPath;
    // For a USB mass-storage device, the sysfs node of the USB device that owns
    // it. Recorded because the bridge chip between the host and the media is the
    // thing that determines which commands can reach the media at all, and a
    // certificate that names the media but not the bridge hides that.
    std::string usbDeviceNode;
    std::chrono::system_clock::time_point discoveryTime;
};

struct CapabilityInfo {
    // What the capabilities below were established for. A regular file has no
    // bus, no controller and no command set, so the NVMe and ATA rows are
    // reported as a single "not applicable" note instead of a table of UNKNOWN
    // entries that reads like a device whose features could not be read.
    TargetKind targetKind = TargetKind::BLOCK_DEVICE;
    CapabilityStatus nvmeBlockErase = CapabilityStatus::UNKNOWN;
    CapabilityStatus nvmeCryptoErase = CapabilityStatus::UNKNOWN;
    CapabilityStatus nvmeOverwrite = CapabilityStatus::UNKNOWN;
    CapabilityStatus ataSecureErase = CapabilityStatus::UNKNOWN;
    CapabilityStatus ataEnhancedSecureErase = CapabilityStatus::UNKNOWN;
    CapabilityStatus ataSanitizeBlockErase = CapabilityStatus::UNKNOWN;
    CapabilityStatus ataSanitizeCryptoErase = CapabilityStatus::UNKNOWN;
    CapabilityStatus ataSanitizeOverwrite = CapabilityStatus::UNKNOWN;
    CapabilityStatus cryptoEraseHost = CapabilityStatus::UNSUPPORTED;
    CapabilityStatus overwriteHost = CapabilityStatus::UNSUPPORTED;
    EncryptionStatus encryptionStatus = EncryptionStatus::UNKNOWN;
    std::string nvmeControllerModel;
    std::string nvmeFirmware;
    uint32_t nvmeNamespaceId = 0;
    bool nvmeSanitizeSupported = false;
    // SANICAP bits 7:3: the maximum number of sanitize actions the controller
    // will accept in one Sanitize command. Recorded because issuing more
    // actions than this is a command error, and because a controller that
    // reports fewer than the tool intends to issue is a plan worth reviewing.
    uint32_t nvmeMaxSanitizeActions = 0;
    std::vector<std::string> supportedSanitizeActions;
    LimitationSet limitations;
};

// A sanitization method the policy engine considered for the requested
// category, together with why it was or was not selected. Recording the
// rejected candidates is what makes a plan reviewable: an assessor can see
// that weaker or unavailable mechanisms were considered and why they were not
// used, rather than having to trust a single asserted rationale.
struct MethodAssessment {
    SanitizationMethod method = SanitizationMethod::NONE;
    bool deviceSupported = false;
    bool permittedByPolicy = false;
    bool selected = false;
    std::string reason;
};

struct SanitizationPlan {
    std::string jobId;
    // What the job was pointed at. Added alongside `device`, not instead of it:
    // every field of DeviceInfo is still meaningful for a device or an image
    // target, and a job that names a block device must keep behaving exactly as
    // it did. A job that names something else fills in `target` and leaves
    // `device` as the identity of the medium, where there is one.
    SanitizationTarget target;
    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationCategory requestedCategory = SanitizationCategory::PURGE;
    // How `requestedCategory` came to be its value, and where the rule that
    // chose it comes from.
    //
    // This is not decoration. The same three level names appear in NIST SP
    // 800-88 Rev. 2, so a plan that says only "PURGE" is ambiguous about
    // whether the standard required it or the operator's local policy did. The
    // distinction changes what an assessor is being asked to check, so it
    // travels with the plan into the CLI output and the evidence.
    struct {
        // "local-policy" when deriveAssuranceTier() produced the tier,
        // "operator" when --assurance was given, "default" otherwise.
        std::string source = "default";
        // The inputs, as the operator gave them. Empty when not applicable.
        SecurityCategorization categorization = SecurityCategorization::UNSET;
        TriState reuseMedia = TriState::UNSET;
        TriState leavingOrgControl = TriState::UNSET;
        // Present whenever source is "local-policy". Names the policy as this
        // project's own, never as a NIST requirement.
        std::string provenance;
        // One line naming the rule that fired.
        std::string rationale;
    } assuranceBasis;

    SanitizationMethod selectedMethod = SanitizationMethod::NONE;
    // Overwrite passes to request when the selected method is an overwrite.
    //
    // NVMe encodes this in the Sanitize command's 4-bit OWPASS field, so 1..15
    // is the whole range the controller can be instructed to perform. 1 is this
    // tool's default, and that is a local choice rather than a NIST one: NIST SP
    // 800-88 Rev. 2 §3.1.1 prescribes no pass count at all. It records that
    // multi-pass overwrite "ranged from a single pass to as high as 39" as
    // historical practice, and that for "SSDs with overprovisioning, such
    // practices should be avoided"; technique selection is deferred to IEEE
    // 2883. A host also cannot know whether a given controller gains anything
    // from more. The value is recorded in the plan so the certificate states
    // what was actually asked for rather than leaving it implied.
    uint8_t overwritePassCount = 1;
    // How thoroughly the overwrite is read back. SAMPLED reads a fixed number
    // of sectors and reports the coverage; FULL reads every sector, which on a
    // multi-terabyte device is a read of the whole medium and is not the
    // default for that reason alone.
    enum class VerifyDepth {
        SAMPLED,
        FULL,
    };
    VerifyDepth verifyDepth = VerifyDepth::SAMPLED;
    std::string rationale;
    std::vector<std::string> standardReferences;
    std::vector<std::string> verificationPlan;
    std::vector<std::string> validationPlan;
    LimitationSet limitations;
    std::vector<std::string> risks;
    std::vector<MethodAssessment> alternativesConsidered;
    bool dryRun = false;
    std::chrono::system_clock::time_point createdAt;
};

struct JobStatus {
    std::string jobId;
    JobState state = JobState::UNKNOWN;
    uint64_t progressPercent = 0;
    // False means the device did not report progress. Consumers must render
    // "Device progress unavailable" rather than displaying progressPercent,
    // which is meaningless in that case.
    bool progressValid = false;
    uint64_t bytesProcessed = 0;
    uint64_t totalBytes = 0;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    // Must be initialised. std::chrono::seconds has a trivial default
    // constructor, so leaving this uninitialised yields an indeterminate value
    // that surfaces in reports and audit records as an absurd duration.
    std::chrono::seconds elapsedTime = std::chrono::seconds{0};
    std::string currentOperation;
    std::string devicePath;
    std::string errorMessage;
    int errorCode = 0;
    // True when this status was produced by a simulated method. Carried into
    // the audit record so a demo run can never be read as a real sanitization
    // result (CLAUDE.md s41).
    bool simulated = false;
};

struct VerificationEvidence {
    std::string method;
    std::string description;
    bool passed = false;
    std::string details;
    LimitationSet limitations;
};

struct VerificationReport {
    std::string jobId;
    VerificationResult result = VerificationResult::INCONCLUSIVE;
    std::vector<VerificationEvidence> evidence;
    std::vector<std::string> scope;
    LimitationSet limitations;
    std::chrono::system_clock::time_point timestamp;
};

struct ValidationReport {
    std::string jobId;
    ValidationResult result = ValidationResult::INCONCLUSIVE;
    std::string reasoning;
    std::vector<std::string> acceptedCriteria;
    std::vector<std::string> rejectedCriteria;
    LimitationSet limitations;
    std::chrono::system_clock::time_point timestamp;
};

struct AuditRecord {
    std::string jobId;
    std::string timestamp;
    // See EvidenceBundle: the invoking user and the effective user are
    // separate, because under sudo they differ and "root" alone attributes the
    // job to nobody.
    std::string operatorName;
    std::string invokingUser;
    uint32_t invokingUid = 0;
    std::string effectiveUser;
    uint32_t effectiveUid = 0;
    bool elevated = false;
    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationPlan plan;
    JobStatus execution;
    VerificationReport verification;
    ValidationReport validation;
    std::string applicationVersion;
};

struct RecoveryTestFile {
    std::string filename;
    uint64_t size = 0;
    std::string sha256;
    std::string fileType;
};

struct RecoveryMetrics {
    size_t knownFiles = 0;
    size_t completeRecoveries = 0;
    size_t partialRecoveries = 0;
    size_t failedRecoveries = 0;
    size_t falsePositives = 0;
    size_t hashMatches = 0;
    size_t signatureDetections = 0;
    double recoveryRate = 0.0;
    double completeRecoveryRate = 0.0;
    double hashMatchRate = 0.0;
};

struct RecoveryTestResult {
    std::string jobId;
    std::string testId;
    std::vector<RecoveryTestFile> baselineFiles;
    std::vector<RecoveryTestFile> recoveredFiles;
    RecoveryMetrics beforeMetrics;
    RecoveryMetrics afterMetrics;
    std::chrono::system_clock::time_point baselineTime;
    std::chrono::system_clock::time_point recoveryTime;
};

std::string transportToString(TransportType t);
std::string mediaTypeToString(MediaType t);
std::string categoryToString(SanitizationCategory c);
std::string methodToString(SanitizationMethod m);
std::string capabilityToString(CapabilityStatus c);
std::string jobStateToString(JobState s);
std::string verificationToString(VerificationResult v);
std::string validationToString(ValidationResult v);
std::string encryptionToString(EncryptionStatus e);

} // namespace ledgerase