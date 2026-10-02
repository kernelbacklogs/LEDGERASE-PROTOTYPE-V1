#include "ledgerase/reporting.hpp"
#include "ledgerase/limitations.hpp"
#include <iostream>
#include <iterator>
#include <sstream>
#include "ledgerase/cli.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/json_adapters.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <openssl/evp.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <random>

namespace ledgerase {

// AuditLogger is gone; see include/ledgerase/reporting.hpp for why. The SHA-256
// helpers below remain, because the certificate's canonical hash uses them.
namespace {

// SHA-256 via the EVP interface. The legacy SHA256_* helpers are deprecated
// in OpenSSL 3.0 and will be removed, so they must not be used here.
std::string sha256Hex(const unsigned char* digest, unsigned int len) {
    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned int>(digest[i]);
    }
    return ss.str();
}

} // namespace

std::string computeSha256(const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (EVP_Digest(data.data(), data.size(), digest, &digestLen, EVP_sha256(),
                   nullptr) != 1) {
        // Returning an empty string is preferable to emitting a bogus hash,
        // but callers must treat "" as "hash unavailable", never as a match.
        return {};
    }

    return sha256Hex(digest, digestLen);
}

class CertificateGenerator::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

CertificateGenerator::CertificateGenerator() : pImpl_(std::make_unique<Impl>()) {}
CertificateGenerator::~CertificateGenerator() = default;

Result<std::string> CertificateGenerator::generateEvidenceText(const EvidenceBundle& bundle) {
    std::ostringstream oss;
    oss << "===========================================\n";
    oss << "       CERTIFICATE OF SANITIZATION\n";
    oss << "       (rendered from the evidence bundle)\n";
    oss << "===========================================\n\n";

    oss << "Certificate ID:      " << bundle.certificateId << "\n";
    oss << "Job ID:              " << bundle.jobId << "\n";
    oss << "Generated:           " << bundle.generatedAt << "\n";
    oss << "Operator:            " << bundle.operatorName << "\n";
    oss << "Application Version: " << bundle.applicationVersion << "\n";
    oss << "Simulated run:       " << (bundle.simulated ? "YES" : "no") << "\n\n";

    oss << "STANDARD BASIS\n";
    oss << "--------------\n";
    oss << "Standard:  " << bundle.standardName << " (" << bundle.standardRole << ")\n";
    for (const auto& reference : bundle.additionalReferences) {
        oss << "Also referenced: " << reference << "\n";
    }
    oss << "\n";
    oss << bundle.conformanceStatement << "\n\n";

    oss << "DEVICE INFORMATION\n";
    oss << "------------------\n";
    oss << "Device Path:   " << bundle.device.path << "\n";
    oss << "Model:         " << bundle.device.model << "\n";
    if (!bundle.device.vendor.empty()) {
        oss << "Vendor:        " << bundle.device.vendor << "\n";
    }
    oss << "Serial:        "
        << (bundle.device.serial.empty() ? "NOT ESTABLISHED" : bundle.device.serial)
        << "\n";
    if (!bundle.device.identitySource.empty()) {
        oss << "Identity From: " << bundle.device.identitySource << "\n";
    }
    oss << "Capacity:      " << (bundle.device.capacityBytes / (1024*1024*1024)) << " GB\n";
    oss << "Transport:     " << transportToString(bundle.device.transport) << "\n";
    oss << "Media Type:    " << mediaTypeToString(bundle.device.mediaType) << "\n";
    if (!bundle.device.firmware.empty()) {
        oss << "Firmware:      " << bundle.device.firmware << "\n";
    }
    oss << "\n";

    oss << "MEDIA SCOPE (operator attestation)\n";
    oss << "-----------------------------------\n";
    oss << "All copies accounted for: "
        << (bundle.scope.allCopiesAccountedFor ? "ATTESTED" : "NOT ATTESTED") << "\n";
    for (const auto& copy : bundle.scope.copiesAddressed) {
        oss << "  Addressed: " << copy << "\n";
    }
    for (const auto& copy : bundle.scope.copiesNotAddressed) {
        oss << "  NOT addressed: " << copy << "\n";
    }
    if (!bundle.scope.rationale.empty()) {
        oss << "  Rationale: " << bundle.scope.rationale << "\n";
    }
    oss << "  Attested by: " << bundle.scope.attestedBy << "\n";
    oss << "\n";

    oss << "PRE-EXECUTION CHECKS\n";
    oss << "--------------------\n";
    for (const auto& check : bundle.preExecution.checks) {
        const char* status = check.result == SafetyCheckResult::PASS ? "PASS"
                          : check.result == SafetyCheckResult::FAIL ? "FAIL" : "WARN";
        oss << "  [" << status << "] " << check.name << ": " << check.message << "\n";
        if (!check.recommendation.empty()) {
            oss << "      -> " << check.recommendation << "\n";
        }
    }
    oss << "Device identity confirmed: "
        << (bundle.preExecution.deviceIdentityConfirmed ? "yes" : "NO") << "\n";
    oss << "Authorization:      "
        << (bundle.preExecution.authorizationReference.empty()
                ? "NOT RECORDED"
                : bundle.preExecution.authorizationReference)
        << "\n";
    if (!bundle.preExecution.authorizedBy.empty()) {
        oss << "Authorized by:     " << bundle.preExecution.authorizedBy << "\n";
    }
    if (!bundle.preExecution.authorizationBasis.empty()) {
        oss << "Basis:              " << bundle.preExecution.authorizationBasis << "\n";
    }
    oss << "\n";

    oss << "DECISION\n";
    oss << "--------\n";
    oss << "Requested category: " << categoryToString(bundle.requestedCategory) << "\n";
    oss << "Selected method:    " << methodToString(bundle.selectedMethod) << "\n";
    oss << "Rationale: " << bundle.decisionRationale << "\n";
    if (!bundle.standardReferences.empty()) {
        oss << "Standard references:\n";
        for (const auto& reference : bundle.standardReferences) {
            oss << "  - " << reference << "\n";
        }
    }
    if (!bundle.alternativesConsidered.empty()) {
        oss << "Methods considered:\n";
        for (const auto& candidate : bundle.alternativesConsidered) {
            oss << "  " << (candidate.selected ? "[SELECTED] " : "[         ] ")
                << std::left << std::setw(32) << methodToString(candidate.method)
                << candidate.reason << "\n";
        }
    }
    oss << "\n";

    oss << "EXECUTION\n";
    oss << "--------\n";
    oss << "Start Time:  " << formatTimestamp(bundle.execution.startTime) << "\n";
    oss << "End Time:    " << formatTimestamp(bundle.execution.endTime) << "\n";
    oss << "Duration:    " << bundle.execution.elapsedTime.count() << " seconds\n";
    oss << "State:       " << jobStateToString(bundle.execution.state) << "\n";
    oss << "Operation:   " << bundle.execution.currentOperation << "\n";
    if (!bundle.execution.errorMessage.empty()) {
        oss << "Error:       " << bundle.execution.errorMessage
            << " (code " << bundle.execution.errorCode << ")\n";
    }
    oss << "\n";

    oss << "VERIFICATION\n";
    oss << "------------\n";
    oss << "Result: " << verificationToString(bundle.verification.result) << "\n";
    oss << "Independence: " << verificationIndependenceToString(
                                 bundle.verificationIndependence.level)
        << " (" << bundle.verificationIndependence.performedBy << ")\n";
    if (!bundle.verificationIndependence.notes.empty()) {
        oss << "  " << bundle.verificationIndependence.notes << "\n";
    }
    for (const auto& item : bundle.verification.evidence) {
        oss << "  - " << item.method << ": " << (item.passed ? "supports" : "does not support")
            << " - " << item.description << "\n";
        if (!item.details.empty()) {
            oss << "      " << item.details << "\n";
        }
    }
    if (!bundle.verification.scope.empty()) {
        oss << "  Scope:\n";
        for (const auto& line : bundle.verification.scope) {
            oss << "    - " << line << "\n";
        }
    }
    oss << "\n";

    oss << "VALIDATION\n";
    oss << "----------\n";
    oss << "Result: " << validationToString(bundle.validation.result) << "\n";
    oss << bundle.validation.reasoning << "\n";
    for (const auto& criterion : bundle.validation.acceptedCriteria) {
        oss << "  Accepted: " << criterion << "\n";
    }
    for (const auto& criterion : bundle.validation.rejectedCriteria) {
        oss << "  Rejected: " << criterion << "\n";
    }
    oss << "\n";

    oss << "RESIDUAL RISK\n";
    oss << "-------------\n";
    oss << "Residual data possible: " << (bundle.residualDataPossible ? "YES" : "no") << "\n";
    oss << bundle.residualRiskStatement << "\n";
    for (const auto& limitation : bundle.residualRiskLimitations) {
        oss << "  - " << limitation << "\n";
    }
    oss << "\n";

    oss << "RETENTION\n";
    oss << "---------\n";
    oss << "Policy:      " << retentionPolicyToString(bundle.retention.policy) << "\n";
    if (!bundle.retention.retainUntil.empty()) {
        oss << "Retain until: " << bundle.retention.retainUntil << "\n";
    }
    oss << "\n";

    oss << "INTEGRITY\n";
    oss << "---------\n";
    oss << "Hash algorithm: " << bundle.hashAlgorithm << "\n";
    oss << "Canonical hash: " << bundle.canonicalHash << "\n";
    oss << "Event chain:   " << bundle.chainLength << " records\n";
    oss << "Chain head:    " << bundle.chainHead << "\n";
    oss << "Signed:        " << (bundle.signatures.empty() ? "no" : "yes") << "\n";
    for (const auto& signature : bundle.signatures) {
        oss << "  " << signature.algorithm << " key " << signature.keyId
            << " over " << signature.signedField << " at " << signature.signedAt << "\n";
    }
    oss << "\n";
    oss << "Check this document with:\n";
    oss << "  ledgerase-cli verify-log <file>\n";
    oss << "===========================================\n";
    return Result<std::string>::ok(oss.str());
}

Result<void> CertificateGenerator::writeEvidencePdf(const EvidenceBundle& bundle,
                                                   const std::string& outputPath) {
    auto textResult = generateEvidenceText(bundle);
    if (textResult.isError()) {
        return Result<void>::err(textResult.error());
    }

    std::ofstream file(outputPath);
    if (!file) {
        return Result<void>::err(ErrorCode::IO_ERROR, "Failed to create PDF file: " + outputPath);
    }
    // A real PDF library is not linked. The file is therefore an explicitly
    // labelled placeholder and says so in its own body, so it cannot be mistaken
    // for a rendered certificate. Use --format text or json for the record.
    file << "%PDF-1.4\n";
    file << "% PLACEHOLDER: this build has no PDF library linked. The text\n";
    file << "% certificate for this job is reproduced below verbatim.\n";
    file << "% Job: " << bundle.jobId << "\n";
    file << "% Certificate: " << bundle.certificateId << "\n";
    file << "% Canonical hash: " << bundle.canonicalHash << "\n";
    for (const char c : textResult.value()) {
        if (c == '%' || c == '(' || c == ')' || c == '\\') file << '\\';
        file << c;
    }
    file << "\n%%EOF\n";
    return Result<void>::success();
}

std::string CertificateGenerator::generateCertificateId() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << "SAN-" << std::put_time(std::gmtime(&time), "%Y%m%d-%H%M%S");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    ss << "-" << dis(gen);

    return ss.str();
}

class ReportGenerator::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

ReportGenerator::ReportGenerator() : pImpl_(std::make_unique<Impl>()) {}
ReportGenerator::~ReportGenerator() = default;

Result<std::string> ReportGenerator::generateExecutionReport(const JobStatus& status) {
    std::ostringstream oss;
    oss << "Job ID: " << status.jobId << "\n";
    oss << "State: " << jobStateToString(status.state) << "\n";
    // Same rule as every other display path: a percentage the device never
    // reported looks like a measurement. progressValid is false when the
    // controller has no progress field.
    oss << "Progress: "
        << (status.progressValid
                ? std::to_string(status.progressPercent) + "%"
                : std::string("Device progress unavailable"))
        << "\n";
    oss << "Bytes Processed: " << status.bytesProcessed << " / " << status.totalBytes << "\n";
    oss << "Elapsed: " << status.elapsedTime.count() << " seconds\n";
    oss << "Operation: " << status.currentOperation << "\n";
    if (!status.errorMessage.empty()) {
        oss << "Error: " << status.errorMessage << " (code: " << status.errorCode << ")\n";
    }
    return Result<std::string>::ok(oss.str());
}

// ---------------------------------------------------------------------------
// OutputFormatter
//
// Moved here from src/cli/cli.cpp. It is a domain formatter, not a CLI concern:
// the GUI has to render the same device, capability and status output, and
// keeping it in the CLI translation unit put it outside the core library, so no
// test and no other consumer could reach it. That is how a formatting rule went
// unfixed in one place and fixed in another - the kind of divergence a shared
// library exists to prevent.
// ---------------------------------------------------------------------------

class OutputFormatter::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

OutputFormatter::OutputFormatter() : pImpl_(std::make_unique<Impl>()) {}
OutputFormatter::~OutputFormatter() = default;

void OutputFormatter::setJsonOutput(bool enabled) {
    jsonOutput_ = enabled;
}

void OutputFormatter::setVerbose(bool enabled) {
    verbose_ = enabled;
}

Result<void> OutputFormatter::outputDeviceInfo(const DeviceInfo& device) {
    std::cout << "Device: " << device.path << "\n";
    std::cout << "  Model:        " << device.model << "\n";
    std::cout << "  Vendor:       " << device.vendor << "\n";
    std::cout << "  Serial:       " << device.serial << "\n";
    std::cout << "  Firmware:     " << device.firmware << "\n";
    std::cout << "  Capacity:     " << (device.capacityBytes / (1024*1024*1024)) << " GB\n";
    std::cout << "  Logical BS:   " << device.logicalBlockSize << " bytes\n";
    std::cout << "  Physical BS:  " << device.physicalBlockSize << " bytes\n";
    std::cout << "  Transport:    " << transportToString(device.transport) << "\n";
    std::cout << "  Media Type:   " << mediaTypeToString(device.mediaType) << "\n";
    // The raw kernel flag, annotated when it is contradicted. Printing a bare
    // "Yes" for a flash pen drive that reports queue/rotational=1 leaves the
    // reader to work out that the flag is about the bridge and not the medium -
    // and an operator who concludes "this is a spinning disk" from it would be
    // wrong about how the device has to be sanitized.
    std::cout << "  Rotational:   " << (device.rotational ? "Yes" : "No");
    if (device.rotationalDisputed) {
        std::cout << " (kernel flag; USB bridges report this for flash too -"
                  << " see Media Type)";
    }
    std::cout << "\n";
    std::cout << "  Removable:    " << (device.removable ? "Yes" : "No") << "\n";
    std::cout << "  Read-Only:    " << (device.readOnly ? "Yes" : "No") << "\n";
    std::cout << "  Mounted:      " << (device.mounted ? "Yes" : "No") << "\n";
    std::cout << "  System Disk:  " << (device.systemDisk ? "Yes" : "No") << "\n";
    std::cout << "  Boot Disk:    " << (device.bootDisk ? "Yes" : "No") << "\n";

    // WWN, identity source and sysfs path were filled in on every inspection and
    // shown by no report and used by no decision. Shown now: the WWN is how an
    // operator tells two otherwise identical drives apart, which is exactly what
    // the confirmation step needs.
    if (!device.wwn.empty()) {
        std::cout << "  WWN:          " << device.wwn << "\n";
    }
    if (!device.identitySource.empty()) {
        std::cout << "  Identity via: " << device.identitySource << "\n";
    }
    if (!device.sysfsPath.empty()) {
        std::cout << "  Sysfs:        " << device.sysfsPath << "\n";
    }

    if (!device.partitions.empty()) {
        std::cout << "  Partitions:\n";
        for (const auto& part : device.partitions) {
            std::cout << "    " << part.path << " - " << part.filesystemType
                      << " - " << (part.sizeBytes / (1024*1024)) << " MB";
            if (part.mounted) std::cout << " [MOUNTED: " << part.mountPoint << "]";
            std::cout << "\n";
        }
    }

    return Result<void>::success();
}

Result<void> OutputFormatter::outputCapabilityInfo(const CapabilityInfo& caps) {
    // Controller identity first. It was read from Identify Controller on every
    // NVMe inspection and then shown by no report, so an assessor had a SANICAP
    // reading with no way to tell which controller produced it. Recorded fields
    // that no one can see are recorded for nothing.
    if (!caps.nvmeControllerModel.empty() || !caps.nvmeFirmware.empty()) {
        std::cout << "Controller:\n";
        if (!caps.nvmeControllerModel.empty()) {
            std::cout << "  Model:     " << caps.nvmeControllerModel << "\n";
        }
        if (!caps.nvmeFirmware.empty()) {
            std::cout << "  Firmware:  " << caps.nvmeFirmware << "\n";
        }
        std::cout << "  Namespace: " << caps.nvmeNamespaceId << "\n";
    }

    std::cout << "\nNVMe Capabilities:\n";
    std::cout << "  Block Erase:      " << capabilityToString(caps.nvmeBlockErase) << "\n";
    std::cout << "  Crypto Erase:     " << capabilityToString(caps.nvmeCryptoErase) << "\n";
    std::cout << "  Overwrite:        " << capabilityToString(caps.nvmeOverwrite) << "\n";
    std::cout << "  Sanitize Supported: " << (caps.nvmeSanitizeSupported ? "Yes" : "No") << "\n";
    // Only meaningful when sanitize is supported, and the value the policy
    // engine now refuses on when it reads zero.
    if (caps.nvmeSanitizeSupported) {
        std::cout << "  Max Sanitize Actions: " << caps.nvmeMaxSanitizeActions
                  << " (SANICAP bits 7:3)\n";
    }

    std::cout << "\nATA Capabilities:\n";
    std::cout << "  Secure Erase:           " << capabilityToString(caps.ataSecureErase) << "\n";
    std::cout << "  Enhanced Secure Erase:  " << capabilityToString(caps.ataEnhancedSecureErase) << "\n";
    std::cout << "  Sanitize Block Erase:   " << capabilityToString(caps.ataSanitizeBlockErase) << "\n";
    std::cout << "  Sanitize Crypto Erase:  " << capabilityToString(caps.ataSanitizeCryptoErase) << "\n";
    std::cout << "  Sanitize Overwrite:     " << capabilityToString(caps.ataSanitizeOverwrite) << "\n";

    std::cout << "\nHost Methods:\n";
    std::cout << "  Overwrite:      " << capabilityToString(caps.overwriteHost) << "\n";
    std::cout << "  Crypto Erase:   " << capabilityToString(caps.cryptoEraseHost) << "\n";

    std::cout << "\nEncryption Status: " << encryptionToString(caps.encryptionStatus) << "\n";

    if (!caps.supportedSanitizeActions.empty()) {
        std::cout << "\nSupported Actions:\n";
        for (const auto& action : caps.supportedSanitizeActions) {
            std::cout << "  - " << action << "\n";
        }
    }

    if (!caps.limitations.empty()) {
        std::cout << "\nLimitations:\n";
        for (const auto& lim : caps.limitations) {
            std::cout << "  - " << lim << "\n";
        }
    }

    return Result<void>::success();
}

Result<void> OutputFormatter::outputJobStatus(const JobStatus& status) {
    std::cout << "Job ID: " << status.jobId << "\n";
    std::cout << "State: " << jobStateToString(status.state) << "\n";
    // A percentage the device never reported is worse than no percentage: it
    // looks like a measurement. progressValid is false when the controller has
    // no progress field, and then the honest statement is that it is unavailable.
    std::cout << "Progress: "
              << (status.progressValid
                      ? std::to_string(status.progressPercent) + "%"
                      : std::string("Device progress unavailable"))
              << "\n";
    std::cout << "Elapsed: " << status.elapsedTime.count() << " seconds\n";
    if (!status.errorMessage.empty()) {
        std::cout << "Error: " << status.errorMessage << " (code: " << status.errorCode << ")\n";
    }
    return Result<void>::success();
}

Result<void> OutputFormatter::outputError(const SanitizerError& error) {
    std::cerr << "ERROR [" << static_cast<int>(error.code()) << "]: " << error.what() << "\n";
    if (!error.recommendedAction().empty()) {
        std::cerr << "Recommended action: " << error.recommendedAction() << "\n";
    }
    return Result<void>::success();
}

Result<void> OutputFormatter::outputMessage(const std::string& message) {
    std::cout << message << "\n";
    return Result<void>::success();
}

Result<void> OutputFormatter::outputWarning(const std::string& message) {
    std::cerr << "WARNING: " << message << "\n";
    return Result<void>::success();
}


namespace {

// Terminal columns the limitation summary aims for.
constexpr std::size_t kSummaryWidth = 78;

} // namespace

Result<void> OutputFormatter::outputLimitations(const LimitationSet& limitations,
                                                const std::string& evidencePath) {
    if (limitations.empty()) {
        return Result<void>::success();
    }

    if (verbose_) {
        // The complete list, with IDs, printed at most once per process. The
        // guard was documented in the comment and in the header and was not in
        // the code, so a run that printed the list at the end of the operation
        // printed it again in the evidence summary.
        if (fullListPrinted_) {
            return Result<void>::success();
        }
        std::cout << "\nLimitations (" << limitations.size() << "):\n";
        std::string group;
        for (const LimitationEntry& entry : limitations.entries()) {
            if (entry.group != group) {
                group = entry.group;
                std::cout << "  " << group << "\n";
            }
            std::cout << "    " << renderLimitation(entry) << "\n";
        }
        fullListPrinted_ = true;
        return Result<void>::success();
    }

    // Grouped view. Four facts, not a wall of near-duplicates.
    std::cout << "\nLimitations (" << limitations.size() << ")\n";

    for (const std::string& groupName : limitationGroups()) {
        std::vector<const LimitationEntry*> inGroup;
        for (const LimitationEntry& entry : limitations.entries()) {
            if (entry.group == groupName) {
                inGroup.push_back(&entry);
            }
        }
        if (inGroup.empty()) {
            continue;
        }

        // Each entry's short label, never its sentence.
        //
        // The previous version used a hand-maintained list of four shortened
        // strings, applied only when a group happened to hold more than two
        // entries, and fell back to the full sentence otherwise. The result was
        // the output this method was supposed to have stopped producing:
        //
        //   Device: Clear-level method. It is not device-level sanitization, A
        //   USB bridge mediates every command. Results describe the bridge's
        //   view of the media.
        //
        // Two facts glued into one sentence with a comma, and the comma is not
        // even where the sentence break was. The short labels already existed on
        // every entry, which is what they are for, so the list of four literals
        // and the branch that chose between them are both gone.
        std::vector<std::string> pieces;
        pieces.reserve(inGroup.size());
        for (const LimitationEntry* entry : inGroup) {
            pieces.push_back(entry->shortLabel.empty() ? entry->text
                                                       : entry->shortLabel);
        }

        // Semicolons, because the pieces are noun phrases rather than sentences.
        // A comma would run two separate facts into one claim; a semicolon keeps
        // them apart and still fits on a line.
        std::string joined;
        for (std::size_t i = 0; i < pieces.size(); ++i) {
            if (i > 0) {
                joined += "; ";
            }
            joined += pieces[i];
        }

        const std::string label = groupName + ":";
        const std::size_t indent = 2 + label.size() + 1;
        std::cout << "  " << label << " ";

        std::istringstream words(joined);
        std::string word;
        std::size_t column = indent;
        bool first = true;
        while (words >> word) {
            if (column + word.size() > kSummaryWidth && !first) {
                std::cout << "\n" << std::string(indent, ' ');
                column = indent;
                first = true;
            }
            if (!first) {
                std::cout << " ";
                ++column;
            }
            std::cout << word;
            column += word.size();
            first = false;
        }
        std::cout << "\n";
    }

    std::cout << "\n  " << limitations.size() << " recorded. Full list: "
              << evidencePath << "\n";
    return Result<void>::success();
}

bool OutputFormatter::fullLimitationListPrinted() const {
    return fullListPrinted_;
}
} // namespace ledgerase
