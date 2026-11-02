#include "cli.hpp"
#include "evidence/reports/progress_reporter.hpp"
#include "ledgerase/device.hpp"
#include "ledgerase/capability.hpp"
#include "ledgerase/safety.hpp"
#include "ledgerase/policy.hpp"
#include "ledgerase/sanitization.hpp"
#include "ledgerase/verification.hpp"
#include "ledgerase/reporting.hpp"
#include "ledgerase/filesystem_capability.hpp"
#include "ledgerase/operator.hpp"
#include "ledgerase/database.hpp"
#include "mock/mock.hpp"
#include "ledgerase/json_adapters.hpp"
#include "ledgerase/ledgerase.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <filesystem>
#include <map>
#include <fstream>
#include <string_view>
#include <cerrno>
#include <cstring>
#include <fcntl.h>

namespace ledgerase {
namespace {

// Makes sure the directory an evidence document will be written into exists, and
// is private if this run is the one that created it.
//
// Shared by the sanitization and carve paths rather than written twice: a carve
// record names the medium, the operator and the recovered digests, which is the
// same sensitivity as a certificate, and a second copy of this logic is a second
// copy to get wrong.
//
// 0700 is applied only to a directory this run created. An existing directory is
// left alone: the operator chose it, and silently changing the permissions of a
// directory they already own would be a worse surprise than a permissive mode
// they set deliberately.
Result<void> ensureEvidenceDirectory(
    const std::string& evidencePath,
    const std::string& advice =
        "Choose a writable location with --evidence <path>, or create the "
        "directory first. Every job must produce a record, so the run is "
        "refused rather than proceeding unrecorded.") {
    const std::size_t slash = evidencePath.find_last_of('/');
    const std::string targetDir =
        slash == std::string::npos ? std::string(".") : evidencePath.substr(0, slash);

    std::error_code ec;
    if (std::filesystem::exists(targetDir, ec)) {
        return Result<void>::success();
    }

    // audit/ and reports/ live inside the evidence directory. When this run is
    // the one creating that parent as well, it is restricted the same way, so
    // the split does not leave a world-readable directory above a private one.
    const std::filesystem::path target{targetDir};
    const std::string leaf = target.filename().string();
    const bool isStoreDirectory =
        leaf == kAuditSubdirectory || leaf == kReportsSubdirectory;
    const std::filesystem::path parent = target.parent_path();
    const bool parentIsNew =
        isStoreDirectory && !parent.empty() && !std::filesystem::exists(parent, ec);

    std::filesystem::create_directories(targetDir, ec);
    if (ec) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "Cannot create the evidence directory " + targetDir + ": " + ec.message(),
            advice);
    }
    std::filesystem::permissions(targetDir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    if (!ec && parentIsNew) {
        std::filesystem::permissions(parent, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, ec);
    }
    if (ec) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "Cannot restrict the evidence directory " + targetDir + ": " + ec.message(),
            "Choose a location where the evidence can be kept private");
    }
    return Result<void>::success();
}

// Bundles written before audit/ and reports/ were separated sit directly in the
// evidence directory. They stay readable: moving the layout must not make an
// existing record set appear to be gone. Nothing is ever written here.
std::string legacyEvidencePath(const std::string& jobId, const std::string& directory) {
    return directory + "/" + jobId + ".json";
}

// Writes an export without following a symlink at the destination and without
// leaving a partial file behind. The temporary file is created in the target
// directory so the final link or rename stays on one filesystem.
Result<void> copyEvidenceFile(const std::string& source,
                              const std::string& destination, bool overwrite) {
    const int input = ::open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot open " + source + ": " +
                                     std::strerror(errno));
    }

    const std::filesystem::path target(destination);
    const std::filesystem::path parent =
        target.parent_path().empty() ? std::filesystem::path(".")
                                     : target.parent_path();
    static unsigned counter = 0;
    const std::filesystem::path temporary =
        parent / ("." + target.filename().string() + ".tmp-" +
                  std::to_string(static_cast<long long>(::getpid())) + "-" +
                  std::to_string(++counter));
    const int output =
        ::open(temporary.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
               S_IRUSR | S_IWUSR);
    if (output < 0) {
        ::close(input);
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot create " + temporary.string() + ": " +
                                     std::strerror(errno));
    }

    std::vector<char> buffer(64 * 1024);
    while (true) {
        const ssize_t n = ::read(input, buffer.data(), buffer.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            ::close(input);
            ::close(output);
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Read failed: " +
                                         std::string(std::strerror(saved)));
        }
        if (n == 0) {
            break;
        }
        size_t written = 0;
        while (written < static_cast<size_t>(n)) {
            const ssize_t w = ::write(output, buffer.data() + written,
                                      static_cast<size_t>(n) - written);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                const int saved = errno;
                ::close(input);
                ::close(output);
                ::unlink(temporary.c_str());
                return Result<void>::err(
                    ErrorCode::IO_ERROR,
                    "Write failed: " + std::string(std::strerror(saved)));
            }
            written += static_cast<size_t>(w);
        }
    }
    ::close(input);
    if (::fsync(output) != 0) {
        const int saved = errno;
        ::close(output);
        ::unlink(temporary.c_str());
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Flush failed: " +
                                     std::string(std::strerror(saved)));
    }
    ::close(output);

    if (overwrite) {
        if (::rename(temporary.c_str(), destination.c_str()) != 0) {
            const int saved = errno;
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot replace " + destination + ": " +
                                         std::strerror(saved));
        }
    } else {
        if (::link(temporary.c_str(), destination.c_str()) != 0) {
            const int saved = errno;
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + destination + ": " +
                                         std::strerror(saved));
        }
        ::unlink(temporary.c_str());
    }
    return Result<void>::success();
}

Result<std::string> sha256OfFileForIndex(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return Result<std::string>::err(ErrorCode::IO_ERROR,
                                        "Cannot read " + path);
    }
    Sha256Stream stream;
    std::vector<char> buffer(64 * 1024);
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got > 0) {
            stream.update(reinterpret_cast<const uint8_t*>(buffer.data()),
                          static_cast<size_t>(got));
        }
    }
    return stream.finalHex();
}

uint64_t fileSizeForIndex(const std::string& path) {
    std::error_code ec;
    const uintmax_t size = std::filesystem::file_size(path, ec);
    return ec ? 0 : static_cast<uint64_t>(size);
}

std::vector<EvidenceChainRow> chainRowsFor(const std::vector<EvidenceRecord>& chain) {
    std::vector<EvidenceChainRow> rows;
    rows.reserve(chain.size());
    for (const EvidenceRecord& record : chain) {
        EvidenceChainRow row;
        row.sequence = record.sequence;
        row.timestamp = record.timestamp;
        row.type = record.type;
        row.payload = record.payload.dump();
        row.prevHash = record.prevHash;
        row.recordHash = record.recordHash;
        rows.push_back(std::move(row));
    }
    return rows;
}

EvidenceArtifactRow artifactRowFor(const std::string& path,
                                   const std::string& type,
                                   const std::string& formatVersion,
                                   const std::string& createdAt,
                                   const std::string& sha256,
                                   const std::string& signatureKeyId,
                                   bool signaturePresent) {
    EvidenceArtifactRow row;
    row.artifactType = type;
    row.path = path;
    row.fileSize = fileSizeForIndex(path);
    row.sha256 = sha256;
    row.formatVersion = formatVersion;
    row.createdAt = createdAt;
    row.signatureKeyId = signatureKeyId;
    row.signaturePresent = signaturePresent;
    return row;
}

EvidenceRegistration registrationFromSanitization(const EvidenceBundle& bundle,
                                                   const std::string& path,
                                                   const std::string& sha256,
                                                   const std::string& description) {
    EvidenceRegistration registration;
    registration.record.jobId = bundle.jobId;
    registration.record.description = description;
    registration.record.operation = "drive-erasure";
    registration.record.target = bundle.device.path;
    registration.record.targetType = mediaTypeToString(bundle.device.mediaType);
    registration.record.deviceModel = bundle.device.model;
    registration.record.status =
        bundle.execution.state == JobState::COMPLETED ? "SUCCESS" : "FAILED";
    registration.record.createdAt = bundle.generatedAt;
    registration.record.bundlePath = path;
    registration.record.bundleSha256 = sha256;
    registration.record.formatVersion = bundle.schema;

    registration.job.jobId = bundle.jobId;
    registration.job.operation = registration.record.operation;
    registration.job.status = registration.record.status;
    if (bundle.execution.startTime != std::chrono::system_clock::time_point{}) {
        registration.job.startedAt = formatTimestamp(bundle.execution.startTime);
    }
    if (bundle.execution.endTime != std::chrono::system_clock::time_point{}) {
        registration.job.completedAt = formatTimestamp(bundle.execution.endTime);
    }
    registration.job.applicationVersion = bundle.applicationVersion;
    registration.job.evidenceFormatVersion = bundle.schema;
    registration.job.deviceId = bundle.device.path;
    registration.job.method = methodToString(bundle.selectedMethod);
    registration.job.result = validationToString(bundle.validation.result);
    registration.job.error = bundle.execution.errorMessage;

    if (!bundle.device.path.empty()) {
        EvidenceDeviceRow device;
        device.deviceId = bundle.device.path;
        device.deviceType = mediaTypeToString(bundle.device.mediaType);
        device.manufacturer = bundle.device.vendor;
        device.model = bundle.device.model;
        device.capacityBytes = bundle.device.capacityBytes;
        device.logicalSectorSize = bundle.device.logicalBlockSize;
        device.identifiers = bundle.device.model;
        registration.device = std::move(device);
    }

    registration.events = chainRowsFor(bundle.eventChain);
    const std::string keyId =
        bundle.signatures.empty() ? std::string() : bundle.signatures.front().keyId;
    registration.artifacts.push_back(artifactRowFor(
        path, "sanitization-bundle", bundle.schema, bundle.generatedAt, sha256,
        keyId, !bundle.signatures.empty()));
    return registration;
}

EvidenceRegistration registrationFromErase(const EraseEvidenceBundle& bundle,
                                           const std::string& path,
                                           const std::string& sha256,
                                           const std::string& description) {
    EvidenceRegistration registration;
    registration.record.jobId = bundle.jobId;
    registration.record.description = description;
    registration.record.operation =
        bundle.targetKind == "folder" ? "folder-erasure" : "file-erasure";
    registration.record.target = bundle.targetPath;
    registration.record.targetType = bundle.targetKind;
    registration.record.status =
        (bundle.filesFailed > 0 || bundle.filesRefused > 0) ? "FAILED" : "SUCCESS";
    registration.record.createdAt = bundle.generatedAt;
    registration.record.bundlePath = path;
    registration.record.bundleSha256 = sha256;
    registration.record.formatVersion = bundle.schema;

    registration.job.jobId = bundle.jobId;
    registration.job.operation = registration.record.operation;
    registration.job.status = registration.record.status;
    registration.job.applicationVersion = bundle.applicationVersion;
    registration.job.evidenceFormatVersion = bundle.schema;
    registration.job.result = registration.record.status;
    if (bundle.filesFailed > 0 || bundle.filesRefused > 0) {
        registration.job.error =
            std::to_string(bundle.filesRefused) + " refused, " +
            std::to_string(bundle.filesFailed) + " failed";
    }

    registration.events = chainRowsFor(bundle.eventChain);
    registration.artifacts.push_back(artifactRowFor(
        path, "erase-bundle", bundle.schema, bundle.generatedAt, sha256, "", false));
    return registration;
}

EvidenceRegistration registrationFromCarve(const CarveEvidenceBundle& bundle,
                                           const std::string& path,
                                           const std::string& sha256,
                                           const std::string& description) {
    EvidenceRegistration registration;
    registration.record.jobId = bundle.jobId;
    registration.record.description = description;
    registration.record.operation = "carving";
    registration.record.target = bundle.source.path;
    registration.record.targetType =
        bundle.source.kind.empty() ? "source" : bundle.source.kind;
    registration.record.status = "SUCCESS";
    registration.record.createdAt = bundle.generatedAt;
    registration.record.bundlePath = path;
    registration.record.bundleSha256 = sha256;
    registration.record.formatVersion = bundle.schema;

    registration.job.jobId = bundle.jobId;
    registration.job.operation = registration.record.operation;
    registration.job.status = registration.record.status;
    registration.job.applicationVersion = bundle.applicationVersion;
    registration.job.evidenceFormatVersion = bundle.schema;
    registration.job.result = registration.record.status;

    registration.events = chainRowsFor(bundle.eventChain);
    registration.artifacts.push_back(artifactRowFor(
        path, "carve-bundle", bundle.schema, bundle.generatedAt, sha256, "", false));
    return registration;
}

Result<EvidenceRecordRow> indexEvidence(const std::string& configuredPath,
                                        const EvidenceRegistration& registration) {
    const std::string path =
        configuredPath.empty() ? defaultDatabasePath() : configuredPath;
    auto opened = EvidenceDatabase::open(path, true);
    if (opened.isError()) {
        return Result<EvidenceRecordRow>::err(opened.error());
    }
    auto initialised = opened.value().initialize();
    if (initialised.isError()) {
        return Result<EvidenceRecordRow>::err(initialised.error());
    }
    return opened.value().registerEvidence(registration);
}

void reportIndexResult(const Result<EvidenceRecordRow>& indexed) {
    if (indexed.isError()) {
        std::cout << "\nWarning: the bundle was written, but the evidence index "
                     "was not updated:\n  "
                  << indexed.error().what() << "\n"
                  << "  The bundle is still the record. Run 'evidence check' to "
                     "reconcile the index.\n";
        return;
    }
    std::cout << "\nEvidence ID: " << indexed.value().evidenceId
              << "  (indexed; the bundle remains the record)\n";
}

std::string currentOperator() {
    return currentOperatorIdentity().invokingUser;
}

std::string describeOptions(const CliOptions& options) {
    std::ostringstream out;
    out << "command=" << options.command;
    if (!options.devicePath.empty()) out << " device=" << options.devicePath;
    if (!options.jobId.empty()) out << " job=" << options.jobId;
    out << " assurance=" << categoryToString(options.assurance)
        << " method=" << methodToString(options.method)
        << " overwrite_passes=" << static_cast<unsigned>(options.overwritePassCount)
        << " dry_run=" << (options.dryRun ? "true" : "false")
        << " simulation=" << (options.simulationMode ? "true" : "false");
    if (!options.outputFile.empty()) out << " output=" << options.outputFile;
    if (!options.evidenceFile.empty()) out << " evidence=" << options.evidenceFile;
    return out.str();
}

// True when this command's positional argument names a job rather than a device.
//
// Without this, the single positional argument was always taken as a device
// path, so the documented invocations "verify JOB-ID", "report JOB-ID" and
// "evidence JOB-ID" all reported "Job ID required". The commands that address a
// past job take a job id; the ones that act on media take a device path.
bool commandTakesJobId(const std::string& command) {
    return command == "verify" || command == "validate" || command == "report" ||
           command == "audit" || command == "evidence" || command == "recover-test";
}

// True when the command's positional argument is a target to be sanitized or
// inspected, rather than a job id or a file to read.
bool commandTakesTarget(const std::string& command) {
    return command == "sanitize" || command == "plan" ||
           command == "capabilities" || command == "inspect";
}

// The schema of an evidence bundle on disk, or an empty string when the file
// is not an evidence bundle.
//
// Read from the stored document rather than through the bundle reader, so
// that a file which is not JSON at all, or is JSON but not a bundle, is
// recognised as such instead of being reported as a damaged bundle.
std::string evidenceSchemaOf(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    nlohmann::json document;
    try {
        document = nlohmann::json::parse(buffer.str());
    } catch (const nlohmann::json::parse_error&) {
        return {};
    }
    if (!document.is_object() || !document.contains("schema")) {
        return {};
    }
    const std::string schema = document.at("schema").get<std::string>();
    for (const char* supported : EvidenceBundle::kSupportedSchemas) {
        if (schema == supported) {
            return schema;
        }
    }
    return {};
}

} // namespace

class CliApplication::Impl {
public:
    Impl() : deviceManager(), capabilityDetector(), safetyManager(),
             policyEngine(SanitizationPolicyEngine::createDefaultPolicy()),
             planner(policyEngine), executor(), verificationEngine(),
             validationEngine(), mockBackend() {
        mockBackend.addDevice(MockBackend::createMockHdd());
        mockBackend.addDevice(MockBackend::createMockSataSsd());
        mockBackend.addDevice(MockBackend::createMockNvmeSsd());
        mockBackend.addDevice(MockBackend::createMockUnsupported());
        mockBackend.addDevice(MockBackend::createMockFailed());
        mockBackend.addDevice(MockBackend::createMockUnknownCapabilities());
        // Two USB profiles, because the question that matters is not "can this
        // tool talk to USB" but "what does it do when a bridge accepts every
        // command and erases nothing".
        mockBackend.addDevice(MockBackend::createMockUsbBridgePassthrough());
        mockBackend.addDevice(MockBackend::createMockUsbBridgeDropsCommands());
    }

    // MediaScopeAttestation from the CLI flags. Nothing here is inferred: an
    // absent flag yields an unattested field, which the builder then treats as
    // a limitation.
    MediaScopeAttestation scopeFrom(const CliOptions& options,
                                    const DeviceInfo& device) const {
        MediaScopeAttestation scope;
        scope.allCopiesAccountedFor = options.attestAllCopies;
        scope.copiesAddressed.push_back(device.path +
                                        " (the media sanitized by this event)");
        if (!options.copiesNotAddressed.empty()) {
            scope.copiesNotAddressed.push_back(options.copiesNotAddressed);
        }
        scope.rationale = options.scopeRationale;
        scope.attestedBy = currentOperator();
        return scope;
    }

    PreExecutionAttestation preExecutionFrom(const CliOptions& options,
                                             const SafetyReport& safety) const {
        PreExecutionAttestation pre;
        pre.checks = safety.checks;
        // --identity-confirmed is an operator attestation that the media's
        // identity was checked against its physical label. It was parsed,
        // documented, echoed into the chain summary, and never assigned here, so
        // the evidence gates always added NO_IDENTITY_CONFIRMATION and always
        // downgraded an acceptance: the flag could not clear the gate it exists
        // to clear.
        pre.deviceIdentityConfirmed = options.attestIdentityConfirmed;
        pre.authorizationReference = options.authorizationRef;
        pre.authorizedBy = options.authorizedBy;
        pre.authorizationBasis = options.authorizationBasis;
        return pre;
    }

    VerificationIndependence independenceFrom(const CliOptions& options) const {
        VerificationIndependence independence;
        if (options.attestIndependentVerification) {
            independence.level = VerificationIndependence::Level::INDEPENDENT;
            independence.performedBy = options.verifierName.empty()
                                           ? std::string("unnamed verifier")
                                           : options.verifierName;
            independence.notes =
                "Asserted by the operator. This tool cannot establish that "
                "verification was performed by a party independent of the "
                "sanitization.";
        } else {
            // Performed by this tool, in this session, about an operation this
            // tool just performed. That is self-verification, and the bundle
            // says so.
            independence.level = VerificationIndependence::Level::SELF;
            independence.performedBy = "ledgerase " + getVersion() + " (same session)";
            independence.notes =
                "Verification was produced by this tool in the same session as "
                "the sanitization. Independent verification requires a separate "
                "party or process and is not established here.";
        }
        return independence;
    }

    RetentionAttestation retentionFrom(const CliOptions& options) const {
        RetentionAttestation retention;
        if (options.retentionPolicy == "organization-defined") {
            retention.policy = RetentionAttestation::Policy::ORGANIZATION_DEFINED;
        } else if (options.retentionPolicy == "contractual") {
            retention.policy = RetentionAttestation::Policy::CONTRACTUAL;
        } else if (options.retentionPolicy == "legal-hold") {
            retention.policy = RetentionAttestation::Policy::LEGAL_HOLD;
        } else {
            retention.policy = RetentionAttestation::Policy::UNDEFINED;
        }
        retention.retainUntil = options.retainUntil;
        return retention;
    }

    // Builds the durable evidence bundle for one sanitization event.
    //
    // The event journal is built *after* the sections, and each record
    // references its section rather than copying it.
    //
    // The earlier arrangement put the whole decision, the whole verification
    // report and the whole validation into both the top-level sections and the
    // chain payloads. The `decision` object was byte-identical in both places,
    // 2473 bytes twice over, and the pre-execution and verification sections
    // overlapped the same way. That doubled the size of every bundle and meant
    // two copies could in principle disagree.
    //
    // A reference is safe to rely on: the record payload carries the SHA-256 of
    // the canonical section, and the record hash covers that digest. Editing a
    // section changes its digest, which changes the record hash, which breaks
    // the link to the next record. The chain still commits to every section, and
    // a reader that only walks the chain still learns each section's digest.
    Result<EvidenceBundle> buildEvidence(const AuditRecord& record,
                                         const CliOptions& options,
                                         const SafetyReport& safety) {
        EvidenceBundle bundle = EvidenceBuilder::build(
            record, record.verification, record.validation,
            scopeFrom(options, record.device),
            preExecutionFrom(options, safety), independenceFrom(options),
            retentionFrom(options))
            .valueOr(EvidenceBundle());

        // The sections the chain will point at, serialised once.
        const nlohmann::json serialised = bundle;
        nlohmann::json checks = nlohmann::json::array();
        for (const auto& check : safety.checks) {
            checks.push_back(check);
        }

        // section name -> (chain record type, compact summary)
        struct Link {
            const char* type;
            const char* section;
            nlohmann::json summary;
        };
        std::vector<Link> links = {
            {"media_identified", "media",
             {{"path", record.device.path},
              {"model", record.device.model},
              {"serial", record.device.serial},
              {"transport", transportToString(record.device.transport)}}},
            {"decision", "decision",
             {{"requested_category", record.plan.requestedCategory},
              {"selected_method", record.plan.selectedMethod},
              {"alternatives_considered",
               static_cast<std::size_t>(record.plan.alternativesConsidered.size())}}},
            {"pre_execution_verification", "pre_execution",
             {{"checks", static_cast<std::size_t>(checks.size())},
              {"device_identity_confirmed", options.attestIdentityConfirmed},
              {"authorization_reference", options.authorizationRef}}},
            {"execution", "execution",
             {{"state", record.execution.state},
              {"elapsed_seconds", record.execution.elapsedTime.count()},
              {"simulated", record.execution.simulated}}},
            {"verification", "verification",
             {{"result", record.verification.result},
              {"evidence_items",
               static_cast<std::size_t>(record.verification.evidence.size())},
              {"independence",
               verificationIndependenceToString(independenceFrom(options).level)}}},
            {"validation", "validation",
             {{"result", record.validation.result},
              {"accepted", record.validation.acceptedCriteria.size()},
              {"rejected", record.validation.rejectedCriteria.size()}}},
        };

        EvidenceJournal journal;
        for (const Link& link : links) {
            nlohmann::json payload = {
                {"section", link.section},
                {"summary", link.summary},
            };
            if (serialised.contains(link.section)) {
                const std::string canonical =
                    serialised.at(link.section).dump();
                const auto digest = sha256HexBytes(
                    reinterpret_cast<const uint8_t*>(canonical.data()),
                    canonical.size());
                if (digest.isError()) {
                    return Result<EvidenceBundle>::err(
                        digest.error());
                }
                payload["section_sha256"] = digest.value();
            }
            const auto appended =
                journal.append(link.type, record.jobId, std::move(payload));
            if (appended.isError()) {
                return Result<EvidenceBundle>::err(appended.error());
            }
        }

        bundle.eventChain = journal.records();
        bundle.chainLength = journal.count();
        bundle.chainHead = journal.head();

        // The chain is part of the signed content, so the hash must be computed
        // again now that it has been attached.
        auto hash = EvidenceBuilder::canonicalHash(bundle);
        if (hash.isError()) {
            return Result<EvidenceBundle>::err(hash.error());
        }
        bundle.canonicalHash = hash.value();

        return bundle;
    }


    void printEvidenceSummary(const EvidenceBundle& bundle,
                              const std::string& evidencePath) {
        std::cout << "\n=== EVIDENCE SUMMARY ===\n";
        std::cout << "Certificate:      " << bundle.certificateId << "\n";
        std::cout << "Standard:         " << bundle.standardName << " ("
                  << bundle.standardRole << ")\n";
        std::cout << "Category:         " << categoryToString(bundle.requestedCategory) << "\n";
        std::cout << "Method:           " << methodToString(bundle.selectedMethod) << "\n";
        std::cout << "Execution:        " << jobStateToString(bundle.execution.state)
                  << (bundle.simulated ? "  (SIMULATED)" : "") << "\n";
        std::cout << "Verification:     " << verificationToString(bundle.verification.result)
                  << " [" << verificationIndependenceToString(
                                 bundle.verificationIndependence.level) << "]\n";
        std::cout << "Validation:       " << validationToString(bundle.validation.result) << "\n";
        std::cout << "All copies:       "
                  << (bundle.scope.allCopiesAccountedFor ? "attested" : "NOT ATTESTED")
                  << "\n";
        std::cout << "Authorization:    "
                  << (bundle.preExecution.authorizationReference.empty()
                          ? "NOT RECORDED"
                          : bundle.preExecution.authorizationReference)
                  << "\n";
        std::cout << "Retention:        "
                  << retentionPolicyToString(bundle.retention.policy) << "\n";
        std::cout << "Residual data:    "
                  << (bundle.residualDataPossible ? "possible" : "not possible")
                  << "\n";
        std::cout << "Chain:            " << bundle.chainLength << " records, head "
                  << bundle.chainHead.substr(0, 16) << "...\n";
        std::cout << "Canonical hash:   " << bundle.canonicalHash << "\n";
        std::cout << "Signed:           "
                  << (bundle.signatures.empty() ? "no" : "yes") << "\n";

        // One grouped block, and only if the same run has not already printed
        // the list in full.
        if (!bundle.residualRiskLimitations.empty() &&
            !formatter.fullLimitationListPrinted()) {
            LimitationSet limitations;
            for (const std::string& limitation : bundle.residualRiskLimitations) {
                limitations.addText(limitation);
            }
            formatter.outputLimitations(limitations, evidencePath);
        }
    }

    // Locates the durable evidence bundle for a job and reads it.
    //
    // The bundle on disk is the tool's only system of record, so every command
    // that answers a question about a past job reads that file rather than an
    // in-memory structure. A job therefore survives the process, works across
    // sessions, and can be handed to a third party.
    //
    // The path is resolved in this order: an explicit --evidence, then the
    // directory this process writes to, then the default directory. A bundle
    // that will not verify is refused here, because a command that answers from
    // an altered document would be worse than not answering.
    Result<EvidenceBundle> loadBundle(const std::string& jobId,
                                      const std::string& explicitPath = {}) const {
        std::vector<std::string> candidates;
        if (!explicitPath.empty()) {
            candidates.push_back(explicitPath);
        } else {
            for (const std::string& directory :
                 {evidenceDirectory, defaultEvidenceDirectory()}) {
                candidates.push_back(
                    CliApplication::defaultEvidencePath(jobId, directory));
                candidates.push_back(legacyEvidencePath(jobId, directory));
            }
        }

        std::string firstMissing;
        for (const auto& path : candidates) {
            if (!std::filesystem::exists(path)) {
                if (firstMissing.empty()) firstMissing = path;
                continue;
            }
            return EvidenceWriter::read(path);
        }

        return Result<EvidenceBundle>::err(
            ErrorCode::DEVICE_NOT_FOUND,
            "No evidence bundle for job " + jobId + " (looked in: " +
                [&] {
                    std::string joined;
                    for (const auto& c : candidates) {
                        if (!joined.empty()) joined += ", ";
                        joined += c;
                    }
                    return joined;
                }() + ")",
            "Every sanitization writes a bundle. Use the path reported when the "
            "job ran, or pass --evidence <file> to point at it directly.");
    }

    // Every job this process produced, discovered by listing the evidence
    // directory rather than by remembering what happened in RAM.
    Result<std::vector<std::string>> listBundlePaths() const {
        std::vector<std::string> paths;
        const auto collect = [&paths](const std::filesystem::path& directory) {
            std::error_code ec;
            if (!std::filesystem::is_directory(directory, ec)) {
                return;
            }
            for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().extension() != ".json") continue;
                const std::string path = entry.path().string();
                if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
                    paths.push_back(path);
                }
            }
        };
        for (const auto& directory : {evidenceDirectory, defaultEvidenceDirectory()}) {
            collect(std::filesystem::path(directory) / kAuditSubdirectory);
            collect(directory);  // bundles from before the audit/ split
            if (!paths.empty()) break;
        }
        std::sort(paths.begin(), paths.end());
        return Result<std::vector<std::string>>::ok(paths);
    }

    DeviceManager deviceManager;
    CapabilityDetector capabilityDetector;
    SafetyManager safetyManager;
    SanitizationPolicyEngine policyEngine;
    SanitizationPlanner planner;
    SanitizationExecutor executor;
    VerificationEngine verificationEngine;
    ValidationEngine validationEngine;
    MockBackend mockBackend;
    OutputFormatter formatter;
    // Real devices by default. Simulation is opt-in via --simulation and, when
    // active, is announced on every command. Defaulting to true here would let
    // mock devices be presented as if they were real hardware, which CLAUDE.md
    // s41 forbids.
    // Where this process writes evidence bundles. Overridable so a GUI or a
    // test can direct output somewhere other than the working directory.
    std::string evidenceDirectory = defaultEvidenceDirectory();
    bool simulationMode = false;
    bool verbose = false;
};

CliApplication::CliApplication() : pImpl_(std::make_unique<Impl>()) {}
CliApplication::~CliApplication() = default;

void CliApplication::setSimulationMode(bool enabled) {
    pImpl_->simulationMode = enabled;
    pImpl_->mockBackend.setSimulationMode(enabled);

    // Route execution through the mock backend whenever simulation is on.
    // Without this, a plan built from a mock device would be handed to the real
    // methods, which open the device path for real. Mock and real devices share
    // paths such as /dev/nvme0n1, so this is the only thing standing between
    // --simulation and a live sanitize of the system disk.
    if (enabled) {
        auto* impl = pImpl_.get();
        pImpl_->executor.setMethodFactory(
            [impl](SanitizationMethod method,
                   const DeviceInfo& device,
                   const CapabilityInfo& capabilities,
                   const SanitizationPlan& plan) {
                return impl->mockBackend.createMethod(method, device, capabilities, plan);
            });
    } else {
        pImpl_->executor.setMethodFactory(nullptr);
    }
}

bool CliApplication::isSimulationMode() const {
    return pImpl_->simulationMode;
}

void CliApplication::setVerbose(bool enabled) {
    pImpl_->verbose = enabled;
    pImpl_->formatter.setVerbose(enabled);
}

const std::string& CliApplication::evidenceDirectory() const {
    return pImpl_->evidenceDirectory;
}

namespace {

// True when the locale can represent the UTF-8 glyphs used by the bar. When it
// cannot, the reporter falls back to ASCII.
bool isUtf8Locale() {
    for (const char* name : {"LC_ALL", "LC_CTYPE", "LANG"}) {
        const char* value = std::getenv(name);
        if (value == nullptr || value[0] == '\0') {
            continue;
        }
        const std::string text(value);
        if (text.find("UTF-8") != std::string::npos ||
            text.find("utf8") != std::string::npos ||
            text.find("UTF8") != std::string::npos) {
            return true;
        }
        // The first non-empty setting decides, per POSIX precedence.
        return false;
    }
    return false;
}

// Absolute-ises a path without requiring it to exist. std::filesystem::absolute
// does not resolve symlinks and does not require the path to be present, which
// is what is wanted here: the directory is created later, by the writer.
std::string makeAbsolute(const std::string& path) {
    if (path.empty()) {
        return path;
    }
    if (path.front() == '/') {
        return path;
    }
    std::error_code ec;
    const std::filesystem::path absolute = std::filesystem::absolute(path, ec);
    if (ec) {
        return path;
    }
    return absolute.lexically_normal().string();
}

bool directoryIsUsable(const std::filesystem::path& path) {
    // The directory need not exist yet: the writer creates it. So the test is
    // whether the nearest existing ancestor can be written to.
    std::filesystem::path probe = path;
    std::error_code ec;
    while (!probe.empty() && !std::filesystem::exists(probe, ec) &&
           probe.has_parent_path()) {
        probe = probe.parent_path();
    }
    if (ec) {
        return false;
    }
    return ::access(probe.c_str(), W_OK) == 0;
}

} // namespace

std::string defaultEvidenceDirectory() {
    // Both spellings are honoured, the new one first. The old name is kept
    // working rather than silently ignored: a deployment that set
    // SANITIZER_EVIDENCE_DIR, or that already has records under the old
    // default, would otherwise find its evidence directory had quietly moved
    // and its history appear to be gone. The rename changes where new records
    // go; it does not disown the ones already written.
    for (const char* name : {"LEDGERASE_EVIDENCE_DIR", "SANITIZER_EVIDENCE_DIR"}) {
        if (const char* override = std::getenv(name)) {
            if (override[0] != '\0') {
                return makeAbsolute(override);
            }
        }
    }

    // Each candidate location is tried under the new name first and the old
    // name second, so an existing directory keeps being used rather than being
    // shadowed by a newly created empty one beside it.
    if (::geteuid() == 0) {
        for (const char* dir : {"/var/lib/ledgerase/evidence",
                                "/var/lib/sanitizer/evidence"}) {
            const std::filesystem::path systemDir{dir};
            if (directoryIsUsable(systemDir)) {
                return systemDir.string();
            }
        }
    }

    if (const char* xdg = std::getenv("XDG_STATE_HOME")) {
        if (xdg[0] != '\0') {
            for (const char* leaf : {"ledgerase/evidence", "sanitizer/evidence"}) {
                const std::string candidate = makeAbsolute(std::string(xdg) + "/" + leaf);
                if (directoryIsUsable(candidate)) {
                    return candidate;
                }
            }
        }
    }

    if (const char* home = std::getenv("HOME")) {
        if (home[0] != '\0') {
            for (const char* leaf : {"ledgerase/evidence", "sanitizer/evidence"}) {
                const std::string candidate = makeAbsolute(
                    std::string(home) + "/.local/state/" + leaf);
                if (directoryIsUsable(candidate)) {
                    return candidate;
                }
            }
        }
    }

    // Nothing exists yet. The new name is used, and the directory is created on
    // first write. The help text says so.
    if (const char* home = std::getenv("HOME")) {
        if (home[0] != '\0') {
            return makeAbsolute(std::string(home) +
                                "/.local/state/ledgerase/evidence");
        }
    }

    // Nothing to anchor to. A relative path is the last resort and the help
    // text says so, so the location is never a silent surprise.
    return kDefaultEvidenceDirectory;
}

std::string CliApplication::defaultEvidencePath(const std::string& jobId,
                                                const std::string& directory) {
    return directory + "/" + kAuditSubdirectory + "/" + jobId + ".json";
}

std::string CliApplication::defaultReportPath(const std::string& jobId,
                                              const std::string& directory,
                                              const std::string& extension) {
    return directory + "/" + kReportsSubdirectory + "/" + jobId + "." + extension;
}

int CliApplication::run(int argc, char* argv[]) {
    // "--fetch EV-00129" is the shorthand for "evidence fetch EV-00129". It is
    // rewritten here rather than handled in a second parser, so both spellings
    // run the same implementation and cannot drift apart.
    std::vector<std::string> shorthand;
    std::vector<char*> shorthandPointers;
    if (argc >= 3 && std::string(argv[1]) == "--fetch") {
        shorthand.emplace_back(argv[0]);
        shorthand.emplace_back("evidence");
        shorthand.emplace_back("fetch");
        for (int i = 2; i < argc; ++i) {
            shorthand.emplace_back(argv[i]);
        }
        shorthandPointers.reserve(shorthand.size());
        for (std::string& argument : shorthand) {
            shorthandPointers.push_back(argument.data());
        }
        argc = static_cast<int>(shorthandPointers.size());
        argv = shorthandPointers.data();
    }

    if (argc < 2) {
        printUsage();
        return 1;
    }

    CliOptions options;
    options.command = argv[1];
    // Collected here rather than on the options struct, because the category
    // names are the carver's vocabulary and CliOptions is shared with every
    // other command.
    std::vector<FileCategory> carveCategories;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            showVersion(options);
            return 0;
        } else if (arg == "--dry-run") {
            options.dryRun = true;
        } else if (arg == "--verbose") {
            options.verbose = true;
            setVerbose(true);
        } else if (arg == "--verify" && i + 1 < argc) {
            options.verifyDepth = argv[++i];
            if (options.verifyDepth == "full") {
                // Recorded on the plan; the policy and verification layers read
                // it from there rather than from the option directly.
            } else if (options.verifyDepth != "sampled") {
                std::cout << "Unknown --verify depth: " << options.verifyDepth
                          << "\nValid depths: sampled, full\n"
                          << "  sampled  reads 64 sectors and reports the "
                             "percentage of the target that covered\n"
                          << "  full     reads every sector, which is a full read "
                             "of the medium\n";
                return 2;
            }
        } else if (arg == "--expect-serial" && i + 1 < argc) {
            options.expectSerial = argv[++i];
        } else if (arg == "--expect-name" && i + 1 < argc) {
            options.expectName = argv[++i];
        } else if (arg == "--no-progress") {
            options.noProgress = true;
        } else if (arg == "--json") {
            options.jsonOutput = true;
            pImpl_->formatter.setJsonOutput(true);
        } else if (arg == "--simulation") {
            options.simulationMode = true;
            setSimulationMode(true);
        } else if (arg == "--assurance" && i + 1 < argc) {
            options.assuranceExplicit = true;
            std::string val = argv[++i];
            if (val == "clear") options.assurance = SanitizationCategory::CLEAR;
            else if (val == "purge") options.assurance = SanitizationCategory::PURGE;
            else if (val == "destroy") options.assurance = SanitizationCategory::DESTROY;
            else {
                // An unrecognised value used to be ignored, leaving the
                // default of purge in place, so "--assurance cleer" ran a purge
                // and reported it as the one that was asked for. Every name is
                // accepted or rejected.
                std::cout << "Unknown --assurance: " << val
                          << "\nValid values: clear, purge, destroy.\n";
                return 2;
            }
        } else if (arg == "--security-categorization" && i + 1 < argc) {
            const std::string val = argv[++i];
            if (val == "low") {
                options.policyCategorization = SecurityCategorization::LOW;
            } else if (val == "moderate" || val == "medium") {
                options.policyCategorization = SecurityCategorization::MODERATE;
            } else if (val == "high") {
                options.policyCategorization = SecurityCategorization::HIGH;
            } else {
                std::cout << "Unknown --security-categorization: " << val
                          << "\nValid values: low, moderate, high.\n"
                             "This is a local policy input, not a NIST SP 800-88\n"
                             "Rev. 2 requirement. Supplying all three of this,\n"
                             "--reuse-media and --leaving-org-control derives the\n"
                             "assurance level from this project's documented policy.\n";
                return 2;
            }
        } else if (arg == "--reuse-media" && i + 1 < argc) {
            const std::string val = argv[++i];
            if (val == "yes" || val == "true" || val == "1") {
                options.policyReuseMedia = TriState::YES;
            } else if (val == "no" || val == "false" || val == "0") {
                options.policyReuseMedia = TriState::NO;
            } else {
                std::cout << "Unknown --reuse-media: " << val
                          << "\nValid values: yes, no. 'no' is not the same as "
                             "omitting the flag: omitting it means the policy\n"
                             "cannot decide, and the flag is required before a "
                             "tier is derived.\n";
                return 2;
            }
        } else if (arg == "--leaving-org-control" && i + 1 < argc) {
            const std::string val = argv[++i];
            if (val == "yes" || val == "true" || val == "1") {
                options.policyLeavingOrgControl = TriState::YES;
            } else if (val == "no" || val == "false" || val == "0") {
                options.policyLeavingOrgControl = TriState::NO;
            } else {
                std::cout << "Unknown --leaving-org-control: " << val
                          << "\nValid values: yes, no. 'no' is not the same as "
                             "omitting the flag: omitting it means the policy\n"
                             "cannot decide, and the flag is required before a "
                             "tier is derived.\n";
                return 2;
            }
        } else if (arg == "--method" && i + 1 < argc) {
            const std::string val = argv[++i];
            // Every name is accepted or rejected. The previous parser mapped
            // "overwrite" to the *NVMe* overwrite, which is the opposite of what
            // an operator typing that word means, and left an unrecognised name
            // as NONE - so "--method nvme-crypto-eraze" ran a job with a
            // different method and reported success.
            if (val == "overwrite" || val == "host-overwrite") {
                options.method = SanitizationMethod::OVERWRITE_HOST;
            } else if (val == "nvme-overwrite") {
                options.method = SanitizationMethod::NVME_OVERWRITE;
            } else if (val == "crypto-erase" || val == "nvme-crypto-erase") {
                options.method = SanitizationMethod::NVME_CRYPTO_ERASE;
            } else if (val == "block-erase" || val == "nvme-block-erase") {
                options.method = SanitizationMethod::NVME_BLOCK_ERASE;
            } else if (val == "secure-erase" || val == "ata-secure-erase") {
                options.method = SanitizationMethod::ATA_SECURE_ERASE;
            } else if (val == "enhanced-secure-erase" ||
                       val == "ata-enhanced-secure-erase") {
                options.method = SanitizationMethod::ATA_ENHANCED_SECURE_ERASE;
            } else if (val == "ata-sanitize-block-erase") {
                options.method = SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE;
            } else if (val == "ata-sanitize-crypto-erase") {
                options.method = SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE;
            } else if (val == "ata-sanitize-overwrite") {
                options.method = SanitizationMethod::ATA_SANITIZE_OVERWRITE;
            } else {
                std::cout << "Unknown --method: " << val << "\n"
                          << "Valid names: overwrite, host-overwrite, "
                             "nvme-overwrite,\n"
                             "             crypto-erase, nvme-crypto-erase, "
                             "block-erase, nvme-block-erase,\n"
                             "             secure-erase, ata-secure-erase, "
                             "enhanced-secure-erase,\n"
                             "             ata-enhanced-secure-erase, "
                             "ata-sanitize-block-erase,\n"
                             "             ata-sanitize-crypto-erase, "
                             "ata-sanitize-overwrite\n";
                return 2;
            }
        } else if (arg == "--format" && i + 1 < argc) {
            const std::string val = argv[++i];
            if (val != "text" && val != "json" && val != "pdf") {
                std::cout << "Unknown --format: " << val << "\n"
                          << "Valid formats: text, json, pdf.\n"
                          << "--format applies to 'report'. Other commands take "
                             "--json, and\nignore it. An unrecognised value is "
                             "refused, not treated as text.\n";
                return 2;
            }
            options.outputFormat = val;
        } else if (arg == "--output" && i + 1 < argc) {
            options.outputFile = argv[++i];
        } else if (arg == "--output-dir" && i + 1 < argc) {
            options.outputDirectory = argv[++i];
        } else if (arg == "--chunk-size" && i + 1 < argc) {
            // carve only. Parsed and range-checked rather than assigned
            // blindly: a chunk below the scanner's floor is silently raised, and
            // an operator who set 512 KiB should be told it became 1 MiB.
            const std::string val = argv[++i];
            char* end = nullptr;
            const long long parsed = std::strtoll(val.c_str(), &end, 10);
            if (end == val.c_str() || *end != '\0' || parsed < 1048576 ||
                parsed > 1073741824LL) {
                std::cout << "Unknown --chunk-size: " << val << "\n"
                          << "Valid values: 1048576 to 1073741824 bytes "
                             "(1 MiB to 1 GiB).\n"
                          << "Anything smaller is raised to 1 MiB by the scanner, "
                             "so a value\n"
                          << "below the floor would not do what it says.\n";
                return 2;
            }
            options.chunkSizeBytes = static_cast<size_t>(parsed);
        } else if (arg == "--max-recovered-bytes" && i + 1 < argc) {
            // carve only. The cap is applied after every candidate's length is
            // known, so it bounds what is written rather than what is found.
            const std::string val = argv[++i];
            char* end = nullptr;
            const long long parsed = std::strtoll(val.c_str(), &end, 10);
            if (end == val.c_str() || *end != '\0' || parsed < 0) {
                std::cout << "Unknown --max-recovered-bytes: " << val << "\n"
                          << "A non-negative byte count is required.\n";
                return 2;
            }
            options.maxRecoveredBytes = static_cast<uint64_t>(parsed);
        } else if (arg == "--passes" && i + 1 < argc) {
        const std::string val = argv[++i];
        char* end = nullptr;
        const long long parsed = std::strtoll(val.c_str(), &end, 10);
        if (end == val.c_str() || *end != '\0' || parsed < 1 || parsed > 15) {
            std::cout << "Unknown --passes: " << val << "\n"
                      << "Valid values: 1 to 15.\n"
                      << "1 is this tool's default. NIST SP 800-88 Rev. 2 sets no\n"
                      << "pass count: it records that multi-pass overwrite was once\n"
                      << "common and that on SSDs with overprovisioning it 'should be\n"
                      << "avoided', and leaves technique choice to IEEE 2883. More\n"
                      << "passes are performed if asked for, and both the requested and\n"
                      << "the completed count are recorded.\n";
            return 2;
        }
        options.erasePasses = static_cast<uint32_t>(parsed);
    } else if (arg == "--probes" && i + 1 < argc) {
        const std::string val = argv[++i];
        char* end = nullptr;
        const long long parsed = std::strtoll(val.c_str(), &end, 10);
        if (end == val.c_str() || *end != '\0' || parsed < 1 || parsed > 64) {
            std::cout << "Unknown --probes: " << val << "\n"
                      << "Valid values: 1 to 64. Each probe is a 512-byte chunk "
                         "of the file's\nown content, taken before the erase and "
                         "searched for afterwards.\n"
                      << "Zero probes would mean no content check at all, which is "
                         "why it is\nrefused rather than treated as a default.\n";
            return 2;
        }
        options.probeCount = static_cast<size_t>(parsed);
    } else if (arg == "--search-limit" && i + 1 < argc) {
        // 0 means the whole medium, which is the default and the only setting
        // that can find a relocated copy. The flag exists so the check can be
        // bounded on a slow medium, and a bounded search says so in its result.
        const std::string val = argv[++i];
        char* end = nullptr;
        const long long parsed = std::strtoll(val.c_str(), &end, 10);
        if (end == val.c_str() || *end != '\0' || parsed < 0) {
            std::cout << "Unknown --search-limit: " << val
                      << "\nA non-negative byte count is required; 0 means the "
                         "whole medium.\n";
            return 2;
        }
        options.searchLimitBytes = static_cast<uint64_t>(parsed);
    } else if (arg == "--erase-method" && i + 1 < argc) {
        // The shared EraseMethod enum, not a file-only flag, and deliberately
        // not --method: that already names a device *sanitization* method
        // (nvme-crypto-erase and so on), and reusing it for a file's overwrite
        // technique would put two different vocabularies behind one name.
        const std::string val = argv[++i];
        if (val != "zero" && val != "zero-fill" && val != "random" &&
            val != "rand") {
            std::cout << "Unknown --erase-method: " << val
                      << "\nValid values: zero, random. 'zero' writes 0x00 over "
                         "every byte (what the device\neraser does). 'random' "
                         "writes a deterministic stream derived from the file's "
                         "size\nand the pass number, so it is reproducible.\n";
            return 2;
        }
        options.eraseMethod = val;
    } else if (arg == "--residual-search-target" && i + 1 < argc) {
        options.residualSearchTarget = argv[++i];
    } else if (arg == "--no-residual-search") {
        // Engaged, not merely accepted. Skipping the only step that reports
        // what is actually still on the medium is a real loss of assurance, so
        // it prints a warning and records the skip and the reason in the
        // evidence rather than passing silently.
        options.noResidualSearch = true;
    } else if (arg == "--residual-search-skip-reason" && i + 1 < argc) {
        options.residualSearchSkipReason = argv[++i];
    } else if (arg == "--recursive" || arg == "-r") {
        options.recursive = true;
    } else if (arg == "--follow-symlinks") {
        options.followSymlinks = true;
    } else if (arg == "--include" && i + 1 < argc) {
        options.includePatterns.push_back(argv[++i]);
    } else if (arg == "--exclude" && i + 1 < argc) {
        options.excludePatterns.push_back(argv[++i]);
    } else if (arg == "--minimum-score" && i + 1 < argc) {
            const std::string val = argv[++i];
            char* end = nullptr;
            const double parsed = std::strtod(val.c_str(), &end);
            if (end == val.c_str() || *end != '\0' || parsed < 0.0 || parsed > 1.0) {
                std::cout << "Unknown --minimum-score: " << val << "\n"
                          << "Valid values: 0.0 to 1.0.\n"
                          << "Candidates scoring below the threshold are still "
                             "counted in the header\n"
                          << "match total, and are reported as not written rather "
                             "than dropped\n"
                          << "silently.\n";
                return 2;
            }
            options.minimumScore = parsed;
        } else if (arg == "--evidence" && i + 1 < argc) {
            options.evidenceFile = argv[++i];
        } else if (arg == "--authorization" && i + 1 < argc) {
            options.authorizationRef = argv[++i];
        } else if (arg == "--authorized-by" && i + 1 < argc) {
            options.authorizedBy = argv[++i];
        } else if (arg == "--authorization-basis" && i + 1 < argc) {
            options.authorizationBasis = argv[++i];
        } else if (arg == "--scope-note" && i + 1 < argc) {
            options.scopeRationale = argv[++i];
        } else if (arg == "--copies-not-addressed" && i + 1 < argc) {
            options.copiesNotAddressed = argv[++i];
        } else if (arg == "--verifier" && i + 1 < argc) {
            options.verifierName = argv[++i];
        } else if (arg == "--public-key" && i + 1 < argc) {
            options.publicKeyFile = argv[++i];
        } else if (arg == "--sign" && i + 1 < argc) {
            options.privateKeyFile = argv[++i];
        } else if (arg == "--retention" && i + 1 < argc) {
            options.retentionPolicy = argv[++i];
        } else if (arg == "--retain-until" && i + 1 < argc) {
            options.retainUntil = argv[++i];
        } else if (arg == "--all-copies") {
            // An explicit operator assertion. Never inferred.
            options.attestAllCopies = true;
        } else if (arg == "--independent-verification") {
            options.attestIndependentVerification = true;
        } else if (arg == "--identity-confirmed") {
            options.attestIdentityConfirmed = true;
        } else if (arg == "--overwrite-passes" && i + 1 < argc) {
            const std::string val = argv[++i];
            char* end = nullptr;
            const long parsed = std::strtol(val.c_str(), &end, 10);
            if (end == val.c_str() || *end != '\0' || parsed < 1 || parsed > 15) {
                pImpl_->formatter.outputError(SanitizerError(
                    ErrorCode::INVALID_ARGUMENT,
                    "--overwrite-passes must be an integer between 1 and 15, got: " + val,
                    "The NVMe OWPASS field is 4 bits, so a controller can only be "
                    "instructed to perform 1 to 15 overwrite passes"));
                return 1;
            }
            options.overwritePassCount = static_cast<uint8_t>(parsed);
        } else if (arg == "--force") {
            options.force = true;
        } else if (arg == "--images" && i + 1 < argc) {
            options.imagesDirectory = argv[++i];
        } else if (arg == "--apply") {
            options.applyMigrate = true;
        } else if (arg == "--description" && i + 1 < argc) {
            options.description = argv[++i];
        } else if (arg == "--db" && i + 1 < argc) {
            options.databasePath = argv[++i];
        } else if (arg == "--query" && i + 1 < argc) {
            options.query = argv[++i];
        } else if (arg == "--operation" && i + 1 < argc) {
            options.searchOperation = argv[++i];
        } else if (arg == "--status" && i + 1 < argc) {
            options.searchStatus = argv[++i];
        } else if (arg == "--target-type" && i + 1 < argc) {
            options.searchTargetType = argv[++i];
        } else if (arg == "--model" && i + 1 < argc) {
            options.searchModel = argv[++i];
        } else if (arg == "--date" && i + 1 < argc) {
            options.searchDate = argv[++i];
        } else if (arg == "--from" && i + 1 < argc) {
            options.searchFrom = argv[++i];
        } else if (arg == "--to" && i + 1 < argc) {
            options.searchTo = argv[++i];
        } else if (arg == "--sort" && i + 1 < argc) {
            const std::string val = argv[++i];
            if (val != "date-asc" && val != "date-desc") {
                std::cout << "Unknown --sort: " << val
                          << "\nValid values: date-asc, date-desc.\n";
                return 2;
            }
            options.sortOrder = val;
        } else if ((arg == "--page" || arg == "--limit" || arg == "--select") &&
                   i + 1 < argc) {
            const std::string val = argv[++i];
            char* end = nullptr;
            const long parsed = std::strtol(val.c_str(), &end, 10);
            if (end == val.c_str() || *end != '\0' || parsed < 0) {
                std::cout << "Unknown " << arg << ": " << val
                          << "\nA non-negative integer is required.\n";
                return 2;
            }
            if (arg == "--page") {
                options.page = parsed < 1 ? 1 : static_cast<int>(parsed);
            } else if (arg == "--limit") {
                options.pageSize = parsed < 1 ? 10 : static_cast<int>(parsed);
            } else {
                options.selectionIndex = static_cast<int>(parsed);
            }
        } else if (arg == "--no-interactive") {
            options.noInteractive = true;
        } else if (arg[0] != '-') {
            const bool wantsJob = commandTakesJobId(options.command);
            if (options.command == "evidence") {
                options.evidenceArgs.push_back(arg);
                if (options.jobId.empty()) {
                    options.jobId = arg;
                }
                if (options.evidenceArgs.size() == 2 &&
                    options.evidenceArgs.front() == "migrate") {
                    options.migrateDirectory = arg;
                }
            } else if (wantsJob) {
                if (options.jobId.empty()) {
                    options.jobId = arg;
                }
            } else if (options.devicePath.empty()) {
                options.devicePath = arg;
            } else if (options.jobId.empty()) {
                options.jobId = arg;
            }
        }
    }

    if (options.verbose) setVerbose(true);

    Result<void> result;

    // With the volatile log removed there is no record of what was asked for, so
    // the invocation is echoed in verbose mode instead of being discarded.
    if (pImpl_->verbose) {
        std::cerr << "[ledgerase] " << describeOptions(options) << "\n";
    }


    // Announce the mode on every command that acts on a sanitization target, so
    // output can never be mistaken for something it is not.
    //
    // Two things had to be right here. The banner is keyed on "does this command
    // take a target", not on "was a path given" - `verify-log <file>` takes a
    // path too, and announcing a disk image would be nonsense. And the real-mode
    // banner is keyed on "is this a real sanitizable target", not on "does the
    // path start with /dev/": a disk image IS destructively overwritten, and
    // under the old test it produced no banner at all, so the one case that is
    // neither hardware nor a simulation was the quietest.
    if (commandTakesTarget(options.command)) {
        if (pImpl_->simulationMode) {
            std::cout << "*** SIMULATION MODE - MOCK DEVICES, NO REAL TARGET IS TOUCHED ***\n";
        } else if (!options.devicePath.empty()) {
            if (DeviceManager::isDiskImage(options.devicePath)) {
                std::cout << "*** REAL DISK IMAGE MODE - " << options.devicePath
                          << " WILL BE OVERWRITTEN IN PLACE ***\n";
                std::cout << "    This is a file, not a block device. The file's contents "
                             "will be destroyed;\n"
                             "    the filesystem it may contain will not be.\n";
            } else if (DeviceManager::isBlockDevice(options.devicePath)) {
                std::cout << "*** REAL DEVICE MODE - DESTRUCTIVE ACTIONS POSSIBLE ON "
                          << options.devicePath << " ***\n";
            }
        }
    }

    if (options.command == "list-devices") {
        result = listDevices(options);
    } else if (options.command == "inspect") {
        result = inspectDevice(options);
    } else if (options.command == "capabilities") {
        result = showCapabilities(options);
    } else if (options.command == "plan") {
        result = createPlan(options);
    } else if (options.command == "sanitize") {
        result = sanitize(options);
    } else if (options.command == "verify") {
        result = verifyJob(options);
    } else if (options.command == "validate") {
        result = validateJob(options);
    } else if (options.command == "recover-test") {
        result = recoverTest(options);
    } else if (options.command == "report") {
        result = showReport(options);
    } else if (options.command == "carve") {
        result = carve(options);
    } else if (options.command == "erase-file" ||
               options.command == "erase-folder") {
        result = eraseFileOrFolder(options);
    } else if (options.command == "audit") {
        result = showAudit(options);
    } else if (options.command == "evidence") {
        result = manageEvidence(options);
    } else if (options.command == "verify-log") {
        result = verifyEvidenceFile(options);
    } else if (options.command == "shell") {
        return runShell();
    } else if (options.command == "version") {
        result = showVersion(options);
    } else if (options.command == "ret-log" || options.command == "give-log") {
        // Named explicitly rather than falling through to "unknown command",
        // because these commands existed and an operator who has scripted
        // around them needs to be told what happened to them.
        pImpl_->formatter.outputError(SanitizerError(
            ErrorCode::UNSUPPORTED_OPERATION,
            "'" + options.command + "' has been removed",
            "The volatile operational log is gone. Every job now writes a durable, "
            "hash-chained evidence bundle and that is the only record. Use "
            "'evidence <job-id>' to read one, 'audit' to list them, and "
            "'verify-log <file>' to check one."));
        printUsage();
        return 1;
    } else {
        pImpl_->formatter.outputMessage("Unknown command: " + options.command);
        printUsage();
        return 1;
    }

    if (result.isError()) {
        pImpl_->formatter.outputError(result.error());
        return 1;
    }

    // Nothing is held in memory at this point. Any job that ran wrote its
    // evidence bundle to disk as part of the sanitize command, before it
    // reported success or failure.
    return 0;
}

void CliApplication::printUsage() {
    std::cout << "Ledgerase - Storage Media Sanitization Platform\n\n";
    std::cout << "Usage: ledgerase-cli <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  list-devices              List all detected storage devices\n";
    std::cout << "  inspect <device>          Show detailed device information\n";
    std::cout << "  capabilities <device>     Show device sanitization capabilities\n";
    std::cout << "  plan <device>             Generate sanitization plan (dry-run)\n";
    std::cout << "  sanitize <device>         Execute sanitization\n";
    std::cout << "  verify <job-id>           Verification for a job, from its evidence\n";
    std::cout << "  validate <job-id>         The validation decision recorded for a job\n";
    std::cout << "  recover-test <job-id>     NOT IMPLEMENTED\n";
    std::cout << "  report <job-id>           Certificate/report in text, JSON or PDF\n";
    std::cout << "  erase-file <path>         Erase one file's content in place, under the\n";
    std::cout << "                            filesystem capability matrix. Refuses on a\n";
    std::cout << "                            filesystem whose row does not permit it.\n";
    std::cout << "  erase-folder <path>       Erase each regular file in a directory.\n";
    std::cout << "                            Symlinks, subdirectories, devices, FIFOs and\n";
    std::cout << "                            sockets are listed and not erased.\n";
    std::cout << "  carve <source>            Module 3: recover files from an image or\n";
    std::cout << "                            device, read-only, by signature carving\n";
    std::cout << "  audit [job-id]            List the evidence records, or show one\n";
    std::cout << "  evidence <job-id>         Show the evidence bundle for a job\n";
    std::cout << "  evidence migrate <dir>    Move bundles written before audit/ and\n";
    std::cout << "                            reports/ were separated into <dir>/audit/.\n";
    std::cout << "                            A dry run unless --apply is given. The\n";
    std::cout << "                            file is moved, never re-written, so the\n";
    std::cout << "                            bytes and the hash are unchanged.\n";
    std::cout << "  evidence list             List the latest indexed evidence records\n";
    std::cout << "  evidence search           Search evidence by description, operation,\n";
    std::cout << "                            target, status, date or job ID\n";
    std::cout << "  evidence show <id>        Show one evidence record and its artifacts\n";
    std::cout << "  evidence verify <id>      Verify the artifacts' SHA-256, bundle hash\n";
    std::cout << "                            and chain (and signature with --public-key)\n";
    std::cout << "  evidence fetch <id>       Verify, then copy the evidence files to an\n";
    std::cout << "                            output directory. Also: --fetch <id>\n";
    std::cout << "  evidence describe <id>    Set a searchable description; recorded as\n";
    std::cout << "                            an annotation, never an edit of the bundle\n";
    std::cout << "  evidence db init|status   Create the index, or show its state\n";
    std::cout << "  evidence backup [dir]     Copy the database and every artifact it\n";
    std::cout << "                            references, with hashes checked\n";
    std::cout << "  evidence restore <dir>    Install a verified backup database\n";
    std::cout << "  evidence check            Compare the index with the evidence store\n";
    std::cout << "  verify-log <file>         Verify an evidence file (hash, chain, signature)\n";
    std::cout << "  shell                     Interactive session\n";
    std::cout << "  version                   Show version information\n\n";
    std::cout << "Options:\n";
    std::cout << "  --dry-run                 Generate plan only, no destructive actions\n";
    std::cout << "  --assurance <level>       Assurance level: clear, purge, destroy (default: purge).\n"
                 "                            An explicit --assurance overrides the local policy\n"
                 "                            below.\n";
    std::cout << "  --security-categorization <low|moderate|high>\n"
                 "  --reuse-media <yes|no>\n"
                 "  --leaving-org-control <yes|no>\n"
                 "                            Derive the assurance level from this project's\n"
                 "                            documented local policy. All three are required;\n"
                 "                            partial input derives nothing and says so. 'no' is\n"
                 "                            not the same as omitting a flag.\n"
                 "                            This is NOT a NIST SP 800-88 Rev. 2 mechanism.\n"
                 "                            Rev. 2 defines clear, purge and destroy and\n"
                 "                            requires a risk-based decision (4.3.6) without\n"
                 "                            specifying how to reach it. The mapping below is\n"
                 "                            the organisation's own policy, and every record\n"
                 "                            says so. See docs/STANDARDS.md.\n";
    std::cout << "  --method <method>         Request a specific method. Refused unless the\n";
    std::cout << "                            device reports it supported and it is\n";
    std::cout << "                            permitted for the requested category.\n";
    std::cout << "  --overwrite-passes <n>    Overwrite passes to request, 1-15 (default: 1)\n";
    std::cout << "  --simulation              Use mock devices (safe for testing)\n";
    std::cout << "  --json                    Output in JSON format\n";
    std::cout << "  --verbose                 Verbose output\n";
    std::cout << "  --format <fmt>            Output format: text, json, pdf\n";
    std::cout << "  --output <file>           Write output to file (report destination)\n";
    std::cout << "  --evidence <file>         Where this job's evidence bundle is written,\n";
    std::cout << "                            or the bundle to read. Overrides the default\n";
    std::cout << "                            path; it does not decide whether one is written.\n";
    std::cout << "  --authorization <ref>     Authorization reference, e.g. a change ticket\n";
    std::cout << "  --authorized-by <name>    Who authorized the sanitization\n";
    std::cout << "  --authorization-basis <s> Organizational policy, contract, or order\n";
    std::cout << "  --all-copies              Attest that every copy of the data is covered\n";
    std::cout << "  --scope-note <text>       Why the scope is or is not complete\n";
    std::cout << "  --copies-not-addressed <t> Copies deliberately left out of scope\n";
    std::cout << "  --identity-confirmed      Attest the device identity was checked\n";
    std::cout << "  --independent-verification  Verification was done by another party\n";
    std::cout << "  --verifier <name>         Who performed the verification\n";
    std::cout << "  --retention <policy>      organization-defined | contractual | legal-hold\n";
    std::cout << "  --retain-until <text>     Retention end\n";
    std::cout << "  --sign <key.pem>          Sign the evidence bundle (Ed25519)\n";
    std::cout << "  --public-key <pub.pem>    Public key used by verify-log\n";
    std::cout << "  --force                   Bypass safety checks (DANGEROUS); also lets an\n";
    std::cout << "                            evidence file be overwritten\n";
    std::cout << "  --output-dir <dir>        carve only: where to write recovered\n";
    std::cout << "                            files. Omit it and only a report is made.\n";
    std::cout << "                            Refused when the directory is on the same\n";
    std::cout << "                            filesystem or device as the source.\n";
    std::cout << "  --images <dir>            list-devices only: also list the regular\n";
    std::cout << "                            files in this directory as disk images,\n";
    std::cout << "                            with their real size. Plain list-devices\n";
    std::cout << "                            lists only the devices the kernel knows.\n";
    std::cout << "  --apply                  evidence migrate only: perform the move.\n";
    std::cout << "                            Without it the command is a dry run and\n";
    std::cout << "                            changes nothing.\n";
    std::cout << "  --db <path>              Evidence index location. Defaults to\n";
    std::cout << "                            $LEDGERASE_DB, then\n";
    std::cout << "                            $XDG_STATE_HOME/ledgerase/ledgerase.db.\n";
    std::cout << "  --description <text>     Optional, searchable description of why the\n";
    std::cout << "                            evidence was created.\n";
    std::cout << "  --query <text>           evidence search: match description, ID,\n";
    std::cout << "                            operation, target, model or job ID.\n";
    std::cout << "  --operation <name>       evidence search: drive-erasure,\n";
    std::cout << "                            file-erasure, folder-erasure or carving.\n";
    std::cout << "  --status <status>        evidence search: SUCCESS or FAILED.\n";
    std::cout << "  --model <text>           evidence search: device model.\n";
    std::cout << "  --date <YYYY-MM-DD>      evidence search: one day.\n";
    std::cout << "  --from <YYYY-MM-DD>      evidence search: earliest day.\n";
    std::cout << "  --to <YYYY-MM-DD>        evidence search: latest day.\n";
    std::cout << "  --page <n>               evidence list/search: page number (default 1)\n";
    std::cout << "  --limit <n>              evidence list/search: records per page\n";
    std::cout << "                            (default 10)\n";
    std::cout << "  --sort <date-asc|date-desc>  evidence list/search ordering\n";
    std::cout << "  --select <n>             choose the nth search result non-interactively\n";
    std::cout << "  --no-interactive         never prompt for a selection\n";
    std::cout << "  --recursive, -r          erase-folder: descend into subdirectories.\n"
                 "                            Off by default: a recursive run can reach\n"
                 "                            files the operator did not enumerate.\n";
    std::cout << "  --follow-symlinks        erase-folder: follow a symlink whose target\n"
                 "                            resolves outside the folder. Off by\n"
                 "                            default; such a link is reported, not\n"
                 "                            followed. Widens scope - ask for it.\n";
    std::cout << "  --include <glob>         erase-folder: only entries matching this\n"
                 "  --exclude <glob>         pattern, and never one matching an\n"
                 "                            --exclude. Matched on the base name and\n"
                 "                            on the path under the folder. '*' does\n"
                 "                            not cross '/'; '**' does. Repeatable.\n";
    std::cout << "  --dry-run                erase-folder: list every file that would be\n"
                 "                            touched, then stop. Opens nothing for\n"
                 "                            writing, takes no probe, removes nothing,\n"
                 "                            and writes no evidence.\n";
    std::cout << "  --passes <n>             erase-file/erase-folder: overwrite passes,\n";
    std::cout << "                            1 to 15 (default 1). Requested and completed\n";
    std::cout << "                            counts are recorded separately, so a run that\n";
    std::cout << "                            stopped part-way is visible as such.\n";
    std::cout << "  --probes <n>             erase only: content chunks taken before the\n";
    std::cout << "                            erase and searched for on the medium after it,\n";
    std::cout << "                            1 to 64 (default 6). Zero is refused: it would\n";
    std::cout << "                            mean no content check at all.\n";
    std::cout << "  --search-limit <bytes>   erase only: bound the residual search. 0 (the\n";
    std::cout << "                            default) searches the whole medium, which is the\n";
    std::cout << "                            only setting that finds a relocated copy.\n";
    std::cout << "  --serial-suffix <n>      Confirm a block device by its last n serial\n";
    std::cout << "                            characters, 4 to 64 (default 6).\n";
    std::cout << "  --category <name>        carve only: only consider image, document,\n";
    std::cout << "                            archive, audio-video, executable, database, text\n";
    std::cout << "                            or unknown. May be given more than once.\n";
    std::cout << "  --chunk-size <bytes>      carve only: scan buffer, 1 MiB to 1 GiB.\n";
    std::cout << "                            Peak memory is chunk + overlap.\n";
    std::cout << "  --max-recovered-bytes    carve only: cap on the total written.\n";
    std::cout << "  --minimum-score <0..1>    carve only: ignore candidates scoring below\n";
    std::cout << "                            this. Applied after the scan, so nothing is\n";
    std::cout << "                            hidden from the candidate count.\n";
    std::cout << "  --verify <depth>         Read-back depth: sampled (default, 64\n";
    std::cout << "                            sectors) or full (every sector, a full\n";
    std::cout << "                            read of the medium). The coverage is\n";
    std::cout << "                            reported either way.\n";
    std::cout << "  --expect-serial <text>   Confirm a block device without a prompt,\n";
    std::cout << "                            by its full serial. For scripts.\n";
    std::cout << "  --expect-name <text>     Confirm a file or image without a prompt,\n";
    std::cout << "                            by its file name. For scripts. A file has no\n";
    std::cout << "                            serial, so its name is what is confirmed.\n";
    std::cout << "  --no-progress            Do not draw the progress bar. The bar is also\n";
    std::cout << "                            suppressed when stdout is not a terminal or\n";
    std::cout << "                            when --json is given.\n";
    std::cout << "  --help, -h                Show this help\n";
    std::cout << "  --version, -v             Show version\n\n";
    std::cout << "Evidence:\n";
    std::cout << "  Every sanitization writes exactly one evidence bundle. It is durable,\n";
    std::cout << "  hash-chained, and third-party verifiable. The default path is\n";
    std::cout << "  " << defaultEvidenceDirectory() << "/audit/<job-id>.json,\n";
    std::cout << "  which is absolute. It resolves, in order, from\n";
    std::cout << "  $LEDGERASE_EVIDENCE_DIR,\n";
    std::cout << "  /var/lib/ledgerase/evidence as root,\n";
    std::cout << "  $XDG_STATE_HOME/ledgerase/evidence,\n";
    std::cout << "  ~/.local/state/ledgerase/evidence,\n";
    std::cout << "  and only then ./evidence.\n";
    std::cout << "  $SANITIZER_EVIDENCE_DIR and the older .../sanitizer/evidence\n";
    std::cout << "  directories are still honoured, and are tried after the ledgerase\n";
    std::cout << "  ones, so renaming the tool does not strand an existing record set.\n";
    std::cout << "  --evidence changes where it is written, never whether. It cannot be\n";
    std::cout << "  suppressed.\n";
    std::cout << "  Read one with 'evidence <job-id>', list them with 'audit', and check\n";
    std::cout << "  any file with 'verify-log <file>'.\n";
    std::cout << "  There is no other log. An earlier version kept one in RAM behind\n";
    std::cout << "  'ret-log' and 'give-log'; both were removed because a record that\n";
    std::cout << "  disappears with the process is not an audit trail.\n";
    std::cout << "  Bundles are kept in audit/ and rendered reports in reports/ (a PDF\n";
    std::cout << "  report with no --output goes to reports/<job-id>.pdf). A report is\n";
    std::cout << "  made from a bundle and states its hash; only audit/ is a record.\n";
    std::cout << "  Bundles written before this split, directly in the directory, are\n";
    std::cout << "  still found.\n";
    std::cout << "  Limitations:\n";
    std::cout << "  Every limitation has a stable ID and one sentence. The terminal shows\n";
    std::cout << "  them grouped under four headings; the evidence file holds the full\n";
    std::cout << "  deduplicated list with IDs. --verbose prints the full list here.\n";
    std::cout << "  Attestations (--all-copies, --authorization, --identity-confirmed,\n";
    std::cout << "  --independent-verification, --retention) are operator assertions.\n";
    std::cout << "  Omitting one lowers the recorded outcome; it is never assumed.\n\n";
    std::cout << "Examples:\n";
    std::cout << "  ledgerase-cli list-devices\n";
    std::cout << "  ledgerase-cli inspect /dev/nvme0n1\n";
    std::cout << "  ledgerase-cli capabilities /dev/nvme0n1\n";
    std::cout << "  ledgerase-cli plan /dev/nvme0n1 --assurance purge\n";
    std::cout << "  ledgerase-cli sanitize /dev/nvme0n1 --dry-run\n";
    std::cout << "  ledgerase-cli sanitize /dev/nvme0n1 --method host-overwrite\n";
    std::cout << "  ledgerase-cli sanitize /dev/sdX --assurance clear --no-progress\n";
    std::cout << "  ledgerase-cli carve ./evidence-target.img --output-dir ./recovered\n";
    std::cout << "  ledgerase-cli audit\n";
    std::cout << "  ledgerase-cli evidence JOB-ID\n";
    std::cout << "  ledgerase-cli verify-log " << defaultEvidenceDirectory()
              << "/audit/JOB-ID.json\n";
    std::cout << "  ledgerase-cli sanitize /dev/sdX --simulation --force\n";
}

// ---------------------------------------------------------------------------
// Module 2: file and folder erasure
// ---------------------------------------------------------------------------

// Resolves the block device a file lives on, for the residual search.
//
// A file-level erase can only write the file's own blocks, but a copy of the
// content can end up anywhere the filesystem put it - a journal, a log, a
// copy-on-write block. Searching only the file would find nothing and the
// absence would be meaningless, so the search runs over the medium.
//
// This reads /proc/self/mountinfo through the existing containment helpers and
// returns an empty string when the medium cannot be established, which the
// caller reports as "not searched" rather than as "nothing found".
std::string mediumForPath(const std::string& path, std::string& why) {
    why.clear();
    const std::string type = reportedFilesystemName(path);
    if (type.empty()) {
        why = "the kernel reported no filesystem for the path";
        return {};
    }
    // Resolved before matching against the mount table, for the same reason
    // filesystemTypeOf() does it: mount points are absolute, so a relative
    // argument matches only "/" and the answer becomes the root filesystem.
    // That is what happened here, and it reported a btrfs medium for a file
    // under /dev/shm.
    std::string resolved = path;
    if (resolved.empty() || resolved.front() != '/') {
        std::error_code ec;
        const std::filesystem::path absolute =
            std::filesystem::absolute(std::filesystem::path(path), ec);
        if (ec) {
            why = "the path could not be resolved to an absolute one: " +
                  ec.message();
            return {};
        }
        resolved = absolute.string();
    }
    // The backing device, from the same table.
    std::ifstream mounts("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string token;
        std::string mountPoint;
        bool separator = false;
        for (int i = 0; i < 6; ++i) {
            if (!(iss >> token)) {
                break;
            }
            if (i == 4) {
                mountPoint = token;
            }
        }
        while (iss >> token) {
            if (token == "-") {
                separator = true;
                break;
            }
        }
        if (!separator) {
            continue;
        }
        std::string fsType;
        std::string source;
        if (!(iss >> fsType) || !(iss >> source)) {
            continue;
        }
        if (fsType != type) {
            continue;
        }
        const bool inside = mountPoint == "/"
                                ? true
                                : (resolved.size() > mountPoint.size() &&
                                   resolved.compare(0, mountPoint.size(),
                                                    mountPoint) == 0 &&
                                   resolved[mountPoint.size()] == '/');
        if (inside && !source.empty()) {
            // The tmpfs case is checked before the "is it a device node" one,
            // because a memory filesystem's source is the literal string
            // "tmpfs" and fails the '/'-prefix test - which meant the honest
            // explanation was replaced by the generic "no device" one.
            if (source.front() != '/' && source == type) {
                // A memory filesystem, e.g. tmpfs. The mount table names no
                // device, so there is no region of bytes to search. Said so
                // rather than falling back to the file, which would report a
                // clean result by construction.
                why = "the filesystem is " + type +
                      ", which is memory rather than a device, so there is no "
                      "medium to search. A copy of the content could only exist "
                      "in a page this file no longer maps, or in swap, and "
                      "neither is reachable from here.";
                return {};
            }
            if (source.front() != '/') {
                continue;
            }
            return source;
        }
    }
    why = "the mount table names no device for the " + type + " mount holding "
          "this file";
    return {};
}

Result<void> CliApplication::eraseFileOrFolder(const CliOptions& options) {
    if (options.devicePath.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "A path is required: ledgerase-cli " + options.command + " <path>");
    }
    const bool folder = options.command == "erase-folder";
    const TargetProperties properties =
        folder ? statTarget(options.devicePath) : statTarget(options.devicePath);
    if (!properties.exists) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Cannot read " + options.devicePath,
            "The path must exist. Nothing was opened and nothing was written.");
    }
    if (folder && !properties.isDirectory) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Not a directory: " + options.devicePath,
            "Use 'erase-file' for a single file.");
    }
    if (!folder && !properties.isRegularFile) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Not a regular file: " + options.devicePath,
            "A block device, directory or device node is a different operation: "
            "use 'sanitize' for a device and 'erase-folder' for a directory.");
    }

    EraseOptions eraseOptions;
    eraseOptions.method = eraseMethodFromString(options.eraseMethod);
    eraseOptions.passes = options.erasePasses;
    eraseOptions.probeCount = options.probeCount;
    eraseOptions.searchLimitBytes = options.searchLimitBytes;
    eraseOptions.simulation = options.simulationMode;
    eraseOptions.recursive = options.recursive;
    eraseOptions.followSymlinks = options.followSymlinks;
    eraseOptions.includePatterns = options.includePatterns;
    eraseOptions.excludePatterns = options.excludePatterns;
    FileEraser eraser(eraseOptions);

    // -- The dry run, before anything can be written -----------------------
    //
    // A multi-file run needs a count and a total before the operator confirms,
    // and the only honest way to get them is to enumerate. For a folder that is
    // planFolder(), which opens nothing for writing. When --dry-run is given
    // this is the whole operation and nothing further runs.
    FolderEraseRecord dryRunRecord;
    if (folder) {
        auto planned = eraser.planFolder(options.devicePath);
        if (planned.isError()) {
            return Result<void>::err(planned.error());
        }
        dryRunRecord = planned.value();
        if (options.dryRun) {
            std::cout << "*** DRY RUN - nothing was written ***\n";
            std::cout << "  Folder:    " << options.devicePath << "\n";
            if (options.recursive) {
                std::cout << "  Scope:     recursive\n";
            } else {
                std::cout << "  Scope:     this folder only; --recursive descends\n";
            }
            if (!options.includePatterns.empty()) {
                std::cout << "  Include:   ";
                for (std::size_t i = 0; i < options.includePatterns.size(); ++i) {
                    std::cout << options.includePatterns[i]
                              << (i + 1 < options.includePatterns.size() ? ", " : "\n");
                }
            }
            if (!options.excludePatterns.empty()) {
                std::cout << "  Exclude:   ";
                for (std::size_t i = 0; i < options.excludePatterns.size(); ++i) {
                    std::cout << options.excludePatterns[i]
                              << (i + 1 < options.excludePatterns.size() ? ", " : "\n");
                }
            }
            std::cout << "  Would erase " << dryRunRecord.filesErased
                      << " file(s), " << dryRunRecord.totalBytes
                      << " bytes, and leave:\n";
            for (const FileEraseRecord& r : dryRunRecord.records) {
                if (r.state == EraseState::ERASED) {
                    std::cout << "    " << r.path << "  (" << r.sizeBytes
                              << " bytes)\n";
                }
            }
            for (const std::string& reason : dryRunRecord.notErased) {
                std::cout << "    not erased: " << reason << "\n";
            }
            std::cout << "  No file was opened for writing and nothing was "
                         "removed.\n";
            return Result<void>::success();
        }
    }

    // A multi-file or recursive run is a different kind of confirmation from a
    // single file. Confirming the folder's name tells the operator they named
    // the right directory; it does not tell them how many files are in it. The
    // count and the total are what make it a decision, so they are stated and
    // then confirmed. This is the file-level equivalent of the drive eraser's
    // serial confirmation and is not skipped for a recursive run.
    if (folder && !options.force) {
        ConfirmationManager confirm;
        DeviceInfo target;
        target.path = options.devicePath;
        target.model = options.recursive
                           ? "Directory (recursive)"
                           : "Directory (this level only)";
        target.capacityBytes = dryRunRecord.totalBytes;
        std::cout << "\nAbout to erase " << dryRunRecord.filesErased
                  << " file(s) totalling " << dryRunRecord.totalBytes
                  << " bytes.\n";
        if (dryRunRecord.filesRefused + dryRunRecord.filesFailed > 0) {
            std::cout << "  " << (dryRunRecord.filesRefused + dryRunRecord.filesFailed)
                      << " entr(y/ies) will not be erased, each with its reason "
                         "in the record.\n";
        }
        auto confirmed = confirm.requireTargetConfirmation(
            target, ConfirmationManager::ConfirmationBasis::FILE_BASENAME,
            options.serialSuffixLength, options.expectSerial, options.expectName);
        if (confirmed.isError()) {
            return confirmed;
        }
    }

    // Confirmation, before anything is written. A file has no serial, so the
    // name is what is confirmed - the same rule the device path uses for images.
    if (!folder && !options.force) {
        ConfirmationManager confirm;
        DeviceInfo target;
        target.path = options.devicePath;
        target.model = folder ? "Directory" : "Regular file";
        // The confirmation panel states the size, and a file-level erase is
        // entirely about the file's content. Showing 0 bytes there would be
        // actively misleading.
        target.capacityBytes = folder ? 0 : properties.sizeBytes;
        auto confirmed = confirm.requireTargetConfirmation(
            target, ConfirmationManager::ConfirmationBasis::FILE_BASENAME,
            options.serialSuffixLength, options.expectSerial,
            options.expectName);
        if (confirmed.isError()) {
            return confirmed;
        }
    }

    std::cout << "*** FILE/FOLDER ERASURE ***\n";
    std::cout << "  Target:   " << options.devicePath << "\n";
    std::cout << "  Passes:   " << eraseOptions.passes
              << " (requested), recorded as completed only if they all finished\n";
    std::cout << "  Probes:   " << eraseOptions.probeCount
              << " chunks of the file's own content, taken before the erase and\n"
                 "            searched for on the medium afterwards. The carver is "
                 "not\n"
                 "            used: it cannot see a file with no magic number.\n";
    if (options.simulationMode) {
        std::cout << "  SIMULATION MODE - no byte of the medium will be changed.\n";
    }

    EraseEvidenceBundle inputs;
    inputs.jobId = EraseEvidenceBuilder::generateJobId();
    inputs.applicationVersion = getVersion();
    const OperatorIdentity identity = currentOperatorIdentity();
    inputs.operatorName = identity.invokingUser;
    inputs.invokingUser = identity.invokingUser;
    inputs.invokingUid = identity.invokingUid;
    inputs.effectiveUser = identity.effectiveUser;
    inputs.effectiveUid = identity.effectiveUid;
    inputs.elevated = identity.elevated;
    inputs.targetPath = options.devicePath;
    inputs.targetKind = folder ? "folder" : "file";
    inputs.simulated = options.simulationMode;
    inputs.options = eraseOptions;
    inputs.filesystemName = reportedFilesystemName(options.devicePath);

    const std::string evidencePath =
        options.evidenceFile.empty()
            ? CliApplication::defaultEvidencePath(inputs.jobId, evidenceDirectory())
            : options.evidenceFile;
    const auto evidenceDir = ensureEvidenceDirectory(evidencePath);
    if (evidenceDir.isError()) {
        return evidenceDir;
    }

    FolderEraseRecord folderRecord;
    if (folder) {
        auto result = eraser.eraseFolder(options.devicePath);
        if (result.isError()) {
            return Result<void>::err(result.error());
        }
        folderRecord = result.value();
        // The per-file records go into the bundle, so a folder erasure is
        // audited file by file in the same format as a single-file one. A
        // summary count is not something an assessor can check.
        inputs.files = folderRecord.records;
        std::cout << "  " << folderRecord.entries.size() << " entries: "
                  << folderRecord.filesErased << " erased, "
                  << folderRecord.filesRefused << " refused, "
                  << folderRecord.filesFailed << " failed\n";
        for (const std::string& reason : folderRecord.notErased) {
            std::cout << "  not erased: " << reason << "\n";
        }
    }

    if (!folder) {
        std::cout << "\nErasing " << options.devicePath << "...\n" << std::flush;
        auto record = eraser.eraseFile(options.devicePath);
        if (record.isError()) {
            return Result<void>::err(record.error());
        }
        const FileEraseRecord& fileRecord = record.value();
        inputs.files.push_back(fileRecord);
        std::cout << "  " << eraseStateToString(fileRecord.state) << ": "
                  << fileRecord.detail << "\n";
        if (fileRecord.refusal.refused) {
            std::cout << "  Refused on " << fileRecord.refusal.filesystem
                      << ".\n";
        }
        // The residue note is the disclosure that a permitted run still leaves a
        // copy on some filesystems. It is printed prominently because the
        // overwrite line above says "erased" and the operator needs the caveat
        // next to it, not buried in the evidence file.
        if (!fileRecord.refusal.residueNote.empty()) {
            std::cout << "  NOTE - what a file-level erase leaves on "
                      << fileRecord.refusal.filesystem << ":\n";
            std::cout << "    " << fileRecord.refusal.residue << "\n";
            std::cout << "    The erase still makes the file unreadable through "
                         "the filesystem.\n"
                      << "    To reach the copies a file cannot, use "
                         "'ledgerase-cli sanitize <device>'.\n";
        }
    }

    // -- The residual search -------------------------------------------------
    //
    // The check that does not depend on the file's format. The probes are
    // chunks of the file's *own* bytes, taken before the erase, and the medium
    // is searched for them afterwards. The carver is deliberately not used: it
    // finds files that identify themselves, so a carver-clean result says
    // nothing about a file with no magic number.
    //
    // The search runs over the whole medium, not over the file, because the
    // file no longer holds anything to find. A copy can be anywhere the
    // filesystem put one - a journal, a log, a copy-on-write block - and
    // searching only the file would report a clean result by construction.
    if (!inputs.simulated) {
        std::string whyNotFound;
        // The medium is whatever actually holds the file's blocks. For a file on
        // a mounted filesystem that is the backing device from the mount table.
        // For a file inside a disk image, the image is the medium and the host
        // filesystem it happens to live on is not - so an explicit target
        // overrides the lookup, and naming it is the only way to search an image.
        const std::string medium =
            options.residualSearchTarget.empty()
                ? mediumForPath(options.devicePath, whyNotFound)
                : options.residualSearchTarget;
        if (!options.residualSearchTarget.empty() && medium.empty()) {
            whyNotFound = "the named residual search target is not readable";
        }
        inputs.residualSearchTarget = medium;
        const std::vector<std::string> swaps =
            SafetyManager::getActiveSwapDevices();

        // The residual search is mandatory unless it is explicitly waived, and
        // the waiver is loud in the output and recorded in the evidence. This is
        // the one step that says what is actually still on the medium; skipping
        // it silently would turn a verified overwrite into an unverified one
        // without saying so.
        if (options.noResidualSearch) {
            std::cout
                << "\n*** THE RESIDUAL SEARCH WAS SKIPPED. ***\n"
                << "  Nothing is claimed about what the medium still holds. This "
                   "is an\n  unverified overwrite, not a verified one."
                << (options.residualSearchSkipReason.empty()
                        ? "\n  No reason was given (--residual-search-skip-reason)."
                        : "\n  Reason given: " + options.residualSearchSkipReason)
                << "\n";
            inputs.residualSearchSkipped = true;
            inputs.residualSearchSkipReason =
                options.residualSearchSkipReason.empty()
                    ? "no reason given"
                    : options.residualSearchSkipReason;
            inputs.limitations.push_back(
                "The residual search was skipped by the operator (--no-"
                "residual-search"
                + (options.residualSearchSkipReason.empty()
                       ? std::string(", no reason given")
                       : ", reason: " + options.residualSearchSkipReason) +
                "). Nothing in this record says what the medium still holds; "
                "the overwrite is unverified.");
        }

        size_t searched = 0;
        for (FileEraseRecord& fileRecord : inputs.files) {
            if (fileRecord.state != EraseState::ERASED) {
                continue;
            }
            if (options.noResidualSearch) {
                continue;
            }
            ++searched;

            if (fileRecord.probes.empty()) {
                std::cout << "\n" << fileRecord.path
                          << ": no probes were taken, so the residual search did "
                             "not run.\n  Nothing is claimed about what the "
                             "medium still holds.\n";
                inputs.limitations.push_back(
                    "No content probes were recorded for " + fileRecord.path +
                    ", so the residual search did not run for it and nothing is "
                    "claimed about what the medium still holds.");
                continue;
            }

            // The probe bytes were captured before the erase and live only in
            // the eraser for the duration of the run. They are deliberately not
            // in the evidence file: a record containing the content that was
            // supposed to be erased is a second copy of it.
            const auto live = eraser.liveProbesFor(fileRecord.path);
            if (live.isError() || live.value().empty()) {
                std::cout << "\n" << fileRecord.path
                          << ": the pre-erase probe bytes were not available, so "
                             "the\n  residual search did not run. This is an "
                             "unverified overwrite.\n";
                inputs.limitations.push_back(
                    "The pre-erase probe bytes were not available for " +
                    fileRecord.path +
                    ", so the residual search did not run for it. This is an "
                    "unverified overwrite, not a verified one.");
                continue;
            }

            if (medium.empty()) {
                std::cout << "\n" << fileRecord.path
                          << ": the residual search did not run. " << whyNotFound
                          << "\n  Nothing is claimed about what the medium still "
                             "holds.\n";
                if (!swaps.empty()) {
                    std::cout << "  " << swaps.size()
                              << " swap area(s) are active (";
                    for (std::size_t i = 0; i < swaps.size(); ++i) {
                        std::cout << swaps[i] << (i + 1 < swaps.size() ? ", " : "");
                    }
                    std::cout << "); a page of this file could have been swapped "
                                 "out before\n  the erase and would be unaffected "
                                 "by it.\n";
                }
                inputs.limitations.push_back(
                    "The residual search did not run for " + fileRecord.path +
                    ": " + whyNotFound +
                    " An erase with no residual search is an unverified "
                    "overwrite, and is reported as one." +
                    (swaps.empty() ? std::string()
                                   : " Swap is active on this host, so a copy of "
                                     "the content may be in a swap area."));
                continue;
            }

            std::cout << "\n" << fileRecord.path << ": searching " << medium
                      << " for the " << fileRecord.probes.size()
                      << " content probe(s) taken before the erase";
            if (options.searchLimitBytes > 0) {
                std::cout << ", bounded to " << options.searchLimitBytes
                          << " bytes";
            }
            std::cout << "...\n" << std::flush;

            auto hits = eraser.searchForProbes(medium, live.value());
            if (hits.isError()) {
                inputs.limitations.push_back(
                    "The residual search for " + fileRecord.path +
                    " could not run: " + hits.error().what());
                std::cout << "  The search could not run: "
                          << hits.error().what() << "\n";
            } else if (hits.value().empty()) {
                std::cout << "  No probe was found anywhere in the searched "
                             "region.\n";
                std::cout << "  That is evidence about the region searched, not "
                             "about the\n  medium: a copy outside the bound, or "
                             "on another device, would not be seen.\n";
            } else {
                fileRecord.residualContentFound = true;
                fileRecord.residualLocations = hits.value();
                std::cout << "  RESIDUAL CONTENT FOUND: " << hits.value().size()
                          << " location(s) still hold content matching the file.\n";
                for (const std::string& hit : hits.value()) {
                    std::cout << "    " << hit << "\n";
                }
            }
        }
        if (searched == 0) {
            std::cout << "\nNo file reached the erased state, so there was "
                         "nothing to search for.\n";
        }
    }

    inputs.folder = folderRecord;

    const auto bundle = EraseEvidenceBuilder::build(inputs);
    if (bundle.isError()) {
        return Result<void>::err(bundle.error());
    }
    const auto written =
        EraseEvidenceWriter::write(bundle.value(), evidencePath, options.force);
    if (written.isError()) {
        return Result<void>::err(written.error());
    }

    {
        const auto digest = sha256OfFileForIndex(evidencePath);
        if (digest.ok()) {
            reportIndexResult(indexEvidence(
                options.databasePath,
                registrationFromErase(bundle.value(), evidencePath, digest.value(),
                                      options.description)));
        }
    }

    std::cout << "\nEvidence: " << evidencePath << "\n";
    std::cout << "  " << bundle.value().chainLength
              << " chained records, head "
              << bundle.value().chainHead.substr(0, 16) << "...\n";
    std::cout << "  One record per file, each carrying the digests of the "
                 "content probes\n  taken before the erase.\n";
    std::cout << "  Verify it with:\n    ledgerase-cli verify-log "
              << evidencePath << "\n";

    // A refusal or a failure is a failed command, not a partial success.
    if (bundle.value().filesFailed > 0 || bundle.value().filesRefused > 0 ||
        folderRecord.filesFailed > 0 || folderRecord.filesRefused > 0) {
        return Result<void>::err(
            ErrorCode::OPERATION_FAILED,
            "Not every file was erased: " +
                std::to_string(bundle.value().filesRefused) + " refused, " +
                std::to_string(bundle.value().filesFailed) + " failed",
            "The record names each one and why. The files that were erased are "
            "listed separately; do not treat the run as a whole.");
    }
    return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Module 3: carving
// ---------------------------------------------------------------------------

namespace {

// Where a command's running commentary goes.
//
// Under --json the machine-readable document is the only thing allowed on
// stdout, so narration moves to stderr. The alternative - interleaving status
// lines with the document - produces output that no JSON parser accepts, which
// is a broken contract rather than a cosmetic problem.
class NarrationChannel {
public:
    explicit NarrationChannel(bool toStderr) : toStderr_(toStderr) {}

    // Chaining has to keep working, and std::flush is a manipulator rather than
    // a value, so the stream is resolved on each call and returned.
    template <typename T>
    NarrationChannel& operator<<(const T& value) {
        (toStderr_ ? std::cerr : std::cout) << value;
        return *this;
    }

    // Manipulators: std::flush, std::endl and friends. They are function
    // pointers, not values, so the templated overload above cannot bind them
    // and the chain would stop here.
    NarrationChannel& operator<<(std::ostream& (*manipulator)(std::ostream&)) {
        (toStderr_ ? std::cerr : std::cout) << manipulator;
        return *this;
    }

private:
    bool toStderr_;
};

} // namespace

Result<void> CliApplication::carve(const CliOptions& options) {
    NarrationChannel info(options.jsonOutput);

    if (options.devicePath.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "A source is required: ledgerase-cli carve <image-or-device>");
    }

    // Classified first so a block device is reported as one. The source is
    // opened read-only either way: a recovery source is evidence.
    const TargetProperties properties = statTarget(options.devicePath);
    if (!properties.exists) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Cannot read " + options.devicePath +
                ": no such file, or it cannot be opened",
            "The source must be a readable image file or a block device. It is "
            "opened read-only and is never written to.");
    }

    info << "Carving " << options.devicePath << " ("
              << (properties.isBlockDevice ? "block device" : "file")
              << ", read-only)\n";
    if (properties.isBlockDevice) {
        info << "  A block device should not be mounted or in use while it is\n"
                     "  being read. Nothing here writes to it.\n";
    }

    // Output containment, before anything is written and before the scan, so a
    // bad --output-dir costs nothing rather than being discovered halfway
    // through a multi-minute run.
    if (!options.outputDirectory.empty()) {
        const auto separate = requireOutputSeparateFromSource(
            options.devicePath, options.outputDirectory);
        if (separate.isError()) {
            return Result<void>::err(separate.error());
        }
    }

    FileCarveSource source(options.devicePath);
    const auto size = source.size();
    if (size.isError()) {
        return Result<void>::err(size.error());
    }
    const uint64_t total = size.value();

    // Where the run's record goes, resolved and the directory created before
    // the scan. A recovery that cannot be recorded should not start: the
    // digests are the only thing this command produces, and a run whose results
    // cannot be checked later has not produced evidence.
    CarveEvidenceBundle carveInputs;
    carveInputs.jobId = CarveEvidenceBuilder::generateJobId();
    const std::string carveEvidencePath =
        options.evidenceFile.empty()
            ? CliApplication::defaultEvidencePath(carveInputs.jobId,
                                                  evidenceDirectory())
            : options.evidenceFile;
    const auto evidenceDir = ensureEvidenceDirectory(carveEvidencePath);
    if (evidenceDir.isError()) {
        return evidenceDir;
    }

    CarveOptions carveOptions;
    if (options.chunkSizeBytes > 0) {
        carveOptions.chunkSize = options.chunkSizeBytes;
    }
    if (options.maxRecoveredBytes > 0) {
        carveOptions.maxTotalOutputBytes = options.maxRecoveredBytes;
    }
    if (!options.minimumScore.has_value()) {
        carveOptions.minimumScore = 0.0;
    } else {
        carveOptions.minimumScore = *options.minimumScore;
    }

    const Carver carver(carveOptions);
    info << "  Scanning " << (total / (1024 * 1024)) << " MiB...\n" << std::flush;

    // Digest the source before reading it. If the digest after the run differs,
    // the medium changed while it was being read, and every offset in the
    // report describes some point between the two states rather than either
    // one. That is an error, not a footnote.
    info << "  Hashing the source before the scan...\n" << std::flush;
    const auto beforeHash = sha256OfFile(options.devicePath);
    if (beforeHash.isError()) {
        return Result<void>::err(beforeHash.error());
    }

    const auto report = carver.scan(source);
    if (report.isError()) {
        return Result<void>::err(report.error());
    }
    const CarveReport& result = report.value();

    // Extract only when a destination was given. The report is the primary
    // output; writing files is an explicit act.
    std::size_t extracted = 0;
    uint64_t extractedBytes = 0;
    std::vector<std::string> extractionFailures;
    // What this run actually wrote. A set of the paths extract() returned, not
    // a later stat() of the suggested name: extraction is additive and refuses
    // to clobber, so a file already at that name from an *earlier* run would
    // otherwise be recorded as written by this one.
    std::map<std::string, uint64_t> writtenThisRun;
    if (!options.outputDirectory.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(options.outputDirectory, ec);
        if (ec) {
            return Result<void>::err(
                ErrorCode::IO_ERROR,
                "Cannot create the output directory: " + options.outputDirectory);
        }
        for (const RecoveredFile& file : result.files) {
            bool withinBudget = false;
            const uint64_t remaining = carver.extractionBudgetRemaining(
                extractedBytes, withinBudget);
            if (!withinBudget || file.length > remaining) {
                const std::string why =
                    "offset " + std::to_string(file.offset) + ": would exceed the "
                    "output budget of " +
                    std::to_string(carveOptions.maxTotalOutputBytes) + " bytes";
                extractionFailures.push_back(why);
                info << "  not written: " << file.describe() << " - " << why
                          << "\n";
                continue;
            }
            std::string written;
            const auto copied =
                carver.extract(source, file, options.outputDirectory, written);
            if (copied.isError()) {
                const std::string why = "offset " + std::to_string(file.offset) +
                                        ": " + copied.error().what();
                extractionFailures.push_back(why);
                info << "  not written: " << file.describe() << " - "
                          << copied.error().what() << "\n";
                continue;
            }
            ++extracted;
            extractedBytes += copied.value();
            writtenThisRun[written] = copied.value();
        }
    }

    info << "  Hashing the source after the scan...\n" << std::flush;
    const auto afterHash = sha256OfFile(options.devicePath);
    if (afterHash.isError()) {
        return Result<void>::err(afterHash.error());
    }
    const bool sourceUnchanged = beforeHash.value() == afterHash.value();

    // The job's own record. Written before anything is reported, so a run that
    // produced results has a record of them even if the terminal is lost.
    carveInputs.applicationVersion = getVersion();
    carveInputs.carverVersion = getVersion();
    const OperatorIdentity identity = currentOperatorIdentity();
    carveInputs.operatorName = identity.invokingUser;
    carveInputs.invokingUser = identity.invokingUser;
    carveInputs.invokingUid = identity.invokingUid;
    carveInputs.effectiveUser = identity.effectiveUser;
    carveInputs.effectiveUid = identity.effectiveUid;
    carveInputs.elevated = identity.elevated;

    carveInputs.source.path = options.devicePath;
    carveInputs.source.kind =
        properties.isBlockDevice ? "block device" : "file";
    carveInputs.source.sizeBytes = total;
    carveInputs.source.sha256BeforeScan = beforeHash.value();
    carveInputs.source.sha256AfterScan = afterHash.value();
    carveInputs.source.unchanged = sourceUnchanged;
    carveInputs.source.openedReadOnly = true;

    // The effective parameters, not the requested ones. Carver clamps them, so
    // what the operator asked for and what the scan did can differ.
    const CarveOptions& effective = carver.options();
    carveInputs.parameters.chunkSize = effective.chunkSize;
    carveInputs.parameters.overlap = effective.overlap;
    carveInputs.parameters.maxCandidates = effective.maxCandidates;
    carveInputs.parameters.maxTotalOutputBytes = effective.maxTotalOutputBytes;
    carveInputs.parameters.maxInferredLength = effective.maxInferredLength;
    carveInputs.parameters.minimumScore = effective.minimumScore;
    carveInputs.parameters.outputDirectory = options.outputDirectory;

    carveInputs.candidatesExamined = result.candidatesExamined;
    carveInputs.notes = result.notes;
    for (const RecoveredFile& file : result.files) {
        CarveRecoveredEntry entry;
        entry.offset = file.offset;
        entry.length = file.length;
        entry.signatureName = file.signatureName;
        entry.extension = file.extension;
        entry.category = fileCategoryToString(file.category);
        entry.confidence = confidenceToString(file.confidence);
        entry.score = file.score;
        entry.sha256 = file.sha256;
        entry.truncated = file.truncated;
        entry.lengthInferred = file.lengthInferred;
        entry.structureValid = file.structureValid;
        entry.reasons = file.reasons;
        // Matched against what this run wrote, not against what exists at the
        // suggested name.
        const auto written = writtenThisRun.find(
            options.outputDirectory + "/" + Carver::suggestName(file));
        if (written != writtenThisRun.end()) {
            entry.extractedPath = written->first;
            entry.extractedBytes = written->second;
        }
        carveInputs.recovered.push_back(std::move(entry));
    }

    const auto carveBundle = CarveEvidenceBuilder::build(
        carveInputs, extractionFailures);
    if (carveBundle.isError()) {
        return Result<void>::err(carveBundle.error());
    }
    const auto carveWritten = CarveEvidenceWriter::write(
        carveBundle.value(), carveEvidencePath, options.force);
    if (carveWritten.isError()) {
        return Result<void>::err(carveWritten.error());
    }

    {
        const auto digest = sha256OfFileForIndex(carveEvidencePath);
        if (digest.ok()) {
            reportIndexResult(indexEvidence(
                options.databasePath,
                registrationFromCarve(carveBundle.value(), carveEvidencePath,
                                      digest.value(), options.description)));
        }
    }

    if (options.jsonOutput) {
        nlohmann::json document;
        document["job_id"] = carveBundle.value().jobId;
        document["source"] = options.devicePath;
        document["source_kind"] = carveInputs.source.kind;
        document["source_size_bytes"] = total;
        document["source_sha256_before_scan"] = carveInputs.source.sha256BeforeScan;
        document["source_sha256_after_scan"] = carveInputs.source.sha256AfterScan;
        document["source_unchanged"] = sourceUnchanged;
        document["candidates_examined"] = result.candidatesExamined;
        document["files_recovered"] = result.files.size();
        document["files_extracted"] = extracted;
        document["bytes_extracted"] = extractedBytes;
        document["extraction_failures"] = extractionFailures;
        nlohmann::json files = nlohmann::json::array();
        for (const CarveRecoveredEntry& entry : carveInputs.recovered) {
            files.push_back(entry);
        }
        document["files"] = files;
        document["notes"] = result.notes;
        document["evidence_path"] = carveEvidencePath;
        document["evidence_canonical_hash"] = carveBundle.value().canonicalHash;
        document["evidence_chain_length"] = carveBundle.value().chainLength;
        std::cout << document.dump(2) << "\n";
        return Result<void>::success();
    }

    info << "\nRecovered " << result.files.size()
              << " candidate file(s) from " << result.candidatesExamined
              << " header match(es).\n\n";

    for (const RecoveredFile& file : result.files) {
        info << "  " << file.describe() << "\n";
        if (file.sha256.size() == 64) {
            info << "    sha256 " << file.sha256 << "\n";
        }
        for (const std::string& reason : file.reasons) {
            info << "    - " << reason << "\n";
        }
        info << "\n";
    }

    if (!options.outputDirectory.empty()) {
        info << "Extracted " << extracted << " file(s), " << extractedBytes
                  << " bytes, to " << options.outputDirectory << "\n";
        if (extracted < result.files.size()) {
            info << "  " << (result.files.size() - extracted)
                      << " were not written; see the reasons above.\n";
        }
    } else {
        info << "No files were written. Pass --output-dir <directory> to "
                     "extract them.\n";
    }

    // The source-integrity statement. This is the check that the scan did not
    // disturb the evidence it is reporting on.
    info << "\nSource integrity:\n";
    info << "  sha256 before scan: " << carveInputs.source.sha256BeforeScan
              << "\n";
    info << "  sha256 after scan:  " << carveInputs.source.sha256AfterScan
              << "\n";
    info << "  " << (sourceUnchanged
                              ? "unchanged: the source is byte-for-byte the same "
                                "as it was before the scan"
                              : "CHANGED: the source differs from its pre-scan "
                                "digest, so the offsets above describe no single "
                                "state of the medium")
              << "\n";
    info << "  The source was opened read-only and no code path opens it "
                 "for writing.\n";

    info << "\nEvidence: " << carveEvidencePath << "\n";
    info << "  " << carveBundle.value().chainLength
              << " chained records, head "
              << carveBundle.value().chainHead.substr(0, 16) << "...\n";
    info << "  One record per recovered file, each carrying that file's "
                 "SHA-256.\n";
    info << "  Verify it with:\n    ledgerase-cli verify-log "
              << carveEvidencePath << "\n";

    for (const std::string& note : result.notes) {
        info << "Note: " << note << "\n";
    }

    // A source that changed under the scan invalidates the whole report, so it
    // is a failed command. Returning 0 would let a script record a recovery
    // whose offsets mean nothing.
    if (!sourceUnchanged) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "The source changed while it was being carved: sha256 before scan " +
                carveInputs.source.sha256BeforeScan + ", after scan " +
                carveInputs.source.sha256AfterScan,
            "Another process wrote to the medium, or the medium is failing. The "
            "recovered offsets cannot be trusted. The record of the run, "
            "including both digests, is at " + carveEvidencePath + ".");
    }
    return Result<void>::success();
}

int CliApplication::runShell() {
    std::cout << "Ledgerase interactive session\n";
    std::cout << "Every job writes its evidence bundle to ./" << kDefaultEvidenceDirectory
              << "/audit/<job-id>.json\n";
    std::cout << "as it finishes, so nothing is lost when this session ends.\n";
    std::cout << "Type 'audit' to list the records, 'evidence <job-id>' to read one,\n";
    std::cout << "'help' for the command list, 'quit' to end the session.\n\n";


    std::string line;
    int lastStatus = 0;
    while (true) {
        std::cout << "ledgerase> " << std::flush;

        if (!std::getline(std::cin, line)) {
            std::cout << "\n";
            break;
        }

        // Tokenise on whitespace. The REPL takes no path arguments containing
        // spaces; use the one-shot form for those.
        std::vector<std::string> tokens;
        std::istringstream tokenizer(line);
        std::string token;
        while (tokenizer >> token) {
            tokens.push_back(token);
        }
        if (tokens.empty()) continue;

        if (tokens.front() == "quit" || tokens.front() == "exit") {
            break;
        }
        if (tokens.front() == "help") {
            printUsage();
            continue;
        }

        std::vector<char*> argv;
        argv.reserve(tokens.size() + 1);
        std::string program = "ledgerase-cli";
        argv.push_back(program.data());
        for (auto& value : tokens) {
            argv.push_back(value.data());
        }
        argv.push_back(nullptr);

        lastStatus = run(static_cast<int>(tokens.size()) + 1, argv.data());
    }

    // Nothing is buffered in memory to discard: every record produced in this
    // session was already written to ./evidence when its job finished.
    std::cout << "Session ended. All evidence bundles remain in ./"
              << kDefaultEvidenceDirectory << ".\n";
    return lastStatus;
}

// The ROT column, and whether the kernel's flag is worth believing on its own.
//
// queue/rotational is authoritative for a disk and routinely wrong for flash
// behind a USB mass-storage bridge: a DataTraveler 2.0 reports 1 while being
// pure flash, and lsblk prints ROTA=1 for it too. The kernel is not lying
// about what it was told by the bridge firmware - the value is simply not a
// statement about the medium.
//
// identifyMediaType() already resolves this by precedence, checking removability
// and the bus before the rotational flag, so TYPE is the derived answer and ROT
// is the raw one. This keeps that distinction visible instead of printing "Yes"
// next to "Removable" with nothing to reconcile them.
//
// The raw flag is never overwritten. An assessor reading the evidence wants what
// the kernel said; what they need is to know it was contradicted, so the column
// is annotated rather than corrected.
bool rotationalIsDisputed(const DeviceInfo& device) {
    // Read from the identity rather than re-derived here, so the annotation can
    // never disagree with the evidence record about the same device.
    return device.rotationalDisputed;
}

std::string rotationalColumn(const DeviceInfo& device) {
    return rotationalIsDisputed(device) ? "Yes*" : (device.rotational ? "Yes" : "No");
}

Result<void> CliApplication::listDevices(const CliOptions& options) {
    Result<std::vector<DeviceInfo>> devicesResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        devicesResult = pImpl_->mockBackend.discoverDevices();
    } else {
        devicesResult = pImpl_->deviceManager.discoverDevices();
    }

    if (devicesResult.isError()) {
        return Result<void>::err(devicesResult.error());
    }

    auto devices = devicesResult.value();

    // The regular files in a directory, as image entries.
    //
    // A disk image is a file, not a device: there is no kernel behind it, so
    // it has no transport, no serial and no rotational flag. What it has is a
    // size, and that is what the listing reports. Only regular files are
    // listed: a directory or a device node in the same place is not an image.
    if (!options.imagesDirectory.empty()) {
        std::error_code dirEc;
        std::filesystem::directory_iterator it(options.imagesDirectory, dirEc);
        if (dirEc) {
            return Result<void>::err(
                ErrorCode::IO_ERROR,
                "Cannot read the image directory " + options.imagesDirectory +
                    ": " + dirEc.message(),
                "Give a directory that exists and can be listed.");
        }
        std::vector<DeviceInfo> images;
        for (const auto& entry : it) {
            std::error_code fileEc;
            if (!entry.is_regular_file(fileEc) || fileEc) {
                continue;
            }
            DeviceInfo info;
            info.path = entry.path().string();
            info.model = entry.path().filename().string();
            info.mediaType = MediaType::IMAGE;
            info.identitySource = "file size";
            std::error_code sizeEc;
            const uintmax_t size = std::filesystem::file_size(entry.path(), sizeEc);
            if (!sizeEc) {
                info.capacityBytes = static_cast<uint64_t>(size);
            }
            images.push_back(std::move(info));
        }
        // Sorted, so the listing does not depend on the order the filesystem
        // happened to hand the entries over in.
        std::sort(images.begin(), images.end(),
                  [](const DeviceInfo& a, const DeviceInfo& b) {
                      return a.path < b.path;
                  });
        devices.insert(devices.end(), images.begin(), images.end());
    }


    if (options.jsonOutput) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& dev : devices) {
            j.push_back({
                {"path", dev.path},
                {"model", dev.model},
                {"vendor", dev.vendor},
                {"serial", dev.serial},
                {"capacity_bytes", dev.capacityBytes},
                {"transport", transportToString(dev.transport)},
                {"media_type", mediaTypeToString(dev.mediaType)},
                {"rotational", dev.rotational},
                {"rotational_disputed", dev.rotationalDisputed},
                {"mounted", dev.mounted},
                {"system_disk", dev.systemDisk},
                {"boot_disk", dev.bootDisk}
            });
        }
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << std::left
                  << std::setw(16) << "DEVICE"
                  << std::setw(24) << "MODEL"
                  << std::setw(10) << "TYPE"
                  << std::setw(12) << "SIZE"
                  << std::setw(10) << "TRANSPORT"
                  << std::setw(8) << "ROT"
                  << std::setw(8) << "MOUNT"
                  << std::setw(6) << "SYS"
                  << "\n";
        std::cout << std::string(94, '-') << "\n";

        for (const auto& dev : devices) {
            std::cout << std::left
                      << std::setw(16) << dev.path
                      << std::setw(24) << dev.model.substr(0, 23)
                      << std::setw(10) << mediaTypeToString(dev.mediaType)
                      << std::setw(12) << formatCapacity(dev.capacityBytes)
                      << std::setw(10) << transportToString(dev.transport)
                      << std::setw(8) << rotationalColumn(dev)
                      << std::setw(8) << (dev.mounted ? "Yes" : "No")
                      << std::setw(6) << (dev.systemDisk ? "Yes" : "No")
                      << "\n";
        }

        // Shown when the flag and the derived type disagree, because a bare
        // "Yes" beside "Removable" is a row the reader has to resolve alone.
        bool anyDisputed = false;
        for (const auto& dev : devices) {
            if (rotationalIsDisputed(dev)) {
                anyDisputed = true;
                break;
            }
        }
        if (anyDisputed) {
            std::cout << "\n";
            std::cout << "  * ROT is the kernel's queue/rotational flag, reported as read. USB\n";
            std::cout << "    bridges commonly report 1 whatever the media inside is, so flash can\n";
            std::cout << "    show ROT=Yes. TYPE is derived independently of that flag, and where\n";
            std::cout << "    they disagree this tool believes TYPE. 'inspect <device>' shows both.\n";
        }
    }

    return Result<void>::success();
}

Result<void> CliApplication::inspectDevice(const CliOptions& options) {
    if (options.devicePath.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Device path required");
    }

    Result<DeviceInfo> deviceResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        deviceResult = pImpl_->mockBackend.inspectDevice(options.devicePath);
    } else {
        deviceResult = pImpl_->deviceManager.inspectDevice(options.devicePath);
    }

    if (deviceResult.isError()) {
        return Result<void>::err(deviceResult.error());
    }

    auto device = deviceResult.value();


    if (options.jsonOutput) {
        nlohmann::json j = {
            {"path", device.path},
            {"model", device.model},
            {"vendor", device.vendor},
            {"serial", device.serial},
            {"firmware", device.firmware},
            {"capacity_bytes", device.capacityBytes},
            {"logical_block_size", device.logicalBlockSize},
            {"physical_block_size", device.physicalBlockSize},
            {"transport", transportToString(device.transport)},
            {"media_type", mediaTypeToString(device.mediaType)},
            {"rotational", device.rotational},
            {"rotational_disputed", device.rotationalDisputed},
            {"removable", device.removable},
            {"read_only", device.readOnly},
            {"mounted", device.mounted},
            {"system_disk", device.systemDisk},
            {"boot_disk", device.bootDisk},
            {"partitions", nlohmann::json::array()},
            {"filesystems", nlohmann::json::array()}
        };
        for (const auto& part : device.partitions) {
            j["partitions"].push_back({
                {"path", part.path},
                {"start_sector", part.startSector},
                {"size_sectors", part.sizeSectors},
                {"size_bytes", part.sizeBytes},
                {"filesystem", part.filesystemType},
                {"mounted", part.mounted},
                {"mount_point", part.mountPoint}
            });
        }
        for (const auto& fs : device.filesystems) {
            j["filesystems"].push_back({
                {"type", fs.type},
                {"label", fs.label},
                {"uuid", fs.uuid},
                {"total_bytes", fs.totalBytes},
                {"free_bytes", fs.freeBytes},
                {"mount_point", fs.mountPoint}
            });
        }
        std::cout << j.dump(2) << "\n";
    } else {
        auto reportResult = pImpl_->formatter.outputDeviceInfo(device);
        if (reportResult.isError()) {
            return Result<void>::err(reportResult.error());
        }
    }

    return Result<void>::success();
}

Result<void> CliApplication::showCapabilities(const CliOptions& options) {
    if (options.devicePath.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Device path required");
    }

    Result<DeviceInfo> deviceResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        deviceResult = pImpl_->mockBackend.inspectDevice(options.devicePath);
    } else {
        deviceResult = pImpl_->deviceManager.inspectDevice(options.devicePath);
    }

    if (deviceResult.isError()) {
        return Result<void>::err(deviceResult.error());
    }

    auto device = deviceResult.value();

    Result<CapabilityInfo> capsResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        capsResult = pImpl_->mockBackend.detectCapabilities(device);
    } else {
        capsResult = pImpl_->capabilityDetector.detectCapabilities(device);
    }

    if (capsResult.isError()) {
        return Result<void>::err(capsResult.error());
    }

    auto caps = capsResult.value();


    if (options.jsonOutput) {
        nlohmann::json j = {
            {"nvme_block_erase", capabilityToString(caps.nvmeBlockErase)},
            {"nvme_crypto_erase", capabilityToString(caps.nvmeCryptoErase)},
            {"nvme_overwrite", capabilityToString(caps.nvmeOverwrite)},
            {"ata_secure_erase", capabilityToString(caps.ataSecureErase)},
            {"ata_enhanced_secure_erase", capabilityToString(caps.ataEnhancedSecureErase)},
            {"ata_sanitize_block_erase", capabilityToString(caps.ataSanitizeBlockErase)},
            {"ata_sanitize_crypto_erase", capabilityToString(caps.ataSanitizeCryptoErase)},
            {"ata_sanitize_overwrite", capabilityToString(caps.ataSanitizeOverwrite)},
            {"host_overwrite", capabilityToString(caps.overwriteHost)},
            {"host_crypto_erase", capabilityToString(caps.cryptoEraseHost)},
            {"encryption_status", encryptionToString(caps.encryptionStatus)},
            {"supported_actions", caps.supportedSanitizeActions},
            {"limitations", caps.limitations}
        };
        std::cout << j.dump(2) << "\n";
    } else {
        auto reportResult = pImpl_->formatter.outputCapabilityInfo(caps);
        if (reportResult.isError()) {
            return Result<void>::err(reportResult.error());
        }
    }

    return Result<void>::success();
}

namespace {

// The refusal advice depends on whether the operator asked for PURGE or simply
// inherited it as the default. Both cases name the same fix, but a default that
// was never chosen reads as a tool limitation rather than a user error.
// Resolves the assurance level for a job, and records where it came from.
//
// Three sources, in precedence order:
//   1. --assurance. The operator asked for a level; that governs, and the basis
//      says so.
//   2. The local policy, when all three of its inputs were supplied.
//   3. The default (purge), unchanged from before this existed.
//
// Precedence is deliberate. An explicit --assurance is the operator overriding
// the policy, and an override that silently lost to the policy would make the
// flag a lie. The policy is a default, not a gate.
//
// The wording here is the important part. The three level names are the
// standard's, so a line reading only "PURGE" is ambiguous about whether NIST
// required it. This tool answers a different question - which level this job
// needs - and the answer comes from the organisation's policy, not from NIST
// SP 800-88 Rev. 2, which requires a risk-based decision (4.3.6) without
// specifying one. So every derived tier names the policy as its source and the
// inputs it came from. Nothing here may read "per NIST".
AssurancePolicyDecision resolveAssurance(const CliOptions& options) {
    AssurancePolicyDecision decision = deriveAssuranceTier(
        options.policyCategorization, options.policyReuseMedia,
        options.policyLeavingOrgControl);

    if (options.assuranceExplicit) {
        decision.derived = false;
        decision.rationale =
            "Requested explicitly with --assurance, which overrides the local "
            "policy. The operator is asserting the level; the tool does not "
            "second-guess it, and the choice is recorded as theirs.";
        return decision;
    }
    if (!decision.derived) {
        decision.rationale =
            "No --assurance and the local policy could not decide, so the "
            "default level is used. Supply --assurance, or all three policy "
            "inputs, to have the level derived rather than assumed.";
    }
    return decision;
}

void applyAssuranceToPlan(const CliOptions& options, SanitizationPlan& plan) {
    const AssurancePolicyDecision decision = resolveAssurance(options);
    if (decision.derived) {
        plan.requestedCategory = decision.tier;
        plan.assuranceBasis.source = "local-policy";
    } else if (options.assuranceExplicit) {
        plan.assuranceBasis.source = "operator";
    } else {
        plan.assuranceBasis.source = "default";
    }
    plan.assuranceBasis.categorization = decision.categorization;
    plan.assuranceBasis.reuseMedia = decision.reuseMedia;
    plan.assuranceBasis.leavingOrgControl = decision.leavingOrgControl;
    plan.assuranceBasis.rationale = decision.rationale;
    plan.assuranceBasis.provenance =
        "local policy - this project's own design, not a NIST SP 800-88 "
        "Rev. 2 requirement";
}

SanitizerError defaultAssuranceRefusal(const SanitizerError& original) {
    if (original.code() != ErrorCode::NO_SUITABLE_METHOD) {
        return original;
    }
    return SanitizerError(
        original.code(),
        "Default assurance (purge) is not achievable on this device. "
        "Re-run with --assurance clear.",
        "The default category is purge, which needs a mechanism that reaches "
        "storage the host cannot see. Pass --assurance clear to overwrite the "
        "host-visible address space instead.");
}

} // namespace

Result<void> CliApplication::createPlan(const CliOptions& options) {
    if (options.devicePath.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Device path required");
    }

    Result<DeviceInfo> deviceResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        deviceResult = pImpl_->mockBackend.inspectDevice(options.devicePath);
    } else {
        deviceResult = pImpl_->deviceManager.inspectDevice(options.devicePath);
    }

    if (deviceResult.isError()) {
        return Result<void>::err(deviceResult.error());
    }

    auto device = deviceResult.value();

    Result<CapabilityInfo> capsResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        capsResult = pImpl_->mockBackend.detectCapabilities(device);
    } else {
        capsResult = pImpl_->capabilityDetector.detectCapabilities(device);
    }

    if (capsResult.isError()) {
        return Result<void>::err(capsResult.error());
    }

    auto caps = capsResult.value();

    // The level is resolved before planning, because it is an input to method
    // selection, and the basis is applied to the finished plan so it travels
    // with the result.
    const AssurancePolicyDecision assuranceDecision = resolveAssurance(options);
    const SanitizationCategory effectiveAssurance =
        assuranceDecision.derived ? assuranceDecision.tier : options.assurance;

    auto planResult = pImpl_->planner.plan(device, caps, effectiveAssurance, true,
                                          options.method);
    if (planResult.isError()) {
        // Reported against the level actually requested, which is the derived
        // one when the policy ran.
        if (!options.assuranceExplicit &&
            effectiveAssurance == SanitizationCategory::PURGE) {
            return Result<void>::err(defaultAssuranceRefusal(planResult.error()));
        }
        return Result<void>::err(planResult.error());
    }

    SanitizationPlan plan = planResult.value();
    applyAssuranceToPlan(options, plan);
    // Sets the count and attaches the disclosure that depends on it. Setting
    // overwritePassCount directly would drop the flash warning, because the
    // pass count is not an input to method selection and so is not seen by
    // plan().
    SanitizationPlanner::applyOverwritePassCount(plan, options.overwritePassCount);
    plan.verifyDepth = options.verifyDepth == "full"
                           ? SanitizationPlan::VerifyDepth::FULL
                           : SanitizationPlan::VerifyDepth::SAMPLED;


    auto reportResult = pImpl_->planner.generatePlanReport(plan, options.verbose);
    if (reportResult.isError()) {
        return Result<void>::err(reportResult.error());
    }

    if (options.jsonOutput) {
        // Emit the plan through the domain adapters so JSON consumers see the
        // same field names and enum strings as the audit log and certificate.
        nlohmann::json j = plan;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << reportResult.value() << "\n";
    }

    return Result<void>::success();
}

Result<void> CliApplication::sanitize(const CliOptions& options) {
    if (options.devicePath.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Device path required");
    }

    Result<DeviceInfo> deviceResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        deviceResult = pImpl_->mockBackend.inspectDevice(options.devicePath);
    } else {
        deviceResult = pImpl_->deviceManager.inspectDevice(options.devicePath);
    }

    if (deviceResult.isError()) {
        return Result<void>::err(deviceResult.error());
    }

    auto device = deviceResult.value();


    // Captured so the evidence bundle can state what was checked before the
    // media was touched, including the case where --force skipped the checks.
    SafetyReport safetyReport;

    // The safety checks always run, including under --force.
    //
    // --force exists so an operator can get past a check that is blocking them
    // for a good reason, not so they can destroy the disk the system is running
    // from. The unmounted / system-disk / boot-disk refusals are therefore
    // unconditional: there is no flag that reaches them. --force now only
    // suppresses the interactive serial confirmation, which is the one step it
    // can legitimately stand in for, and the evidence records that it did so.
    {
        // A simulated device is evaluated against the state it declares, not
        // against the machine this process happens to be running on. Probing the
        // real system for a mock's path would refuse a demo run because the
        // host's own disk is mounted, and would let a mock that declares
        // systemDisk=true through because the host's state said otherwise.
        auto safetyResult = pImpl_->simulationMode || options.simulationMode
            ? SafetyManager::checkSimulatedDeviceSafety(device)
            : pImpl_->safetyManager.checkDeviceSafety(device.path);
        if (safetyResult.isError()) {
            return Result<void>::err(safetyResult.error());
        }

        safetyReport = safetyResult.value();

        if (safetyReport.hasCriticalFailure) {
            std::cout << "\n=== SAFETY CHECKS FAILED ===\n";
            for (const auto& check : safetyReport.checks) {
                const std::string status =
                    check.result == SafetyCheckResult::PASS ? "PASS" :
                    check.result == SafetyCheckResult::FAIL ? "FAIL" : "WARN";
                std::cout << "  [" << status << "] " << check.name << ": " << check.message << "\n";
                if (!check.recommendation.empty()) {
                    std::cout << "    -> " << check.recommendation << "\n";
                }
            }
            if (options.force) {
                std::cout << "\n--force does not override these checks. Refusing to "
                             "sanitize the system or boot disk, or a mounted device, "
                             "from the running operating system.\n";
            }
            return Result<void>::err(ErrorCode::DEVICE_MOUNTED,
                                     "Safety checks failed - aborting",
                                     "Unmount the device, and sanitize a disk that is "
                                     "not the running system or boot disk");
        }
    }

    Result<CapabilityInfo> capsResult;

    if (pImpl_->simulationMode || options.simulationMode) {
        capsResult = pImpl_->mockBackend.detectCapabilities(device);
    } else {
        capsResult = pImpl_->capabilityDetector.detectCapabilities(device);
    }

    if (capsResult.isError()) {
        return Result<void>::err(capsResult.error());
    }

    auto caps = capsResult.value();

    // Same resolution as the plan path: the derived level is what is requested,
    // and the refusal is reported against it rather than against the default.
    const AssurancePolicyDecision assuranceDecision = resolveAssurance(options);
    const SanitizationCategory effectiveAssurance =
        assuranceDecision.derived ? assuranceDecision.tier : options.assurance;

    auto planResult = pImpl_->planner.plan(device, caps, effectiveAssurance, options.dryRun,
                                          options.method);
    if (planResult.isError()) {
        if (!options.assuranceExplicit &&
            effectiveAssurance == SanitizationCategory::PURGE) {
            return Result<void>::err(defaultAssuranceRefusal(planResult.error()));
        }
        return Result<void>::err(planResult.error());
    }

    SanitizationPlan plan = planResult.value();
    applyAssuranceToPlan(options, plan);
    // The overwrite pass count is applied here as well as in the plan path.
    // It was not applied at all on this path, so `sanitize --overwrite-passes
    // 3` planned one pass in `plan`, reported one pass, and then executed one
    // pass: the flag was accepted and discarded. The executor reads
    // plan.overwritePassCount, so nothing downstream corrected it.
    SanitizationPlanner::applyOverwritePassCount(plan, options.overwritePassCount);
    // The requested read-back depth is applied here, in the sanitize path, not
    // only in the plan path. It was previously set in createPlan() alone, so
    // `sanitize --verify full` silently verified with the 64-sector sample: the
    // flag was accepted, the plan command showed it, and the run that actually
    // destroyed the media did not use it.
    plan.verifyDepth = options.verifyDepth == "full"
                           ? SanitizationPlan::VerifyDepth::FULL
                           : SanitizationPlan::VerifyDepth::SAMPLED;
    // The plan-dependent safety checks, added to the report that is already in
    // hand. Until now the method-support check and the capability limitations
    // were implemented and called from nowhere, so a run that reached this point
    // had never been checked against the method it was about to use. Both
    // results go into the evidence bundle's pre-execution record.
    {
        auto planned = pImpl_->safetyManager.addPlanChecks(
            safetyReport, plan.device, plan.capabilities, plan.requestedCategory,
            plan.selectedMethod);
        if (planned.isError()) {
            return Result<void>::err(planned.error());
        }
        safetyReport = planned.value();
        if (safetyReport.hasCriticalFailure) {
            std::cout << "\n=== SAFETY CHECKS FAILED (PLAN) ===\n";
            for (const auto& check : safetyReport.checks) {
                if (check.result == SafetyCheckResult::PASS) {
                    continue;
                }
                std::cout << "  [" << (check.result == SafetyCheckResult::FAIL
                                            ? "FAIL" : "WARN")
                          << "] " << check.name << ": " << check.message << "\n";
                if (!check.recommendation.empty()) {
                    std::cout << "    -> " << check.recommendation << "\n";
                }
            }
            return Result<void>::err(
                ErrorCode::OPERATION_FAILED,
                "The chosen method does not pass the safety checks",
                "The plan is refused. Run 'plan' to see why a method was chosen, "
                "and 'capabilities' to see what the device reports.");
        }
    }

    // Re-validated here because the flag is applied after the policy engine
    // built the plan. A bad value must not reach the device.
    if (plan.overwritePassCount < 1 || plan.overwritePassCount > 15) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "--overwrite-passes must be between 1 and 15, got " +
                std::to_string(static_cast<unsigned>(plan.overwritePassCount)),
            "The NVMe OWPASS field is 4 bits wide");
    }


    if (options.dryRun) {
        std::cout << "=== DRY RUN MODE ===\n";
        auto reportResult = pImpl_->planner.generatePlanReport(plan, options.verbose);
        if (reportResult.ok()) std::cout << reportResult.value() << "\n";
        std::cout << "\nNo destructive actions performed.\n";
        return Result<void>::success();
    }

    // Where this job's evidence bundle goes. --evidence overrides the location;
    // it never decides whether a bundle is written. Resolved *before* execution
    // and the directory created here, so a path that cannot be written is
    // discovered before the media is touched rather than after. A sanitization
    // that cannot be recorded must not start.
    const std::string evidencePath =
        options.evidenceFile.empty()
            ? defaultEvidencePath(plan.jobId, pImpl_->evidenceDirectory)
            : options.evidenceFile;

    const auto directory = ensureEvidenceDirectory(evidencePath);
    if (directory.isError()) {
        return directory;
    }

    std::cout << "Evidence will be written to: " << evidencePath << "\n";

    if (!options.force) {
        ConfirmationManager confirmMgr;
        // A file or an image has no serial, so it is confirmed by its name. A
        // block device keeps the serial-suffix check unchanged.
        const bool targetIsFile =
            !DeviceManager::isBlockDevice(options.devicePath) &&
            DeviceManager::isDiskImage(options.devicePath);
        auto confirmResult = confirmMgr.requireTargetConfirmation(
            device,
            targetIsFile
                ? ConfirmationManager::ConfirmationBasis::FILE_BASENAME
                : ConfirmationManager::ConfirmationBasis::SERIAL_SUFFIX,
            options.serialSuffixLength, options.expectSerial,
            options.expectName);
        if (confirmResult.isError()) {
            return Result<void>::err(confirmResult.error());
        }
    } else {
    }

    if (options.force) {
        // The checks did run; only the interactive confirmation was skipped.
        // Recording it as skipped is the point: the bundle must not imply an
        // operator confirmed a serial suffix when nobody typed one.
        safetyReport.addCheck("Serial suffix confirmation",
                              SafetyCheckResult::WARNING,
                              "Skipped: --force was supplied",
                              "The device identity was NOT confirmed by the operator "
                              "before execution. Treat this record with corresponding "
                              "caution.",
                              false);
    }

    std::cout << "\nStarting sanitization: " << methodToString(plan.selectedMethod) << "\n";
    std::cout << "Job ID: " << plan.jobId << "\n\n";

    // The reporter is the only thing that draws progress. The monitoring
    // callback below used to print a second "Progress: N%" line from the CLI,
    // which is how two formatters ended up disagreeing about the same job.
    const bool suppressProgress = options.noProgress || options.jsonOutput;
    ProgressConfig progressConfig =
        ProgressReporter::detect(suppressProgress, isUtf8Locale());
    ProgressReporter reporter(progressConfig);
    setActiveProgressReporter(&reporter);

    JobStatus finalStatus;
    VerificationReport methodVerification;
    auto execResult = pImpl_->executor.executeWithMonitoring(
        plan,
        [&](const JobStatus& status) { finalStatus = status; },
        &methodVerification);

    setActiveProgressReporter(nullptr);
    reporter.finish();
    std::cout << "\n";

    if (execResult.isError()) {
        return Result<void>::err(execResult.error());
    }


    std::cout << "\nSanitization " << jobStateToString(finalStatus.state) << "\n";

    if (finalStatus.simulated) {
        std::cout << "*** SIMULATED RESULT - NO REAL DEVICE WAS TOUCHED ***\n";
    }

    if (finalStatus.state == JobState::COMPLETED) {
        std::cout << "Duration: " << finalStatus.elapsedTime.count() << " seconds\n";
    } else {
        std::cout << "Sanitization did NOT complete.\n";
        if (!finalStatus.errorMessage.empty()) {
            std::cout << "Reason: " << finalStatus.errorMessage << "\n";
        }
    }

    AuditRecord record;
    record.jobId = plan.jobId;
    record.timestamp = formatTimestamp(std::chrono::system_clock::now());
    {
        const OperatorIdentity identity = currentOperatorIdentity();
        record.operatorName = identity.invokingUser;
        record.invokingUser = identity.invokingUser;
        record.invokingUid = identity.invokingUid;
        record.effectiveUser = identity.effectiveUser;
        record.effectiveUid = identity.effectiveUid;
        record.elevated = identity.elevated;
    }
    record.applicationVersion = getVersion();
    record.device = device;
    record.capabilities = caps;
    record.plan = plan;
    record.execution = finalStatus;

    // -- Verification -------------------------------------------------------
    // Performed by the engine for this method, not asserted by the caller. The
    // result is evidence and is reported even when it is not a pass.
    // The method's own verification is preferred: it performed the operation and
    // is the only component that can evidence what happened to it, which is what
    // makes a simulated read-back possible at all. The engine is the fallback for
    // the case where the method produced nothing.
    VerificationReport verificationReport;
    if (!methodVerification.evidence.empty()) {
        verificationReport = methodVerification;
    } else {
        auto derived = pImpl_->verificationEngine.verify(plan, finalStatus, nullptr);
        if (derived.ok()) {
            verificationReport = derived.value();
        }
    }
    if (!verificationReport.evidence.empty()) {
        record.verification = verificationReport;
        std::cout << "\nVerification: " << verificationToString(record.verification.result)
                  << "\n";
        for (const auto& item : record.verification.evidence) {
            std::cout << "  - " << item.method << ": "
                      << (item.passed ? "supports" : "does not support") << " - "
                      << item.description << "\n";
        }
        // The scope, because "PASS" without it is not a statement about the
        // medium. A read-back of 64 sectors is 0.05% of a 64 GiB disk and
        // 100% of a 32 MiB one, and the reader cannot tell which from the
        // verdict alone. These are the verification scope lines, which already
        // carry the count and the fraction of the target.
        for (const std::string& scopeLine : record.verification.scope) {
            std::cout << "  scope: " << scopeLine << "\n";
        }
    }

    // -- Validation ---------------------------------------------------------
    // Separate from verification: verification asks what happened, validation
    // asks whether the outcome should be accepted.
    auto validation = pImpl_->validationEngine.validate(plan, record.verification, finalStatus);
    if (validation.isError()) {
    } else {
        record.validation = validation.value();
        // Deliberately not printed here. The recorded verdict is printed once at
        // the end of the run, after the evidence gates have had their say, and
        // the gates can only lower the engine's answer. Printing the engine's
        // verdict here as well produced two verdicts for one job, and they
        // differed whenever a gate fired - the reader had to work out which of
        // the two was the outcome.
    }

    // -- Evidence -----------------------------------------------------------
    // Written for every sanitization event. This is not optional and cannot be
    // switched off: the bundle is the only system of record this tool has, so a
    // sanitization that produced no bundle would be an unevidenced,
    // untraceable event. The default path is <evidence dir>/audit/<job-id>.json and
    // --evidence overrides where it goes, not whether it happens.
    auto bundle = pImpl_->buildEvidence(record, options, safetyReport);
    if (bundle.isError()) {
        return Result<void>::err(bundle.error());
    }

    EvidenceBundle evidence = bundle.value();

    // Signing happens before the file is written so the signature covers the
    // exact bytes that land on disk.
    if (!options.privateKeyFile.empty()) {
        auto signature = EvidenceVerifier::sign(evidence, options.privateKeyFile);
        if (signature.isError()) {
            return Result<void>::err(signature.error());
        }
        std::cout << "Signed with Ed25519 key " << signature.value().keyId << "\n";
    }

    auto written = EvidenceWriter::write(evidence, evidencePath, options.force);
    if (written.isError()) {
        return Result<void>::err(written.error());
    }

    {
        const auto digest = sha256OfFileForIndex(evidencePath);
        if (digest.ok()) {
            reportIndexResult(indexEvidence(
                options.databasePath,
                registrationFromSanitization(evidence, evidencePath, digest.value(),
                                             options.description)));
        }
    }

    pImpl_->printEvidenceSummary(evidence, evidencePath);

    // The verdict itself is already in the certificate header above, and is
    // printed once there. This adds only the reasoning, and states when the
    // evidence gates lowered the engine's answer rather than printing a second
    // verdict for the same job.
    std::cout << "\nValidation reasoning:\n";
    if (!evidence.validation.reasoning.empty()) {
        std::cout << "  " << evidence.validation.reasoning << "\n";
    } else {
        std::cout << "  (none recorded)\n";
    }
    if (record.validation.result != evidence.validation.result) {
        // The lowered verdict above is the one of record. Naming the engine's
        // own answer here produced a second verdict for one job, in the same
        // run, that disagreed with the first; a reader had to work out which
        // was the outcome. What they need is to know that a gate fired, and the
        // reasoning above already says which one.
        std::cout << "  The validation engine's own answer was lowered by the "
                     "evidence gates; the verdict above is the one of record.\n";
    }

    std::cout << "\nEvidence bundle written to: " << evidencePath << "\n";
    std::cout << "This file is the durable record of this sanitization. It is\n"
                 "written for every job and cannot be suppressed. Verify it with:\n"
              << "  ledgerase-cli verify-log " << evidencePath << "\n";

    // A job that did not reach COMPLETED is a failed command, not a successful
    // one. Returning 0 here would let a script record a sanitization that never
    // happened.
    if (finalStatus.state != JobState::COMPLETED) {
        return Result<void>::err(
            finalStatus.errorCode != 0
                ? static_cast<ErrorCode>(finalStatus.errorCode)
                : ErrorCode::OPERATION_FAILED,
            finalStatus.errorMessage.empty()
                ? std::string("Sanitization ended in state ") +
                      jobStateToString(finalStatus.state)
                : finalStatus.errorMessage);
    }

    return Result<void>::success();
}

// Re-runs verification for a job from its durable evidence bundle.
//
// The bundle is the system of record, so this works for a job from any earlier
// process on any machine that has the file. What it reports is the verification
// that was recorded at the time, re-derived from the artefacts in the bundle
// rather than re-executed against the device: the device has usually been
// removed by the time anyone asks.
Result<void> CliApplication::verifyJob(const CliOptions& options) {
    if (options.jobId.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Job ID required");
    }

    auto bundle = pImpl_->loadBundle(options.jobId, options.evidenceFile);
    if (bundle.isError()) {
        return Result<void>::err(bundle.error());
    }

    // Refuse to answer from a document that has been altered or truncated.
    // Reporting a verification read out of a tampered bundle would be worse
    // than reporting nothing.
    auto structural = EvidenceVerifier::verifyStructureFromBundle(bundle.value());
    if (structural.isError()) {
        return Result<void>::err(structural.error());
    }
    if (!structural.value().chainConsistent || !structural.value().canonicalHashMatches) {
        std::string reasons;
        for (const auto& finding : structural.value().findings) {
            if (!reasons.empty()) reasons += "; ";
            reasons += finding;
        }
        return Result<void>::err(
            ErrorCode::VALIDATION_FAILED,
            "The evidence bundle for job " + options.jobId + " does not verify: " + reasons,
            "Treat the underlying sanitization as unevidenced");
    }

    // The verification is re-derived from the recorded plan and execution so the
    // output is produced by the engine, not merely copied out of the file.
    SanitizationPlan plan;
    plan.jobId = bundle.value().jobId;
    plan.device = bundle.value().device;
    plan.requestedCategory = bundle.value().requestedCategory;
    plan.selectedMethod = bundle.value().selectedMethod;
    plan.rationale = bundle.value().decisionRationale;
    // residualRiskLimitations is a plain string list in the stored bundle
    // (including schema-1 bundles), so it comes back in as text rather than as
    // registry IDs. The registry is not consulted here on purpose: a
    // limitation recorded by an older build must survive unchanged.
    for (const std::string& limitation : bundle.value().residualRiskLimitations) {
        plan.limitations.addText(limitation);
    }

    VerificationEngine engine;
    auto verification = engine.verify(plan, bundle.value().execution, nullptr);
    if (verification.isError()) {
        return Result<void>::err(verification.error());
    }

    if (options.jsonOutput) {
        nlohmann::json j = verification.value();
        std::cout << j.dump(2) << "\n";
        return Result<void>::success();
    }

    std::cout << "Job:            " << bundle.value().jobId << "\n";
    std::cout << "Certificate:    " << bundle.value().certificateId << "\n";
    std::cout << "Canonical hash: " << bundle.value().canonicalHash.substr(0, 16) << "...\n";
    std::cout << "Verification:   " << verificationToString(verification.value().result) << "\n";
    for (const auto& item : verification.value().evidence) {
        std::cout << "\n  Evidence item\n";
        std::cout << "    Method:       " << item.method << "\n";
        std::cout << "    Description:  " << item.description << "\n";
        std::cout << "    Supports:     " << (item.passed ? "yes" : "no") << "\n";
        if (!item.details.empty()) std::cout << "    Details:      " << item.details << "\n";
        for (const auto& limitation : item.limitations) {
            std::cout << "    Limitation:   " << limitation << "\n";
        }
    }
    if (!verification.value().scope.empty()) {
        std::cout << "\n  Scope\n";
        for (const auto& line : verification.value().scope) {
            std::cout << "    - " << line << "\n";
        }
    }
    for (const auto& limitation : verification.value().limitations) {
        std::cout << "  Limitation: " << limitation << "\n";
    }

    // What was actually recorded, so the re-derivation above can be compared
    // against the original rather than replacing it silently.
    const auto& recorded = bundle.value().verification;
    if (recorded.result != verification.value().result) {
        std::cout << "\n  NOTE: the bundle recorded "
                  << verificationToString(recorded.result)
                  << " at the time of the sanitization. The result above is\n"
                     "        re-derived from the recorded plan and execution. Both\n"
                     "        are shown because neither supersedes the other.";
    }
    std::cout << "\nNote: this verification was produced by the same tool that ran the\n"
                 "sanitization, from the record it wrote. It is not independent\n"
                 "verification and cannot establish that the recorded events occurred.\n";
    return Result<void>::success();
}

Result<void> CliApplication::validateJob(const CliOptions& options) {
    if (options.jobId.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Job ID required");
    }

    auto bundle = pImpl_->loadBundle(options.jobId, options.evidenceFile);
    if (bundle.isError()) {
        return Result<void>::err(bundle.error());
    }

    auto structural = EvidenceVerifier::verifyStructureFromBundle(bundle.value());
    if (structural.isError()) {
        return Result<void>::err(structural.error());
    }
    if (!structural.value().chainConsistent || !structural.value().canonicalHashMatches) {
        return Result<void>::err(
            ErrorCode::VALIDATION_FAILED,
            "The evidence bundle for job " + options.jobId + " does not verify; "
            "its validation decision is not being reported",
            "Treat the underlying sanitization as unevidenced");
    }

    // Report the decision the bundle actually carries, including every gate the
    // builder applied. Re-running the validation engine here could produce a
    // different answer from the one that was certified, and the certified one is
    // the one that matters.
    const auto& recorded = bundle.value().validation;

    if (options.jsonOutput) {
        nlohmann::json j = {
            {"job_id", bundle.value().jobId},
            {"certificate_id", bundle.value().certificateId},
            {"recorded_validation", recorded},
            {"recorded_verification_result", bundle.value().verification.result},
            {"simulated", bundle.value().simulated}
        };
        std::cout << j.dump(2) << "\n";
        return Result<void>::success();
    }

    std::cout << "Job:           " << bundle.value().jobId << "\n";
    std::cout << "Certificate:   " << bundle.value().certificateId << "\n";
    std::cout << "Method:        " << methodToString(bundle.value().selectedMethod) << "\n";
    std::cout << "Category:      " << categoryToString(bundle.value().requestedCategory) << "\n";
    std::cout << "Validation:    " << validationToString(recorded.result) << "\n";
    std::cout << "\nReasoning:\n  " << recorded.reasoning << "\n";
    for (const auto& criterion : recorded.acceptedCriteria) {
        std::cout << "\n  Accepted:   " << criterion << "\n";
    }
    for (const auto& criterion : recorded.rejectedCriteria) {
        std::cout << "  Rejected:   " << criterion << "\n";
    }
    for (const auto& limitation : recorded.limitations) {
        std::cout << "  Limitation: " << limitation << "\n";
    }
    if (bundle.value().residualDataPossible) {
        std::cout << "\n  Residual data remains possible. " << bundle.value().residualRiskStatement << "\n";
    }
    return Result<void>::success();
}

// Forensic post-sanitization recovery testing against controlled disk images.
// Not implemented: the CLI reports that plainly rather than reporting success.
Result<void> CliApplication::recoverTest(const CliOptions& options [[maybe_unused]]) {
    pImpl_->formatter.outputMessage(
        "NOT IMPLEMENTED: forensic post-sanitization recovery testing.\n"
        "  This tool does not yet scan disk images, carve files, or compute\n"
        "  recovery metrics. No recovery test was performed and no recovery\n"
        "  metric in any report should be interpreted as a result.\n"
        "  The extension point is a carving/recovery module invoked against\n"
        "  the image files in tests/.");
    return Result<void>::err(ErrorCode::NOT_IMPLEMENTED,
                             "Forensic recovery testing is not implemented",
                             "Do not report recovery metrics until this is implemented");
}

Result<void> CliApplication::showReport(const CliOptions& options) {
    if (options.jobId.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT, "Job ID required");
    }

    auto bundle = pImpl_->loadBundle(options.jobId, options.evidenceFile);
    if (bundle.isError()) {
        return Result<void>::err(bundle.error());
    }

    const std::string format = options.outputFormat.empty() ? "text" : options.outputFormat;
    CertificateGenerator generator;

    // The report is a rendering of the evidence bundle, which is the record.
    // It is therefore written to include the bundle's own canonical hash, so a
    // report can always be traced back to the exact document it came from.
    const std::string hash = bundle.value().canonicalHash;

    if (format == "json") {
        nlohmann::json j = bundle.value();
        std::cout << j.dump(2) << "\n";
        return Result<void>::success();
    }

    if (format == "pdf") {
        // With no --output the report goes to <evidence dir>/reports/. It is
        // rendered from the bundle read above and states that bundle's
        // canonical hash; it is not a second record.
        const bool defaultDestination = options.outputFile.empty();
        const std::string outputPath =
            defaultDestination
                ? CliApplication::defaultReportPath(options.jobId,
                                                    pImpl_->evidenceDirectory, "pdf")
                : options.outputFile;
        if (defaultDestination) {
            const auto made = ensureEvidenceDirectory(
                outputPath, "Choose a writable location with --output <file.pdf>.");
            if (made.isError()) {
                return made;
            }
        }
        auto written = generator.writeEvidencePdf(bundle.value(), outputPath);
        if (written.isError()) {
            return Result<void>::err(written.error());
        }
        std::cout << "Report written to " << outputPath << "\n";
        return Result<void>::success();
    }

    auto text = generator.generateEvidenceText(bundle.value());
    if (text.isError()) {
        return Result<void>::err(text.error());
    }
    std::cout << text.value() << "\n"
              << "Evidence canonical hash: " << hash << "\n";
    return Result<void>::success();
}

// Lists the durable evidence bundles, or shows one in full. This is the audit
// trail: it is read from disk, so it shows what other processes and other
// machines actually recorded, not what this process remembers.
Result<void> CliApplication::showAudit(const CliOptions& options) {
    if (options.jobId.empty()) {
        auto paths = pImpl_->listBundlePaths();
        if (paths.isError()) {
            return Result<void>::err(paths.error());
        }

        std::cout << "=== EVIDENCE RECORDS (durable, on disk) ===\n";
        if (paths.value().empty()) {
            std::cout << "No evidence bundles found in ./"
                      << kDefaultEvidenceDirectory << " or ./"
                      << pImpl_->evidenceDirectory << ".\n";
            std::cout << "Every sanitization writes one. If you expected a record here,\n"
                         "the run either did not happen or wrote elsewhere; check the\n"
                         "path reported at the time of the run.\n";
            return Result<void>::success();
        }

        std::printf("%-24s %-22s %-10s %-14s %s\n", "JOB", "CERTIFICATE", "VERIFIED",
                    "VALIDATION", "PATH");
        std::cout << std::string(100, '-') << "\n";

        size_t intact = 0;
        for (const auto& path : paths.value()) {
            auto bundle = EvidenceWriter::read(path);
            if (bundle.isError()) {
                std::printf("%-24s %-22s %-10s %-14s %s\n", "<unreadable>", "-", "ERROR",
                            "-", path.c_str());
                continue;
            }
            const auto check = EvidenceVerifier::verifyStructure(path);
            const bool ok = check.ok() && check.value().schemaRecognised &&
                            check.value().canonicalHashMatches && check.value().chainConsistent;
            if (ok) ++intact;
            std::printf("%-24s %-22s %-10s %-14s %s\n",
                        bundle.value().jobId.c_str(),
                        bundle.value().certificateId.c_str(),
                        ok ? "yes" : "ALTERED",
                        validationToString(bundle.value().validation.result).c_str(),
                        path.c_str());
        }
        std::cout << "\n" << intact << " of " << paths.value().size()
                  << " bundle(s) verify against their own hash and chain.\n";
        return Result<void>::success();
    }

    auto bundle = pImpl_->loadBundle(options.jobId, options.evidenceFile);
    if (bundle.isError()) {
        return Result<void>::err(bundle.error());
    }
    pImpl_->printEvidenceSummary(
        bundle.value(),
        options.evidenceFile.empty() ? std::string("the default evidence path")
                                     : options.evidenceFile);
    return Result<void>::success();
}

// Moves the bundles that were written before audit/ and reports/ were
// separated out of the evidence directory and into its audit/ subdirectory.
//
// The file is moved, never re-read and re-written. A bundle is a record: the
// bytes on disk are what a third party verifies, and re-serialising it would
// produce a different document even when nothing had changed. The move is a
// rename within one filesystem, so the bytes that arrive are the bytes that
// left, and the hash and the chain are checked again at the destination.
//
// A dry run unless --apply is given. A directory of records is not changed by
// a command that was not asked to change it.
//
// A bundle is moved only if it verifies. One that does not is left exactly
// where it is and reported, because a damaged record is itself evidence and
// moving it would hide where it was found.
//
// reports/ is not touched: the scan is not recursive, so only the bundles that
// sit directly in the evidence directory are considered.
Result<void> CliApplication::migrateEvidence(const CliOptions& options) {
    const std::string directory =
        options.migrateDirectory.empty() ? defaultEvidenceDirectory()
                                          : options.migrateDirectory;

    std::error_code dirEc;
    if (!std::filesystem::is_directory(directory, dirEc)) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "No such evidence directory: " + directory,
            "Give the directory that holds the bundles to move.");
    }

    // The candidates: regular files sitting directly in the evidence
    // directory. The scan is not recursive, so audit/ and reports/ are not
    // reached at all.
    std::vector<std::string> candidates;
    {
        std::error_code ec;
        std::filesystem::directory_iterator it(directory, ec);
        if (ec) {
            return Result<void>::err(
                ErrorCode::IO_ERROR,
                "Cannot list the evidence directory " + directory + ": " +
                    ec.message(),
                "Check the path and its permissions.");
        }
        for (const auto& entry : it) {
            std::error_code fileEc;
            if (!entry.is_regular_file(fileEc) || fileEc) {
                continue;
            }
            if (entry.path().extension() != ".json") {
                continue;
            }
            candidates.push_back(entry.path().string());
        }
    }
    std::sort(candidates.begin(), candidates.end());

    const bool apply = options.applyMigrate;
    size_t moved = 0;
    size_t notBundles = 0;
    size_t refused = 0;

    std::cout << (apply ? "Migrating evidence bundles" : "Evidence migration (dry run)")
              << " in " << directory << "\n";
    if (!apply) {
        std::cout << "Nothing is changed without --apply.\n";
    }
    std::cout << "\n";

    const std::string auditDirectory = directory + "/" + kAuditSubdirectory;

    for (const std::string& source : candidates) {
        const std::string name =
            std::filesystem::path(source).filename().string();
        const std::string destination = auditDirectory + "/" + name;

        // Is this an evidence bundle at all? A file that is not one is not
        // moved and not an error: the evidence directory may hold other JSON,
        // and the command is about bundles.
        const std::string schema = evidenceSchemaOf(source);
        if (schema.empty()) {
            std::cout << "  not a bundle   " << name
                      << "  (left where it is)\n";
            ++notBundles;
            continue;
        }

        // A bundle that does not verify is not moved. A damaged record is
        // evidence in its own right, and moving it would hide where it was
        // found.
        const auto before = EvidenceVerifier::verifyStructure(source);
        if (before.isError() || !before.value().canonicalHashMatches ||
            !before.value().chainConsistent) {
            std::cout << "  NOT VERIFIED  " << name
                      << "  (left where it is)\n";
            if (before.isError()) {
                std::cout << "                 " << before.error().what() << "\n";
            } else {
                for (const std::string& finding : before.value().findings) {
                    if (finding.find("MISMATCH") != std::string::npos ||
                        finding.find("FAILED") != std::string::npos) {
                        std::cout << "                 " << finding << "\n";
                    }
                }
            }
            ++refused;
            continue;
        }

        // Refuse to overwrite. A bundle already in audit/ is a record; it is
        // not this command's to replace.
        if (std::filesystem::exists(destination)) {
            std::cout << "  EXISTS        " << name
                      << "  (refused to overwrite " << kAuditSubdirectory
                      << "/" << name << ")\n";
            ++refused;
            continue;
        }

        if (!apply) {
            std::cout << "  would move    " << name << "  ->  "
                      << kAuditSubdirectory << "/" << name << "\n";
            ++moved;
            continue;
        }

        // The destination directory, owner-only, as the rest of the evidence
        // tree is.
        if (!std::filesystem::exists(auditDirectory)) {
            std::error_code createEc;
            std::filesystem::create_directories(auditDirectory, createEc);
            if (createEc) {
                std::cout << "  FAILED        " << name << "  (cannot create "
                          << kAuditSubdirectory << ": " << createEc.message()
                          << ")\n";
                ++refused;
                continue;
            }
            std::error_code permEc;
            std::filesystem::permissions(
                auditDirectory, std::filesystem::perms::owner_all,
                std::filesystem::perm_options::replace, permEc);
        }

        // A rename, so the bytes are the bytes. Not a read and a write.
        std::error_code moveEc;
        std::filesystem::rename(source, destination, moveEc);
        if (moveEc) {
            std::cout << "  FAILED        " << name << "  (" << moveEc.message()
                      << ")\n";
            ++refused;
            continue;
        }

        // Checked again at the destination: the same document, verified the
        // same way, in its new place.
        const auto after = EvidenceVerifier::verifyStructure(destination);
        const bool intact = !after.isError() && after.value().canonicalHashMatches &&
                            after.value().chainConsistent;
        if (!intact) {
            std::cout << "  FAILED        " << name
                      << "  (moved, but it does not verify at the "
                         "destination)\n";
            ++refused;
            continue;
        }

        std::cout << "  moved         " << name << "  ->  "
                  << kAuditSubdirectory << "/" << name
                  << "  (hash and chain verified before and after)\n";
        ++moved;
    }

    std::cout << "\n";
    if (apply) {
        std::cout << moved << " bundle(s) moved, " << notBundles
                  << " file(s) that were not bundles, " << refused
                  << " refused.\n";
    } else {
        std::cout << moved << " bundle(s) would be moved, " << notBundles
                  << " file(s) that were not bundles, " << refused
                  << " refused. Nothing was changed.\n";
    }

    if (refused > 0) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            std::to_string(refused) +
                " bundle(s) were not moved. They are listed above with the "
                "reason.",
            "A bundle that does not verify is left where it is. Look at it "
            "before moving it by hand.");
    }
    return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Evidence index commands
// ---------------------------------------------------------------------------

namespace {

constexpr int kDefaultPageSize = 10;

Result<EvidenceDatabase> openIndex(const CliOptions& options, bool create) {
    const std::string path =
        options.databasePath.empty() ? defaultDatabasePath() : options.databasePath;
    auto opened = EvidenceDatabase::open(path, create);
    if (opened.isError()) {
        return Result<EvidenceDatabase>::err(opened.error());
    }
    auto initialised = opened.value().initialize();
    if (initialised.isError()) {
        return Result<EvidenceDatabase>::err(initialised.error());
    }
    return Result<EvidenceDatabase>::ok(std::move(opened.value()));
}

Result<EvidenceRecordRow> resolveRecord(const EvidenceDatabase& database,
                                        const std::string& key) {
    if (key.rfind("EV-", 0) == 0) {
        return database.recordForEvidenceId(key);
    }
    return database.recordForJob(key);
}

struct ArtifactVerification {
    bool integrityOk = false;
    bool signatureChecked = false;
    bool signatureValid = false;
    std::string detail;
};

Result<ArtifactVerification> verifyArtifactFile(const EvidenceArtifactRow& artifact,
                                                const std::string& publicKey) {
    std::error_code ec;
    if (!std::filesystem::exists(artifact.path, ec)) {
        return Result<ArtifactVerification>::err(
            ErrorCode::DEVICE_NOT_FOUND,
            "The evidence file is missing: " + artifact.path);
    }

    ArtifactVerification result;
    const auto digest = sha256OfFileForIndex(artifact.path);
    if (digest.isError()) {
        return Result<ArtifactVerification>::err(digest.error());
    }
    if (digest.value() != artifact.sha256) {
        result.detail = "SHA-256 MISMATCH: the file is not the one that was "
                        "registered";
        return Result<ArtifactVerification>::ok(result);
    }

    std::ifstream input(artifact.path, std::ios::binary);
    nlohmann::json document = nlohmann::json::parse(input, nullptr, false);
    if (document.is_discarded() || !document.is_object()) {
        result.detail = "The file is not a JSON evidence document";
        return Result<ArtifactVerification>::ok(result);
    }
    const std::string schema = document.value("schema", "");

    if (schema.find("evidence_bundle") != std::string::npos) {
        auto checked = publicKey.empty()
                           ? EvidenceVerifier::verifyStructure(artifact.path)
                           : EvidenceVerifier::verify(artifact.path, publicKey);
        if (checked.isError()) {
            return Result<ArtifactVerification>::err(checked.error());
        }
        const EvidenceVerification& verification = checked.value();
        result.integrityOk = verification.schemaRecognised &&
                             verification.canonicalHashMatches &&
                             verification.chainConsistent;
        if (!publicKey.empty()) {
            result.signatureChecked = verification.signaturePresent;
            result.signatureValid =
                verification.signaturePresent && verification.signatureValid;
            if (!verification.signaturePresent) {
                result.detail = "no signature present";
            } else if (!verification.signatureValid) {
                result.detail = "signature INVALID";
            }
        }
    } else if (schema.find("erase_bundle") != std::string::npos) {
        auto checked = EraseEvidenceVerifier::verifyStructure(artifact.path);
        if (checked.isError()) {
            return Result<ArtifactVerification>::err(checked.error());
        }
        result.integrityOk = checked.value().schemaRecognised &&
                             checked.value().canonicalHashMatches &&
                             checked.value().chainConsistent;
        result.detail = "file-erasure records are hash verified, not signed";
    } else if (schema.find("carve_bundle") != std::string::npos) {
        auto checked = CarveEvidenceVerifier::verifyStructure(artifact.path);
        if (checked.isError()) {
            return Result<ArtifactVerification>::err(checked.error());
        }
        result.integrityOk = checked.value().schemaRecognised &&
                             checked.value().canonicalHashMatches &&
                             checked.value().chainConsistent;
        result.detail = "carve records are hash verified, not signed";
    } else {
        result.detail = "Unrecognised evidence schema: " + schema;
        return Result<ArtifactVerification>::ok(result);
    }

    if (result.integrityOk && result.detail.empty()) {
        result.detail = "content is unaltered";
    }
    return Result<ArtifactVerification>::ok(result);
}

std::string datePart(const std::string& timestamp) {
    return timestamp.size() >= 10 ? timestamp.substr(0, 10) : timestamp;
}

void printEvidenceTable(const std::vector<EvidenceRecordRow>& records, int total,
                        int page, int pageSize, bool newestFirst) {
    const int start = total == 0 ? 0 : (page - 1) * pageSize + 1;
    const int end = (page - 1) * pageSize + static_cast<int>(records.size());
    std::cout << "LEDGERASE EVIDENCE RECORDS\n\n";
    if (total == 0) {
        std::cout << "No evidence records match.\n";
        std::cout << "Use 'ledgerase-cli evidence search --query <text>' to widen "
                     "the search.\n";
        return;
    }
    std::cout << "Showing " << start << "-" << end << " of " << total
              << " record(s), " << (newestFirst ? "newest first" : "oldest first")
              << "\n\n";
    std::printf("%-10s %-12s %-16s %-24s %-8s  %s\n", "ID", "DATE", "OPERATION",
                "TARGET", "STATUS", "DESCRIPTION");
    std::cout << std::string(100, '-') << "\n";
    for (const EvidenceRecordRow& record : records) {
        std::printf("%-10s %-12s %-16s %-24s %-8s  %s\n",
                    record.evidenceId.c_str(), datePart(record.createdAt).c_str(),
                    record.operation.c_str(), record.target.c_str(),
                    record.status.c_str(),
                    record.description.empty() ? "-" : record.description.c_str());
    }
    const int pages = (total + pageSize - 1) / pageSize;
    if (page < pages) {
        std::cout << "\nUse --page " << (page + 1) << " to view more records.\n";
    }
    if (page > 1) {
        std::cout << "Use --page " << (page - 1) << " to go back.\n";
    }
    std::cout << "Use 'ledgerase-cli evidence search' to find a specific record.\n";
}

void printRecordDetail(const EvidenceRecordRow& record,
                       const std::vector<EvidenceArtifactRow>& artifacts) {
    std::cout << "SELECTED EVIDENCE: " << record.evidenceId << "\n\n";
    std::cout << "Description: " << (record.description.empty() ? "-"
                                                               : record.description)
              << "\n";
    std::cout << "Operation:   " << record.operation << "\n";
    std::cout << "Target:      " << record.target << " (" << record.targetType
              << ")\n";
    std::cout << "Date:        " << datePart(record.createdAt) << "\n";
    std::cout << "Status:      " << record.status << "\n";
    std::cout << "Job ID:      " << record.jobId << "\n";
    std::cout << "Bundle:      " << record.bundlePath << "\n";
    std::cout << "SHA-256:     " << record.bundleSha256 << "\n";
    std::cout << "\nArtifacts:\n";
    for (const EvidenceArtifactRow& artifact : artifacts) {
        std::cout << "  - " << artifact.artifactType << ": " << artifact.path
                  << " (" << artifact.fileSize << " bytes, sha256 "
                  << artifact.sha256.substr(0, 16) << "...)\n";
        if (artifact.signaturePresent) {
            std::cout << "    signed with key " << artifact.signatureKeyId << "\n";
        }
    }
}

} // namespace

Result<void> CliApplication::manageEvidence(const CliOptions& options) {
    const std::string action =
        options.evidenceArgs.empty() ? std::string() : options.evidenceArgs.front();

    if (action == "migrate") {
        return migrateEvidence(options);
    }
    if (action == "list") {
        return evidenceList(options);
    }
    if (action == "search") {
        return evidenceSearch(options);
    }
    if (action == "show") {
        return evidenceShowRecord(options);
    }
    if (action == "verify") {
        return evidenceVerify(options);
    }
    if (action == "fetch") {
        return evidenceFetch(options);
    }
    if (action == "describe") {
        return evidenceDescribe(options);
    }
    if (action == "db") {
        return evidenceDatabaseCommand(options);
    }
    if (action == "backup") {
        return evidenceBackup(options);
    }
    if (action == "restore") {
        return evidenceRestore(options);
    }
    if (action == "check") {
        return evidenceCheck(options);
    }
    if (action.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT, "An evidence action is required",
            "Usage: ledgerase-cli evidence list|search|show|verify|fetch|describe|"
            "db|backup|restore|check [arguments]");
    }
    // Backwards compatibility: "evidence <job-id>" still shows a bundle.
    return showEvidence(options);
}

Result<void> CliApplication::evidenceList(const CliOptions& options) {
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    const int pageSize = options.pageSize > 0 ? options.pageSize : kDefaultPageSize;
    const int offset = (options.page - 1) * pageSize;
    const bool newestFirst = options.sortOrder != "date-asc";
    auto page = database.value().list(pageSize, offset, newestFirst);
    if (page.isError()) {
        return Result<void>::err(page.error());
    }
    if (options.jsonOutput) {
        nlohmann::json output;
        output["total"] = page.value().total;
        output["page"] = options.page;
        output["records"] = nlohmann::json::array();
        for (const EvidenceRecordRow& record : page.value().records) {
            output["records"].push_back({{"evidence_id", record.evidenceId},
                                         {"description", record.description},
                                         {"operation", record.operation},
                                         {"target", record.target},
                                         {"status", record.status},
                                         {"created_at", record.createdAt}});
        }
        std::cout << output.dump(2) << "\n";
        return Result<void>::success();
    }
    printEvidenceTable(page.value().records, page.value().total, options.page,
                       pageSize, newestFirst);
    return Result<void>::success();
}

Result<void> CliApplication::evidenceSearch(const CliOptions& options) {
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    EvidenceSearchQuery query;
    query.query = options.query;
    query.operation = options.searchOperation;
    query.status = options.searchStatus;
    query.targetType = options.searchTargetType;
    query.deviceModel = options.searchModel;
    query.date = options.searchDate;
    query.fromDate = options.searchFrom;
    query.toDate = options.searchTo;

    const int pageSize = options.pageSize > 0 ? options.pageSize : kDefaultPageSize;
    const int offset = (options.page - 1) * pageSize;
    const bool newestFirst = options.sortOrder != "date-asc";
    auto page = database.value().search(query, pageSize, offset, newestFirst);
    if (page.isError()) {
        return Result<void>::err(page.error());
    }

    if (options.jsonOutput) {
        nlohmann::json output;
        output["total"] = page.value().total;
        output["records"] = nlohmann::json::array();
        for (const EvidenceRecordRow& record : page.value().records) {
            output["records"].push_back({{"evidence_id", record.evidenceId},
                                         {"description", record.description},
                                         {"operation", record.operation},
                                         {"target", record.target},
                                         {"status", record.status},
                                         {"created_at", record.createdAt}});
        }
        std::cout << output.dump(2) << "\n";
        return Result<void>::success();
    }

    if (page.value().total == 0) {
        std::cout << "No evidence records match the search.\n";
        return Result<void>::success();
    }

    if (page.value().records.size() == 1) {
        auto artifacts =
            database.value().artifactsFor(page.value().records.front().evidenceId);
        if (artifacts.isError()) {
            return Result<void>::err(artifacts.error());
        }
        printRecordDetail(page.value().records.front(), artifacts.value());
        return Result<void>::success();
    }

    std::cout << page.value().total << " MATCHING EVIDENCE RECORD(S)\n\n";
    for (size_t i = 0; i < page.value().records.size(); ++i) {
        const EvidenceRecordRow& record = page.value().records[i];
        std::cout << "[" << (i + 1) << "] " << record.evidenceId << " - "
                  << (record.description.empty() ? "(no description)"
                                                 : record.description)
                  << "\n";
        std::cout << "    " << datePart(record.createdAt) << " | "
                  << record.target << " | " << record.status << "\n\n";
    }

    const auto select = [&](int index) -> Result<void> {
        if (index < 1 ||
            index > static_cast<int>(page.value().records.size())) {
            return Result<void>::err(
                ErrorCode::INVALID_ARGUMENT,
                "Selection out of range: " + std::to_string(index),
                "Choose a number from the list.");
        }
        const EvidenceRecordRow& record = page.value().records[index - 1];
        auto artifacts = database.value().artifactsFor(record.evidenceId);
        if (artifacts.isError()) {
            return Result<void>::err(artifacts.error());
        }
        printRecordDetail(record, artifacts.value());
        if (options.selectionIndex > 0 || options.noInteractive ||
            !::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO)) {
            return Result<void>::success();
        }
        std::cout << "\n1. View details\n2. Verify integrity\n3. Fetch evidence\n"
                     "4. Back\n\nChoose: ";
        std::string choice;
        if (!std::getline(std::cin, choice)) {
            return Result<void>::success();
        }
        CliOptions selected = options;
        selected.evidenceArgs = {"show", record.evidenceId};
        if (choice == "1") {
            return evidenceShowRecord(selected);
        }
        if (choice == "2") {
            selected.evidenceArgs = {"verify", record.evidenceId};
            return evidenceVerify(selected);
        }
        if (choice == "3") {
            selected.evidenceArgs = {"fetch", record.evidenceId};
            return evidenceFetch(selected);
        }
        return Result<void>::success();
    };

    if (options.selectionIndex > 0) {
        return select(options.selectionIndex);
    }
    if (options.noInteractive || !::isatty(STDIN_FILENO) ||
        !::isatty(STDOUT_FILENO)) {
        std::cout << "Select with 'ledgerase-cli evidence show <evidence-id>', or "
                     "pass --select <number>.\n";
        return Result<void>::success();
    }

    std::cout << "Select a record: " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line) || line.empty()) {
        return Result<void>::success();
    }
    char* end = nullptr;
    const long parsed = std::strtol(line.c_str(), &end, 10);
    if (end == line.c_str() || *end != '\0') {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "Not a selection number: " + line);
    }
    return select(static_cast<int>(parsed));
}

Result<void> CliApplication::evidenceShowRecord(const CliOptions& options) {
    if (options.evidenceArgs.size() < 2) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT, "An evidence ID is required",
            "Usage: ledgerase-cli evidence show EV-00001");
    }
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    auto record = resolveRecord(database.value(), options.evidenceArgs[1]);
    if (record.isError()) {
        return Result<void>::err(record.error());
    }
    auto artifacts = database.value().artifactsFor(record.value().evidenceId);
    if (artifacts.isError()) {
        return Result<void>::err(artifacts.error());
    }
    if (options.jsonOutput) {
        nlohmann::json output = {
            {"evidence_id", record.value().evidenceId},
            {"description", record.value().description},
            {"operation", record.value().operation},
            {"target", record.value().target},
            {"target_type", record.value().targetType},
            {"status", record.value().status},
            {"created_at", record.value().createdAt},
            {"job_id", record.value().jobId},
            {"bundle_path", record.value().bundlePath},
            {"bundle_sha256", record.value().bundleSha256},
            {"artifacts", nlohmann::json::array()}};
        for (const EvidenceArtifactRow& artifact : artifacts.value()) {
            output["artifacts"].push_back(
                {{"type", artifact.artifactType},
                 {"path", artifact.path},
                 {"file_size", artifact.fileSize},
                 {"sha256", artifact.sha256},
                 {"signature_present", artifact.signaturePresent}});
        }
        std::cout << output.dump(2) << "\n";
        return Result<void>::success();
    }
    printRecordDetail(record.value(), artifacts.value());
    return Result<void>::success();
}

Result<void> CliApplication::evidenceVerify(const CliOptions& options) {
    if (options.evidenceArgs.size() < 2) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT, "An evidence ID is required",
            "Usage: ledgerase-cli evidence verify EV-00001 [--public-key <pub.pem>]");
    }
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    auto record = resolveRecord(database.value(), options.evidenceArgs[1]);
    if (record.isError()) {
        return Result<void>::err(record.error());
    }
    auto artifacts = database.value().artifactsFor(record.value().evidenceId);
    if (artifacts.isError()) {
        return Result<void>::err(artifacts.error());
    }
    if (artifacts.value().empty()) {
        return Result<void>::err(
            ErrorCode::VERIFICATION_FAILED,
            "No artifacts are registered for " + record.value().evidenceId,
            "Run 'ledgerase-cli evidence check'.");
    }

    bool allOk = true;
    bool anySignatureChecked = false;
    bool anySignatureInvalid = false;
    for (const EvidenceArtifactRow& artifact : artifacts.value()) {
        auto checked = verifyArtifactFile(artifact, options.publicKeyFile);
        if (checked.isError()) {
            allOk = false;
            std::cout << "  FAILED  " << artifact.path << "\n            "
                      << checked.error().what() << "\n";
            continue;
        }
        anySignatureChecked = anySignatureChecked || checked.value().signatureChecked;
        anySignatureInvalid =
            anySignatureInvalid ||
            (checked.value().signatureChecked && !checked.value().signatureValid);
        const bool signatureMissingButRequested =
            !options.publicKeyFile.empty() && !checked.value().signatureChecked;
        if (!checked.value().integrityOk || signatureMissingButRequested) {
            allOk = false;
        }
        std::cout << "  " << (checked.value().integrityOk ? "OK    " : "FAILED")
                  << "  " << artifact.path << "\n            "
                  << checked.value().detail << "\n";
    }

    VerificationResultRow row;
    row.evidenceId = record.value().evidenceId;
    row.jobId = record.value().jobId;
    row.timestamp = formatTimestamp(std::chrono::system_clock::now());
    row.status = allOk ? "VERIFIED" : "FAILED";
    row.verifiedHash = record.value().bundleSha256;
    row.signatureStatus = anySignatureChecked
                              ? (anySignatureInvalid ? "invalid" : "valid")
                              : "not checked";
    (void)database.value().recordVerification(row);

    std::cout << "\n" << record.value().evidenceId << ": "
              << (allOk ? "verified" : "NOT verified") << "\n";
    if (allOk) {
        std::cout << "The artifact bytes match their recorded SHA-256 and each "
                     "bundle's own hash and chain verify.\n";
        if (!anySignatureChecked) {
            std::cout << "Signature: not checked (pass --public-key to check it). "
                         "Hash verification is integrity, not authentication.\n";
        }
    }
    if (!allOk) {
        return Result<void>::err(
            ErrorCode::VERIFICATION_FAILED,
            "Evidence " + record.value().evidenceId + " did not verify",
            "Do not treat the files as authentic. Inspect the paths above.");
    }
    return Result<void>::success();
}

Result<void> CliApplication::evidenceFetch(const CliOptions& options) {
    if (options.evidenceArgs.size() < 2) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT, "An evidence ID is required",
            "Usage: ledgerase-cli evidence fetch EV-00001 [--output <dir>]");
    }
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    auto record = resolveRecord(database.value(), options.evidenceArgs[1]);
    if (record.isError()) {
        return Result<void>::err(record.error());
    }
    auto artifacts = database.value().artifactsFor(record.value().evidenceId);
    if (artifacts.isError()) {
        return Result<void>::err(artifacts.error());
    }
    if (artifacts.value().empty()) {
        return Result<void>::err(ErrorCode::DEVICE_NOT_FOUND,
                                 "No artifacts are registered for " +
                                     record.value().evidenceId);
    }

    const std::string destination =
        options.outputFile.empty()
            ? "evidence-export/" + record.value().evidenceId
            : options.outputFile;

    // Verify before exporting, and check collisions first, so a failed run does
    // not leave a half-exported set behind.
    bool signatureChecked = false;
    bool signatureInvalid = false;
    bool signatureVerifiable = false;
    for (const EvidenceArtifactRow& artifact : artifacts.value()) {
        auto checked = verifyArtifactFile(artifact, options.publicKeyFile);
        if (checked.isError()) {
            return Result<void>::err(
                ErrorCode::VERIFICATION_FAILED,
                std::string("Refusing to export: ") + checked.error().what(),
                "The original evidence file is untouched. Repair or restore it "
                "before fetching.");
        }
        if (!checked.value().integrityOk) {
            return Result<void>::err(
                ErrorCode::VERIFICATION_FAILED,
                "Refusing to export " + artifact.path + ": " +
                    checked.value().detail);
        }
        signatureVerifiable = signatureVerifiable || artifact.signaturePresent;
        if (!options.publicKeyFile.empty()) {
            signatureChecked = signatureChecked || checked.value().signatureChecked;
            signatureInvalid = signatureInvalid ||
                               (checked.value().signatureChecked &&
                                !checked.value().signatureValid);
        }
    }
    if (signatureInvalid) {
        return Result<void>::err(
            ErrorCode::VERIFICATION_FAILED,
            "Refusing to export " + record.value().evidenceId +
                ": the signature did not verify",
            "The original evidence file is untouched. Check the public key and "
            "the bundle before fetching.");
    }

    std::error_code ec;
    const std::filesystem::path root(destination);
    if (!std::filesystem::exists(root, ec)) {
        std::filesystem::create_directories(root, ec);
        if (ec) {
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + destination + ": " +
                                         ec.message());
        }
        std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, ec);
    }
    if (!std::filesystem::is_directory(root, ec)) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 destination + " is not a directory");
    }

    for (const EvidenceArtifactRow& artifact : artifacts.value()) {
        const std::filesystem::path target =
            root / std::filesystem::path(artifact.path).filename();
        if (std::filesystem::exists(target, ec) && !options.force) {
            return Result<void>::err(
                ErrorCode::IO_ERROR,
                "Refusing to overwrite " + target.string(),
                "Choose another --output directory, or use --force.");
        }
    }

    for (const EvidenceArtifactRow& artifact : artifacts.value()) {
        const std::filesystem::path target =
            root / std::filesystem::path(artifact.path).filename();
        auto copied = copyEvidenceFile(artifact.path, target.string(), options.force);
        if (copied.isError()) {
            return Result<void>::err(copied.error());
        }
    }

    VerificationResultRow row;
    row.evidenceId = record.value().evidenceId;
    row.jobId = record.value().jobId;
    row.timestamp = formatTimestamp(std::chrono::system_clock::now());
    row.status = "VERIFIED";
    row.verifiedHash = record.value().bundleSha256;
    row.signatureStatus = signatureChecked
                              ? (signatureInvalid ? "invalid" : "valid")
                              : (signatureVerifiable ? "not checked" : "not supported");
    (void)database.value().recordVerification(row);

    std::cout << "Retrieved " << record.value().evidenceId << " to " << destination
              << "\n";
    std::cout << "  Integrity: verified (SHA-256 and bundle hash/chain)\n";
    if (!options.publicKeyFile.empty()) {
        if (signatureChecked) {
            std::cout << "  Signature: valid\n";
        } else {
            std::cout << "  Signature: not verifiable for this record type\n";
        }
    } else {
        std::cout << "  Signature: not checked (pass --public-key to check). "
                     "Integrity is not authentication.\n";
    }
    std::cout << "  The original files were not moved or modified.\n";
    return Result<void>::success();
}

Result<void> CliApplication::evidenceDescribe(const CliOptions& options) {
    if (options.evidenceArgs.size() < 2) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT, "An evidence ID is required",
            "Usage: ledgerase-cli evidence describe EV-00001 --description \"text\"");
    }
    if (options.description.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "--description is required",
                                 "The description is optional metadata, but this "
                                 "command exists to set it.");
    }
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    auto record = resolveRecord(database.value(), options.evidenceArgs[1]);
    if (record.isError()) {
        return Result<void>::err(record.error());
    }
    auto annotated = database.value().annotate(record.value().evidenceId,
                                               options.description, currentOperator());
    if (annotated.isError()) {
        return Result<void>::err(annotated.error());
    }
    std::cout << record.value().evidenceId
              << ": description updated. The change is recorded as an annotation; "
                 "the bundle and its hash are unchanged.\n";
    return Result<void>::success();
}

Result<void> CliApplication::evidenceDatabaseCommand(const CliOptions& options) {
    const std::string sub = options.evidenceArgs.size() > 1
                                ? options.evidenceArgs[1]
                                : std::string("status");
    if (sub == "init") {
        auto database = openIndex(options, true);
        if (database.isError()) {
            return Result<void>::err(database.error());
        }
        auto status = database.value().status();
        if (status.isError()) {
            return Result<void>::err(status.error());
        }
        std::cout << "Evidence database initialised.\n";
        std::cout << "  Path:   " << status.value().path << "\n";
        std::cout << "  Schema: " << status.value().schemaVersion << "\n";
        std::cout << "  Mode:   " << status.value().journalMode << "\n";
        return Result<void>::success();
    }
    if (sub != "status") {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "Unknown evidence db action: " + sub,
                                 "Use 'evidence db init' or 'evidence db status'.");
    }
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    auto status = database.value().status();
    if (status.isError()) {
        return Result<void>::err(status.error());
    }
    std::cout << "LEDGERASE EVIDENCE DATABASE\n\n";
    std::cout << "  Path:          " << status.value().path << "\n";
    std::cout << "  Exists:        " << (status.value().exists ? "yes" : "no") << "\n";
    std::cout << "  Schema:        " << status.value().schemaVersion << "\n";
    std::cout << "  Journal mode:  " << status.value().journalMode << "\n";
    std::cout << "  Size:          " << status.value().sizeBytes << " bytes\n";
    std::cout << "  Evidence:      " << status.value().evidenceCount << "\n";
    std::cout << "  Jobs:          " << status.value().jobCount << "\n";
    std::cout << "  Artifacts:     " << status.value().artifactCount << "\n";
    std::cout << "  Verifications: " << status.value().verificationCount << "\n";
    std::cout << "  Migrations:    " << status.value().migrationCount << "\n";
    std::cout << "\nThe database is an index. The bundles it points to are the "
                 "record.\n";
    return Result<void>::success();
}

Result<void> CliApplication::evidenceBackup(const CliOptions& options) {
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    const std::string destination =
        !options.outputFile.empty()
            ? options.outputFile
            : (options.evidenceArgs.size() > 1
                   ? options.evidenceArgs[1]
                   : (options.databasePath.empty() ? defaultDatabasePath()
                                                   : options.databasePath) +
                         ".backup");
    auto backed = database.value().backupTo(destination, options.force);
    if (backed.isError()) {
        return Result<void>::err(backed.error());
    }
    std::cout << "Evidence backup written to " << destination << "\n";
    std::cout << "  It contains the SQLite database and a copy of every artifact "
                 "it references.\n";
    return Result<void>::success();
}

Result<void> CliApplication::evidenceRestore(const CliOptions& options) {
    if (options.evidenceArgs.size() < 2) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT, "A backup directory is required",
            "Usage: ledgerase-cli evidence restore <backup-dir> [--db <path>]");
    }
    const std::string destination =
        options.databasePath.empty() ? defaultDatabasePath() : options.databasePath;
    auto restored =
        EvidenceDatabase::restoreFrom(options.evidenceArgs[1], destination,
                                      options.force);
    if (restored.isError()) {
        return Result<void>::err(restored.error());
    }
    std::cout << "Evidence database restored to " << destination << "\n";
    std::cout << "  The backup manifest and every artifact copy were verified "
                 "before the database was installed.\n";
    return Result<void>::success();
}

Result<void> CliApplication::evidenceCheck(const CliOptions& options) {
    auto database = openIndex(options, false);
    if (database.isError()) {
        return Result<void>::err(database.error());
    }
    auto report = database.value().consistency(
        [&](const EvidenceArtifactRow& artifact) -> Result<void> {
            auto checked = verifyArtifactFile(artifact, options.publicKeyFile);
            if (checked.isError()) {
                return Result<void>::err(checked.error());
            }
            if (!checked.value().integrityOk) {
                return Result<void>::err(ErrorCode::VERIFICATION_FAILED,
                                         checked.value().detail);
            }
            return Result<void>::success();
        });
    if (report.isError()) {
        return Result<void>::err(report.error());
    }

    std::vector<ConsistencyFinding> findings = report.value().findings;

    // Orphan bundles: files in the evidence store that the index does not know.
    std::vector<std::string> directories = {pImpl_->evidenceDirectory,
                                            defaultEvidenceDirectory()};
    std::vector<std::string> seen;
    for (const std::string& directory : directories) {
        for (const std::string& candidate :
             {directory + "/" + kAuditSubdirectory, directory}) {
            std::error_code ec;
            if (!std::filesystem::is_directory(candidate, ec)) {
                continue;
            }
            for (const auto& entry :
                 std::filesystem::directory_iterator(candidate, ec)) {
                if (!entry.is_regular_file() || entry.path().extension() != ".json") {
                    continue;
                }
                const std::string path = entry.path().string();
                if (std::find(seen.begin(), seen.end(), path) != seen.end()) {
                    continue;
                }
                seen.push_back(path);
                std::ifstream input(path, std::ios::binary);
                nlohmann::json document =
                    nlohmann::json::parse(input, nullptr, false);
                if (document.is_discarded() || !document.is_object()) {
                    continue;
                }
                const std::string jobId = document.value("job_id", "");
                if (jobId.empty()) {
                    continue;
                }
                if (database.value().recordForJob(jobId).isError()) {
                    findings.push_back(
                        {"", "orphan-file",
                         "The bundle " + path +
                             " is not registered in the evidence index"});
                }
            }
        }
    }

    std::cout << "EVIDENCE CONSISTENCY CHECK\n\n";
    std::cout << "Artifacts checked: " << report.value().checked << "\n";
    if (findings.empty()) {
        std::cout << "No inconsistencies found.\n";
        std::cout << "Every registered artifact exists, matches its recorded "
                     "SHA-256, and its bundle hash and chain verify.\n";
        return Result<void>::success();
    }
    std::cout << findings.size() << " finding(s):\n\n";
    for (const ConsistencyFinding& finding : findings) {
        std::cout << "  [" << finding.kind << "]"
                  << (finding.evidenceId.empty() ? "" : " " + finding.evidenceId)
                  << "\n    " << finding.detail << "\n";
    }
    return Result<void>::err(
        ErrorCode::OPERATION_FAILED,
        std::to_string(findings.size()) + " consistency finding(s)",
        "Missing or altered artifacts are evidence problems, not just index "
        "problems. Do not treat the affected records as verified.");
}

// Renders the evidence bundle for a job, optionally signing it and writing it to
// a new path. Reading is from the durable record, so this works for a job from
// any process.
Result<void> CliApplication::showEvidence(const CliOptions& options) {
    if (options.jobId == "migrate") {
        return migrateEvidence(options);
    }
    if (options.jobId.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Job ID required",
            "Usage: ledgerase-cli evidence <job-id> [--evidence <file>] [--sign <key.pem>]");
    }

    auto loaded = pImpl_->loadBundle(options.jobId, options.evidenceFile);
    if (loaded.isError()) {
        return Result<void>::err(loaded.error());
    }

    EvidenceBundle bundle = loaded.value();

    if (options.jsonOutput) {
        nlohmann::json j = bundle;
        std::cout << j.dump(2) << "\n";
    } else {
        pImpl_->printEvidenceSummary(
            bundle, options.evidenceFile.empty() ? std::string("the default evidence path")
                                                 : options.evidenceFile);
    }

    // --sign re-signs the document as it stands. It cannot be used to alter
    // anything: the signature covers the canonical hash, and verify-log checks
    // the content against that hash.
    if (!options.privateKeyFile.empty()) {
        auto signature = EvidenceVerifier::sign(bundle, options.privateKeyFile);
        if (signature.isError()) {
            return Result<void>::err(signature.error());
        }
        std::cout << "\nSigned with Ed25519 key " << signature.value().keyId << "\n";
    }

    // Writing to a new path requires one to be named, because the existing
    // record is already on disk and must not be overwritten by accident.
    if (!options.outputFile.empty() && options.evidenceFile.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "--output for an evidence bundle means where to write it",
            "Use: ledgerase-cli evidence <job-id> --evidence <file.json>");
    }

    if (!options.evidenceFile.empty() && options.evidenceFile != loaded.value().jobId) {
        const std::string& target = options.evidenceFile;
        if (std::filesystem::exists(target) && !options.force) {
            return Result<void>::err(
                ErrorCode::IO_ERROR,
                "Refusing to overwrite the existing evidence file " + target,
                "Re-run with --force to replace it, or choose another path");
        }
        auto written = EvidenceWriter::write(bundle, target, options.force);
        if (written.isError()) {
            return Result<void>::err(written.error());
        }
        std::cout << "\nEvidence bundle written to: " << target << "\n";
    }

    return Result<void>::success();
}

// Verifies an evidence file produced by this or any other tool. Requires no
// state from the producing session.
Result<void> CliApplication::verifyEvidenceFile(const CliOptions& options) {
    // The file may be given positionally or with --output; both are accepted so
    // that "verify-log <file>" reads naturally.
    const std::string path = !options.outputFile.empty() ? options.outputFile
                                                        : options.devicePath;
    if (path.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "An evidence file path is required",
            "Usage: ledgerase-cli verify-log <file.json> [--public-key <pub.pem>]");
    }

    const bool wantSignature = !options.publicKeyFile.empty();
    // Two document types share this command. A carve record is a different
    // schema with a different set of claims, and verifying it with the
    // sanitization reader would read fields that are not there. The schema is
    // read first and the matching verifier used, so "verify-log" means one
    // thing: check whatever this file claims, against the machinery built for
    // that kind of claim.
    const bool carveIsEraseRecord = [&path]() -> bool {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return false;
        }
        nlohmann::json document = nlohmann::json::parse(input, nullptr, false);
        if (document.is_discarded() || !document.is_object()) {
            return false;
        }
        if (!document.contains("schema") || !document.at("schema").is_string()) {
            return false;
        }
        return document.at("schema").get<std::string>() ==
               EraseEvidenceBundle::kSchema;
    }();

    const bool isCarveRecord = [&path]() -> bool {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return false;   // the real verifier reports the open failure
        }
        nlohmann::json document = nlohmann::json::parse(input, nullptr, false);
        if (document.is_discarded() || !document.is_object()) {
            return false;
        }
        if (!document.contains("schema") || !document.at("schema").is_string()) {
            return false;
        }
        const std::string schema = document.at("schema").get<std::string>();
        bool recognised = schema == CarveEvidenceBundle::kSchema ||
                          schema == EraseEvidenceBundle::kSchema;
        for (const char* legacy : CarveEvidenceBundle::kLegacySchemas) {
            recognised = recognised || schema == legacy;
        }
        for (const char* legacy : EraseEvidenceBundle::kLegacySchemas) {
            recognised = recognised || schema == legacy;
        }
        return recognised;
    }();

        // A file/folder erasure is the other hash-chained document this
        // command understands. It is a different set of claims from a carve
        // record - a content fingerprint and a refusal list rather than a list
        // of digests - and it is verified with the reader built for it.
        if (carveIsEraseRecord) {
            auto eraseCheck = EraseEvidenceVerifier::verifyStructure(path);
            if (eraseCheck.isError()) {
                return Result<void>::err(eraseCheck.error());
            }
            const auto& erase = eraseCheck.value();
            if (options.jsonOutput) {
                nlohmann::json j = {
                    {"file", path},
                    {"document_type", "erase record"},
                    {"schema_recognised", erase.schemaRecognised},
                    {"canonical_hash_matches", erase.canonicalHashMatches},
                    {"chain_consistent", erase.chainConsistent},
                    {"chain_length", erase.chainLength},
                    {"signature_present", false},
                    {"trustworthy", erase.schemaRecognised &&
                                        erase.canonicalHashMatches &&
                                        erase.chainConsistent},
                    {"findings", erase.findings},
                    {"limitations", erase.limitations}};
                std::cout << j.dump(2) << "\n";
            } else {
                std::string verdict;
                if (!erase.schemaRecognised) {
                    verdict = "UNRECOGNISED - not an erase record";
                } else if (!erase.canonicalHashMatches) {
                    verdict = "ALTERED - content does not match the recorded hash";
                } else if (!erase.chainConsistent) {
                    verdict = "INCOMPLETE - event chain does not verify";
                } else {
                    verdict =
                        "INTACT - unaltered and the chain verifies. Unsigned, so "
                        "this shows the file was not changed after it was "
                        "written; it says nothing about who wrote it.";
                }
                std::cout << "=== ERASE RECORD VERIFICATION ===\n";
                std::cout << "File:                " << path << "\n";
                std::cout << "Document:            erase record ("
                          << EraseEvidenceBundle::kSchema << ")\n";
                std::cout << "Verdict:             " << verdict << "\n\n";
                std::cout << "Schema recognised:   "
                          << (erase.schemaRecognised ? "yes" : "no") << "\n";
                std::cout << "Content unaltered:   "
                          << (erase.canonicalHashMatches ? "yes" : "NO") << "\n";
                std::cout << "Event chain:         "
                          << (erase.chainConsistent ? "intact" : "BROKEN") << " ("
                          << erase.chainLength << " records)\n";
                std::cout << "Signature:           absent (erase records are "
                             "unsigned)\n";
                std::cout << "\nFindings:\n";
                for (const std::string& finding : erase.findings) {
                    std::cout << "  - " << finding << "\n";
                }
                std::cout << "\nLimitations of this verification:\n";
                for (const std::string& limitation : erase.limitations) {
                    std::cout << "  - " << limitation << "\n";
                }
            }
            if (!erase.schemaRecognised || !erase.canonicalHashMatches ||
                !erase.chainConsistent) {
                return Result<void>::err(
                    ErrorCode::VALIDATION_FAILED,
                    "Erase record did not verify",
                    "Treat the recorded erase as unevidenced. The digests it "
                    "claims cannot be relied on.");
            }
            return Result<void>::success();
        }


    if (isCarveRecord) {
        if (wantSignature) {
            return Result<void>::err(
                ErrorCode::INVALID_ARGUMENT,
                "This is a carve record, and carve records are not signed",
                "Drop --public-key. A signature can only be checked against a "
                "sanitization certificate, which is produced by 'sanitize'.");
        }
        auto carveCheck = CarveEvidenceVerifier::verifyStructure(path);
        if (carveCheck.isError()) {
            return Result<void>::err(carveCheck.error());
        }
        const auto& carve = carveCheck.value();
        if (options.jsonOutput) {
            nlohmann::json j = {
                {"file", path},
                {"document_type", "carve record"},
                {"schema_recognised", carve.schemaRecognised},
                {"canonical_hash_matches", carve.canonicalHashMatches},
                {"chain_consistent", carve.chainConsistent},
                {"chain_length", carve.chainLength},
                {"signature_present", false},
                {"trustworthy", carve.schemaRecognised && carve.canonicalHashMatches &&
                                    carve.chainConsistent},
                {"findings", carve.findings},
                {"limitations", carve.limitations}};
            std::cout << j.dump(2) << "\n";
        } else {
            std::string verdict;
            if (!carve.schemaRecognised) {
                verdict = "UNRECOGNISED - not a carve record";
            } else if (!carve.canonicalHashMatches) {
                verdict = "ALTERED - content does not match the recorded hash";
            } else if (!carve.chainConsistent) {
                verdict = "INCOMPLETE - event chain does not verify";
            } else {
                verdict =
                    "INTACT - unaltered and the chain verifies. Unsigned, so this "
                    "shows the file was not changed after it was written; it says "
                    "nothing about who wrote it.";
            }
            std::cout << "=== CARVE RECORD VERIFICATION ===\n";
            std::cout << "File:                " << path << "\n";
            std::cout << "Document:            carve record (" << CarveEvidenceBundle::kSchema
                      << ")\n";
            std::cout << "Verdict:             " << verdict << "\n\n";
            std::cout << "Schema recognised:   "
                      << (carve.schemaRecognised ? "yes" : "no") << "\n";
            std::cout << "Content unaltered:   "
                      << (carve.canonicalHashMatches ? "yes" : "NO") << "\n";
            std::cout << "Event chain:         "
                      << (carve.chainConsistent ? "intact" : "BROKEN") << " ("
                      << carve.chainLength << " records)\n";
            std::cout << "Signature:           absent (carve records are unsigned)\n";
            std::cout << "\nFindings:\n";
            for (const std::string& finding : carve.findings) {
                std::cout << "  - " << finding << "\n";
            }
            std::cout << "\nLimitations of this verification:\n";
            for (const std::string& limitation : carve.limitations) {
                std::cout << "  - " << limitation << "\n";
            }
        }
        if (!carve.schemaRecognised || !carve.canonicalHashMatches ||
            !carve.chainConsistent) {
            return Result<void>::err(
                ErrorCode::VALIDATION_FAILED,
                "Carve record did not verify",
                "Treat the recovered digests as unevidenced. The record of what "
                "the carver claims to have found cannot be relied on.");
        }
        return Result<void>::success();
    }

    auto verification = wantSignature
        ? EvidenceVerifier::verify(path, options.publicKeyFile)
        : EvidenceVerifier::verifyStructure(path);

    if (verification.isError()) {
        return Result<void>::err(verification.error());
    }

    const auto& report = verification.value();


    if (options.jsonOutput) {
        nlohmann::json j = {
            {"file", path},
            {"schema_recognised", report.schemaRecognised},
            {"canonical_hash_matches", report.canonicalHashMatches},
            {"chain_consistent", report.chainConsistent},
            {"chain_length", report.chainLength},
            {"signature_present", report.signaturePresent},
            {"signature_valid", report.signatureValid},
            {"trustworthy", report.schemaRecognised && report.canonicalHashMatches &&
                                report.chainConsistent &&
                                (report.signaturePresent == false || (wantSignature && report.signatureValid))},
            {"findings", report.findings},
            {"limitations", report.limitations}
        };
        std::cout << j.dump(2) << "\n";
    } else {
        // The signature is computed over the stored canonical hash. If the
        // content no longer matches that hash, a "valid" signature only proves
        // the stored hash was not altered, not that the document is intact, so
        // the verdict is stated as a single judgement rather than as
        // independent yes/no fields.
        const bool contentIntact = report.canonicalHashMatches;
        const bool chainOk = report.chainConsistent;
        const bool signedOk = report.signatureValid && wantSignature;

        std::string verdict;
        if (!report.schemaRecognised) {
            verdict = "UNRECOGNISED - not an evidence bundle";
        } else if (!contentIntact) {
            verdict = "ALTERED - content does not match the recorded hash";
        } else if (!chainOk) {
            verdict = "INCOMPLETE - event chain does not verify";
        } else if (!report.signaturePresent) {
            verdict = "UNSIGNED - intact but proves nothing about origin";
        } else if (!wantSignature) {
            verdict = "INTERNALLY CONSISTENT - signature not checked";
        } else if (!signedOk) {
            verdict = "BAD SIGNATURE - key does not match this document";
        } else {
            verdict = "VERIFIED - unaltered, chain intact, signature valid";
        }

        std::cout << "=== EVIDENCE VERIFICATION ===\n";
        std::cout << "File:                " << path << "\n";
        std::cout << "Verdict:             " << verdict << "\n\n";
        std::cout << "Schema recognised:   " << (report.schemaRecognised ? "yes" : "no") << "\n";
        std::cout << "Content unaltered:   " << (report.canonicalHashMatches ? "yes" : "NO") << "\n";
        std::cout << "Event chain:         " << (report.chainConsistent ? "intact" : "BROKEN")
                  << " (" << report.chainLength << " records)\n";
        std::cout << "Signature:           ";
        if (!report.signaturePresent) {
            std::cout << "absent\n";
        } else if (wantSignature) {
            std::cout << (report.signatureValid ? "valid over the recorded hash" : "INVALID") << "\n";
        } else {
            std::cout << "present, not checked (supply --public-key)\n";
        }

        std::cout << "\nFindings:\n";
        for (const auto& finding : report.findings) {
            std::cout << "  - " << finding << "\n";
        }
        std::cout << "\nLimitations of this verification:\n";
        for (const auto& limitation : report.limitations) {
            std::cout << "  - " << limitation << "\n";
        }
    }

    const bool sound = report.schemaRecognised && report.canonicalHashMatches &&
                       report.chainConsistent;
    if (!sound) {
        return Result<void>::err(ErrorCode::VALIDATION_FAILED,
                                 "Evidence file did not verify",
                                 "Treat the underlying sanitization as unevidenced");
    }
    return Result<void>::success();
}

Result<void> CliApplication::showVersion(const CliOptions& options [[maybe_unused]]) {
    std::cout << "Ledgerase version " << getVersion() << "\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Platform: Linux x86_64\n";
    std::cout << "Standards: NIST SP 800-88 Rev. 2, IEEE 2883-2022\n";
    return Result<void>::success();
}

} // namespace ledgerase