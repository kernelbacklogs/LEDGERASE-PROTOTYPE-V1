#include "ledgerase/verification.hpp"

#include <iomanip>
#include "ledgerase/sanitization.hpp"
#include <sstream>

namespace ledgerase {

class VerificationEngine::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

VerificationEngine::VerificationEngine() : pImpl_(std::make_unique<Impl>()) {}
VerificationEngine::~VerificationEngine() = default;

Result<VerificationReport> VerificationEngine::verify(const SanitizationPlan& plan,
                                                       const JobStatus& executionStatus,
                                                       std::unique_ptr<ISanitizationMethod> method) {
    if (method) {
        return method->verify();
    }

    switch (plan.selectedMethod) {
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
            return verifyNvme(plan.device, executionStatus, plan.selectedMethod);
        case SanitizationMethod::ATA_SECURE_ERASE:
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            return verifyAta(plan.device, executionStatus, plan.selectedMethod);
        case SanitizationMethod::OVERWRITE_HOST:
            return verifyOverwrite(plan, executionStatus);
        case SanitizationMethod::CRYPTO_ERASE_HOST:
            return verifyCryptoErase(plan.device, executionStatus);
        default:
            break;
    }

    VerificationReport report;
    report.jobId = plan.jobId;
    report.timestamp = std::chrono::system_clock::now();
    report.result = VerificationResult::INCONCLUSIVE;
    report.evidence.push_back({
        "unknown",
        "Unknown method",
        false,
        "No verification available for method: " + methodToString(plan.selectedMethod),
        {{LimitationId::NOT_IMPLEMENTED, "method not recognized"}}
    });
    return Result<VerificationReport>::ok(report);
}

Result<VerificationReport> VerificationEngine::verifyNvme(const DeviceInfo& device [[maybe_unused]],
                                                           const JobStatus& executionStatus,
                                                           SanitizationMethod method [[maybe_unused]]) {
    VerificationReport report;
    report.jobId = executionStatus.jobId;
    report.timestamp = std::chrono::system_clock::now();

    if (executionStatus.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "nvme_sanitize_status",
            "NVMe Sanitize Status log",
            true,
            "Device reported sanitize completion with success status",
            {{LimitationId::HOST_SCOPE_ONLY}}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "nvme_sanitize_status",
            "NVMe Sanitize Status log",
            false,
            executionStatus.errorMessage.empty() ? "Sanitize did not complete successfully" : executionStatus.errorMessage,
            {{LimitationId::HOST_SCOPE_ONLY}}
        });
    }

    report.scope.push_back("NVMe Sanitize command completion status");
    report.scope.push_back("NVMe Sanitize Status log (Sanitize Progress, Sanitize Status)");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);

    return Result<VerificationReport>::ok(report);
}

Result<VerificationReport> VerificationEngine::verifyAta(const DeviceInfo& device [[maybe_unused]],
                                                          const JobStatus& executionStatus,
                                                          SanitizationMethod method [[maybe_unused]]) {
    VerificationReport report;
    report.jobId = executionStatus.jobId;
    report.timestamp = std::chrono::system_clock::now();

    if (executionStatus.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "ata_status",
            "ATA Status Register",
            true,
            "Device reported command completion without error",
            {LimitationId::HOST_SCOPE_ONLY}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "ata_status",
            "ATA Status Register",
            false,
            executionStatus.errorMessage.empty() ? "Command did not complete successfully" : executionStatus.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
    }

    report.scope.push_back("ATA command completion status");
    report.scope.push_back("ATA Sanitize Status (if supported)");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);

    return Result<VerificationReport>::ok(report);
}

void addOverwriteReadBackEvidence(const DeviceInfo& device,
                                   VerificationReport& report,
                                   bool exhaustive) {
    const bool readBackApplicable = !device.path.empty() && device.capacityBytes > 0;
    if (!readBackApplicable) {
        report.result = VerificationResult::INCONCLUSIVE;
        report.evidence.push_back({
            "host_read_back",
            "Read-back of the overwrite pattern",
            false,
            "No device path or capacity was available, so no sector could be read "
            "back and the overwrite could not be confirmed by inspecting the media.",
            {LimitationId::DEVICE_SELF_REPORT}
        });
        report.scope.push_back(
            "Read-back attempted but not possible: no path or capacity");
        return;
    }

    const uint32_t blockSize =
        device.logicalBlockSize != 0 ? device.logicalBlockSize : 512;
    auto readBack = exhaustive
                        ? readBackVerifyEverySector(device.path,
                                                    device.capacityBytes,
                                                    blockSize)
                        : readBackVerifyOverwrite(device.path,
                                                  device.capacityBytes,
                                                  blockSize);

    if (readBack.isError()) {
        // The read-back could not be performed. Not a pass, and not necessarily
        // a failure either, so it is reported as inconclusive with the reason
        // rather than quietly skipped.
        report.result = VerificationResult::INCONCLUSIVE;
        report.evidence.push_back({
            "host_read_back",
            "Read-back of the overwrite pattern",
            false,
            std::string("Read-back verification could not be performed: ") +
                readBack.error().what(),
            {LimitationId::DEVICE_SELF_REPORT}
        });
        report.scope.push_back("Read-back attempted but failed");
        return;
    }

    const auto& rb = readBack.value();
    report.evidence.push_back({
        "host_read_back",
        "Read-back of the overwrite pattern",
        rb.passed,
        rb.detail,
        rb.limitations
    });
    report.result = rb.passed ? VerificationResult::PASS : VerificationResult::FAIL;
    {
        // The scope line has to distinguish a sample from an exhaustive read.
        // "Read back 64 sectors" and "read the entire target" support very
        // different statements, and reporting them the same way would let a
        // reader over-read the evidence.
        std::ostringstream scope;
        if (rb.exhaustive) {
            scope << "Read-back of every one of the " << rb.samplesChecked
                  << " sectors in the target (" << std::fixed
                  << std::setprecision(4) << (rb.coveredFraction * 100.0)
                  << "% of the target read, exhaustively)";
        } else {
            scope << "Read-back of " << rb.samplesChecked
                  << " sectors sampled evenly across the target, covering "
                  << std::fixed << std::setprecision(4)
                  << (rb.coveredFraction * 100.0)
                  << "% of it. This is a sample, not an exhaustive read.";
        }
        report.scope.push_back(scope.str());
    }
}

Result<VerificationReport> VerificationEngine::verifyOverwrite(
    const SanitizationPlan& plan, const JobStatus& executionStatus) {
    const DeviceInfo& device = plan.device;
    VerificationReport report;
    report.jobId = executionStatus.jobId;
    report.timestamp = std::chrono::system_clock::now();

    if (executionStatus.state != JobState::COMPLETED) {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "host_overwrite",
            "Host-level overwrite completion",
            false,
            executionStatus.errorMessage.empty() ? "The overwrite did not complete"
                                                 : executionStatus.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
        report.scope.push_back("Host-level write to all logical block addresses");
        report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
        return Result<VerificationReport>::ok(report);
    }

    // Write completion is necessary but not sufficient: it says the writes were
    // issued and flushed, not that the media now holds what was written. The
    // media is read back and looked at.
    //
    // This matters most for USB, where there is usually no device status log to
    // consult and the host overwrite is the only mechanism in play. Without a
    // read-back, a bridge that accepted every write and did nothing with them
    // would be reported as a successful sanitization.
    addOverwriteReadBackEvidence(device, report,
                                 plan.verifyDepth ==
                                     SanitizationPlan::VerifyDepth::FULL);

    report.evidence.push_back({
        "host_write",
        "Host-level overwrite completion with flush",
        true,
        "The overwrite ran to completion and the writes were flushed to the device",
        {LimitationId::DEVICE_SELF_REPORT}
    });

    report.scope.push_back("Host-level write to all logical block addresses");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::CLEAR_ONLY);
    if (device.transport == TransportType::USB) {
        report.limitations.add(LimitationId::USB_BRIDGE_OPAQUE);
    }
    report.limitations.add(LimitationId::SELF_VERIFIED);

    return Result<VerificationReport>::ok(report);
}

Result<VerificationReport> VerificationEngine::verifyCryptoErase(const DeviceInfo& device [[maybe_unused]],
                                                                  const JobStatus& executionStatus) {
    VerificationReport report;
    report.jobId = executionStatus.jobId;
    report.timestamp = std::chrono::system_clock::now();

    report.result = VerificationResult::INCONCLUSIVE;
    report.evidence.push_back({
        "host_crypto_erase",
        "Host cryptographic erase",
        false,
        "Host crypto erase requires pre-configured encryption (LUKS, etc.) - not implemented",
        {LimitationId::CRYPTO_ERASE_NEEDS_FDE}
    });

    report.scope.push_back("Encryption key destruction (if implemented)");
    report.limitations.add(LimitationId::NOT_IMPLEMENTED);
    report.limitations.add(LimitationId::CRYPTO_ERASE_NEEDS_FDE);
    report.limitations.add(LimitationId::CRYPTO_ERASE_KEYS_ONLY);

    return Result<VerificationReport>::ok(report);
}

class ValidationEngine::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

ValidationEngine::ValidationEngine() : pImpl_(std::make_unique<Impl>()) {}
ValidationEngine::~ValidationEngine() = default;

Result<ValidationReport> ValidationEngine::validate(const SanitizationPlan& plan,
                                                     const VerificationReport& verification,
                                                     const JobStatus& executionStatus) {
    switch (plan.selectedMethod) {
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
            return validateNvme(plan, verification, executionStatus);
        case SanitizationMethod::ATA_SECURE_ERASE:
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            return validateAta(plan, verification, executionStatus);
        case SanitizationMethod::OVERWRITE_HOST:
            return validateOverwrite(plan, verification, executionStatus);
        case SanitizationMethod::CRYPTO_ERASE_HOST:
            return validateCryptoErase(plan, verification, executionStatus);
        default:
            break;
    }

    ValidationReport report;
    report.jobId = plan.jobId;
    report.timestamp = std::chrono::system_clock::now();
    report.result = ValidationResult::INCONCLUSIVE;
    report.reasoning = "Unknown sanitization method";
    return Result<ValidationReport>::ok(report);
}

Result<ValidationReport> ValidationEngine::validateNvme(const SanitizationPlan& plan,
                                                         const VerificationReport& verification,
                                                         const JobStatus& executionStatus) {
    ValidationReport report;
    report.jobId = plan.jobId;
    report.timestamp = std::chrono::system_clock::now();

    std::ostringstream reasoning;

    if (executionStatus.state != JobState::COMPLETED) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Execution failed: " << executionStatus.errorMessage;
        report.reasoning = reasoning.str();
        report.rejectedCriteria.push_back("Execution did not complete successfully");
        return Result<ValidationReport>::ok(report);
    }

    if (verification.result != VerificationResult::PASS) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Verification failed: " << verificationToString(verification.result);
        report.reasoning = reasoning.str();
        report.rejectedCriteria.push_back("Verification did not pass");
        return Result<ValidationReport>::ok(report);
    }

    reasoning << "NVMe sanitize command completed successfully. ";
    reasoning << "Device reported completion for " << methodToString(plan.selectedMethod) << ". ";

    if (plan.selectedMethod == SanitizationMethod::NVME_CRYPTO_ERASE) {
        reasoning << "Crypto Erase destroys the encryption key, rendering data unreadable. ";
        if (plan.capabilities.encryptionStatus == EncryptionStatus::UNKNOWN) {
            reasoning << "However, encryption status is UNKNOWN - effectiveness cannot be confirmed. ";
            report.acceptedCriteria.push_back("Device-reported Crypto Erase completion");
            report.limitations.add(LimitationId::ENCRYPTION_UNKNOWN);
            report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
        } else {
            report.acceptedCriteria.push_back("Device-reported Crypto Erase completion");
            report.result = ValidationResult::ACCEPTED;
        }
    } else if (plan.selectedMethod == SanitizationMethod::NVME_BLOCK_ERASE) {
        reasoning << "Block Erase instructs controller to erase all user-accessible blocks. ";
        report.acceptedCriteria.push_back("Device-reported Block Erase completion");
        report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
    } else {
        reasoning << "Overwrite performed by controller on all user-accessible blocks. ";
        report.acceptedCriteria.push_back("Device-reported Overwrite completion");
        report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
    }

    reasoning << "LIMITATION: Host cannot verify erasure of controller-managed areas (overprovisioning, ";
    reasoning << "wear-leveling, retired blocks, spare media). ";
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);

    report.reasoning = reasoning.str();
    return Result<ValidationReport>::ok(report);
}

Result<ValidationReport> ValidationEngine::validateAta(const SanitizationPlan& plan,
                                                        const VerificationReport& verification,
                                                        const JobStatus& executionStatus) {
    ValidationReport report;
    report.jobId = plan.jobId;
    report.timestamp = std::chrono::system_clock::now();

    std::ostringstream reasoning;

    if (executionStatus.state != JobState::COMPLETED) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Execution failed: " << executionStatus.errorMessage;
        report.reasoning = reasoning.str();
        report.rejectedCriteria.push_back("Execution did not complete successfully");
        return Result<ValidationReport>::ok(report);
    }

    if (verification.result != VerificationResult::PASS) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Verification failed: " << verificationToString(verification.result);
        report.reasoning = reasoning.str();
        report.rejectedCriteria.push_back("Verification did not pass");
        return Result<ValidationReport>::ok(report);
    }

    reasoning << "ATA sanitize/secure erase command completed successfully. ";

    if (plan.selectedMethod == SanitizationMethod::ATA_ENHANCED_SECURE_ERASE) {
        reasoning << "Enhanced Secure Erase uses vendor-specific pattern. ";
        report.acceptedCriteria.push_back("Device-reported Enhanced Secure Erase completion");
        report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
    } else if (plan.selectedMethod == SanitizationMethod::ATA_SECURE_ERASE) {
        reasoning << "Standard Secure Erase completed. ";
        report.acceptedCriteria.push_back("Device-reported Secure Erase completion");
        report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
    } else {
        reasoning << "ATA Sanitize " << methodToString(plan.selectedMethod) << " completed. ";
        report.acceptedCriteria.push_back("Device-reported ATA Sanitize completion");
        report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
    }

    reasoning << "LIMITATION: Host cannot verify firmware-managed areas (overprovisioning, ";
    reasoning << "wear-leveling, reallocated sectors). ";
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);

    report.reasoning = reasoning.str();
    return Result<ValidationReport>::ok(report);
}

Result<ValidationReport> ValidationEngine::validateOverwrite(const SanitizationPlan& plan,
                                                              const VerificationReport& verification,
                                                              const JobStatus& executionStatus) {
    ValidationReport report;
    report.jobId = plan.jobId;
    report.timestamp = std::chrono::system_clock::now();

    std::ostringstream reasoning;

    if (executionStatus.state != JobState::COMPLETED) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Execution failed: " << executionStatus.errorMessage;
        report.reasoning = reasoning.str();
        report.rejectedCriteria.push_back("Execution did not complete successfully");
        return Result<ValidationReport>::ok(report);
    }

    if (verification.result != VerificationResult::PASS) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Verification failed: " << verificationToString(verification.result);
        report.reasoning = reasoning.str();
        report.rejectedCriteria.push_back("Verification did not pass");
        return Result<ValidationReport>::ok(report);
    }

    if (plan.requestedCategory == SanitizationCategory::PURGE) {
        report.result = ValidationResult::REJECTED;
        reasoning << "Host overwrite completed but only provides CLEAR-level assurance. ";
        reasoning << "Requested PURGE category requires device-level sanitization for SSDs. ";
        report.rejectedCriteria.push_back("Host overwrite insufficient for PURGE on SSDs");
        report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
        report.limitations.add(LimitationId::CLEAR_ONLY);
    } else if (verification.result == VerificationResult::INCONCLUSIVE) {
        // A CLEAR request would otherwise be accepted on the strength of write
        // completion alone. Where the media could not be read back, the honest
        // outcome is that acceptance is undecided, not that it succeeded.
        report.result = ValidationResult::INCONCLUSIVE;
        reasoning << "The overwrite reported completion, but the media could not be "
                     "read back to confirm it, so the outcome cannot be accepted. ";
        report.rejectedCriteria.push_back(
            "No direct evidence that the overwrite reached the media");
        report.limitations.add(LimitationId::VERIFICATION_INCONCLUSIVE);
    } else if (plan.device.transport == TransportType::USB) {
        report.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
        reasoning << "The host-visible address space of the USB device was overwritten "
                     "and the sampled sectors read back clean. ";
        report.acceptedCriteria.push_back(
            "Host-level overwrite completed and confirmed by read-back over sampled sectors");
        report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
        report.limitations.add(LimitationId::SAMPLED_READBACK);
        report.limitations.add(LimitationId::REMOVABLE_HISTORY);
    } else {
        report.result = ValidationResult::ACCEPTED;
        reasoning << "Host overwrite completed successfully and the sampled sectors "
                     "read back with the overwrite pattern. ";
        // The scope qualifier matters. NIST SP 800-88 Rev. 2 defines clear
        // (Appendix A) as sanitizing "all user-addressable storage locations",
        // and §3.1.1 says overwriting "cannot address all areas of the ISM
        // where sensitive data may be retained" on flash devices that "contain
        // spare cells and perform wear levelling". A host overwrite is therefore
        // a clear-level technique on media it can fully address, and is not
        // clear for the ISM on overprovisioned flash. The plan's method
        // selection and the device's media type are what settle which applies
        // here; this validator records the host-level outcome and says so.
        reasoning << "This is the outcome of a host-level overwrite of the "
                     "host-visible address space. Whether that constitutes a "
                     "clear sanitization of the ISM depends on the media being "
                     "fully addressable; on overprovisioned flash it is not, and "
                     "the device's own capability record governs that. ";
        report.acceptedCriteria.push_back(
            "Host-level overwrite of the logical address space completed");
        report.acceptedCriteria.push_back(
            "Sampled read-back confirms the pattern in the sectors examined, "
            "which is a sample and not the whole address space");
    }

    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    if (verification.result != VerificationResult::PASS) {
        report.limitations.add(LimitationId::VERIFICATION_FAILED);
    }

    report.reasoning = reasoning.str();
    return Result<ValidationReport>::ok(report);
}

Result<ValidationReport> ValidationEngine::validateCryptoErase(const SanitizationPlan& plan [[maybe_unused]],
                                                                const VerificationReport& verification [[maybe_unused]],
                                                                const JobStatus& executionStatus [[maybe_unused]]) {
    ValidationReport report;
    report.jobId = plan.jobId;
    report.timestamp = std::chrono::system_clock::now();

    report.result = ValidationResult::INCONCLUSIVE;
    report.reasoning = "Host crypto erase not implemented - cannot validate";
    report.limitations.add(LimitationId::NOT_IMPLEMENTED);
    report.limitations.add(LimitationId::CRYPTO_ERASE_NEEDS_FDE);

    return Result<ValidationReport>::ok(report);
}

} // namespace ledgerase