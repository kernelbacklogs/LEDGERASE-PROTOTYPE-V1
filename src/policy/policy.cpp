#include "ledgerase/policy.hpp"
#include "ledgerase/device.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/sanitization.hpp"
#include "ledgerase/platform/linux.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace ledgerase {

class SanitizationPolicyEngine::Impl {
public:
    // Deliberately empty. It used to hold its own copy of the PolicyConfig,
    // which nothing read: every decision below used the engine's `config_`.
    // Two copies of a policy is two answers waiting to diverge, and the second
    // one is the one nobody edits.
};

SanitizationPolicyEngine::SanitizationPolicyEngine(const PolicyConfig& config)
    : pImpl_(std::make_unique<Impl>()), config_(config) {}
SanitizationPolicyEngine::~SanitizationPolicyEngine() = default;

Result<SanitizationPlan> SanitizationPolicyEngine::createPlan(const DeviceInfo& device,
                                                               const CapabilityInfo& capabilities,
                                                               SanitizationCategory requestedCategory,
                                                               bool dryRun,
                                                               SanitizationMethod requestedMethod) {
    SanitizationPlan plan;
    plan.jobId = SanitizationExecutor::generateJobId();
    plan.device = device;
    // Classified from the path, so a device or image plan records the same
    // kind the rest of the pipeline already assumes. A block device or a disk
    // image is classified from the path; a device node is a block device, a
    // regular file is an image. The stat() is only for the classification, and
    // a failure leaves the kind unknown rather than aborting a plan that would
    // otherwise succeed.
    {
        const TargetProperties properties = statTarget(device.path);
        plan.target.path = device.path;
        plan.target.kind =
            classifyTarget(device.path, &properties, /*isRecoverySource=*/false);
        plan.target.label = device.path;
        plan.target.itemCount = 1;
    }
    plan.capabilities = capabilities;
    plan.requestedCategory = requestedCategory;
    plan.dryRun = dryRun;
    plan.createdAt = std::chrono::system_clock::now();

    SanitizationMethod selected;
    if (requestedMethod != SanitizationMethod::NONE) {
        // An explicitly requested method is honoured only if the device supports
        // it and it is permitted for the requested category. It is never adopted
        // on the strength of the operator asking.
        //
        // Previously --method was parsed and then ignored entirely, so
        // "--method crypto-erase" against a device that could not do it produced
        // a plan for a completely different mechanism and reported success. A
        // flag that silently does the opposite of what it says is worse than a
        // missing flag.
        if (requestedMethod == SanitizationMethod::UNSUPPORTED) {
            return Result<SanitizationPlan>::err(
                ErrorCode::INVALID_ARGUMENT,
                "'Unsupported' is not a method that can be requested",
                "Run 'plan <device>' to see what this device supports");
        }
        if (!isMethodSupported(requestedMethod, capabilities)) {
            // The status the device reported is part of the message, not only of
            // the hint: "not supported" and "we could not determine it" are
            // different facts and the operator needs to know which one this is.
            const CapabilityStatus status =
                capabilityStatusFor(requestedMethod, capabilities);
            return Result<SanitizationPlan>::err(
                ErrorCode::NO_SUITABLE_METHOD,
                std::string("The requested method ") + methodToString(requestedMethod) +
                    " is not supported by this device; the device reports that "
                    "capability as " + capabilityToString(status),
                status == CapabilityStatus::UNKNOWN
                    ? "UNKNOWN means this tool could not establish the capability, "
                      "not that the device lacks it. Run 'capabilities <device>' for "
                      "the detail, or 'plan <device>' to let the policy engine choose."
                    : "Run 'capabilities <device>' for the detail, or 'plan <device>' "
                      "to let the policy engine choose.");
        }
        if (requestedCategory != SanitizationCategory::CLEAR &&
            (requestedMethod == SanitizationMethod::OVERWRITE_HOST ||
             requestedMethod == SanitizationMethod::CRYPTO_ERASE_HOST)) {
            return Result<SanitizationPlan>::err(
                ErrorCode::NO_SUITABLE_METHOD,
                std::string("The requested method ") + methodToString(requestedMethod) +
                    " cannot deliver " + categoryToString(requestedCategory) +
                    " assurance",
                "A host-side technique only ever satisfies CLEAR. Requesting Purge "
                "with a host overwrite is refused rather than downgraded, whether the "
                "method was chosen by policy or named on the command line.");
        }
        selected = requestedMethod;
    } else {
        auto methodResult = selectMethod(device, capabilities, requestedCategory);
        if (methodResult.isError()) {
            return Result<SanitizationPlan>::err(methodResult.error());
        }
        selected = methodResult.value();
    }
    plan.selectedMethod = selected;

    if (plan.selectedMethod == SanitizationMethod::UNSUPPORTED) {
        // DESTROY is separated from PURGE because the two failures have nothing
        // to do with each other, and lumping them produced a message that
        // invited a downgrade.
        //
        // DESTROY is not a software operation. This tool does not destroy media,
        // so it has no method to offer and there is no capability the device
        // could report that would change that. Telling the operator to "use
        // --assurance clear" was actively harmful once the local policy could
        // derive DESTROY: it handed them a one-flag bypass of a requirement
        // their own policy had just made. A derived DESTROY is a decision
        // about physical destruction, and the answer is the disposition
        // workflow, not a different level.
        if (requestedCategory == SanitizationCategory::DESTROY) {
            return Result<SanitizationPlan>::err(
                ErrorCode::NO_SUITABLE_METHOD,
                "DESTROY was requested, and this tool cannot perform it: "
                "destruction is a physical process outside what software can do.",
                "Record a destruction disposition instead: the media identity, "
                "who carried it out, when, the method used, and any evidence "
                "reference. Do not substitute a sanitization method for it, and "
                "do not lower the level to get a plan - if DESTROY came from "
                "the local policy, the requirement is to destroy the media, not "
                "to find a way around it. If DESTROY was typed directly and was "
                "not what was meant, say so explicitly with --assurance.");
        }
        if (requestedCategory == SanitizationCategory::PURGE) {
            return Result<SanitizationPlan>::err(
                ErrorCode::NO_SUITABLE_METHOD,
                "PURGE is not available on this device. Use --assurance clear.",
                "The device reports no mechanism that reaches storage the host "
                "cannot see, so a stronger category cannot be claimed. A host "
                "overwrite satisfies clear.");
        }
        return Result<SanitizationPlan>::err(
            ErrorCode::NO_SUITABLE_METHOD,
            "No sanitization method is available for " + device.path + ".",
            "Run 'ledgerase-cli capabilities " + device.path +
                "' to see what the device reports. If everything reads "
                "UNKNOWN, this tool cannot establish a method for it.");
    }

    // The overwrite pass count is part of what will be asked of the device, so
    // an out-of-range value is refused here rather than at execution time, where
    // it would surface as a controller command error after the operator had
    // already confirmed the target. NVMe carries it in a 4-bit field, so 1..15
    // is the entire range of behaviour a controller can be asked for.
    const bool isOverwrite =
        plan.selectedMethod == SanitizationMethod::NVME_OVERWRITE ||
        plan.selectedMethod == SanitizationMethod::ATA_SANITIZE_OVERWRITE ||
        plan.selectedMethod == SanitizationMethod::OVERWRITE_HOST;
    if (isOverwrite && (plan.overwritePassCount < 1 || plan.overwritePassCount > 15)) {
        return Result<SanitizationPlan>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Overwrite pass count " +
                std::to_string(static_cast<unsigned>(plan.overwritePassCount)) +
                " is out of range; the NVMe OWPASS field encodes 1 to 15 passes",
            "Pass a count between 1 and 15");
    }

    plan.rationale = "";
    for (const auto& r : getMethodRationale(plan.selectedMethod, device, capabilities, requestedCategory)) {
        if (!plan.rationale.empty()) plan.rationale += " ";
        plan.rationale += r;
    }

    plan.standardReferences = getStandardReferences(plan.selectedMethod);
    plan.verificationPlan = getVerificationPlan(plan.selectedMethod);
    plan.validationPlan = getValidationPlan(plan.selectedMethod);
    plan.limitations = getLimitations(device, capabilities, plan.selectedMethod);
    plan.risks = getRisks(device, capabilities, plan.selectedMethod);

    // SANICAP bits 7:3 give the maximum number of actions the controller will
    // accept in one Sanitize command, and it is recorded in CapabilityInfo with
    // a comment saying that issuing more than the controller reports is a
    // command error. Nothing checked it. The plan asks for exactly one action,
    // so the check can only fire for a controller that reports fewer than one -
    // which means "cannot sanitize at all" and is refused here rather than
    // discovered when the command comes back with a status code.
    if (device.transport == TransportType::NVME &&
        plan.selectedMethod != SanitizationMethod::NONE &&
        plan.selectedMethod != SanitizationMethod::OVERWRITE_HOST &&
        capabilities.nvmeSanitizeSupported &&
        capabilities.nvmeMaxSanitizeActions == 0) {
        return Result<SanitizationPlan>::err(
            ErrorCode::NO_SUITABLE_METHOD,
            "The controller reports a Sanitize capacity of zero actions, so it "
            "will accept no Sanitize command. Its SANICAP field was read as "
            "supporting sanitization, which cannot both be true.",
            "The SANICAP field and the status of the device disagree. Do not "
            "issue a sanitize command to it. Use a host overwrite, or replace "
            "the drive.");
    }

    plan.alternativesConsidered =
        assessCandidates(device, capabilities, requestedCategory, plan.selectedMethod);

    return Result<SanitizationPlan>::ok(plan);
}

Result<SanitizationMethod> SanitizationPolicyEngine::selectMethod(const DeviceInfo& device,
                                                                   const CapabilityInfo& capabilities,
                                                                   SanitizationCategory category) {
    if (config_.strictMode) {
        for (const auto& rule : config_.rules) {
            if (rule.category == category) {
                for (const auto& method : rule.allowedMethods) {
                    if (isMethodSupported(method, capabilities)) {
                        return Result<SanitizationMethod>::ok(method);
                    }
                }
                if (!config_.allowUnknownCapabilities) {
                    return Result<SanitizationMethod>::err(ErrorCode::NO_SUITABLE_METHOD,
                        "No allowed method supported for category " + categoryToString(category));
                }
            }
        }
    }

    if (device.transport == TransportType::NVME) {
        if (category == SanitizationCategory::PURGE) {
            if (capabilities.nvmeCryptoErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::NVME_CRYPTO_ERASE);
            if (capabilities.nvmeBlockErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::NVME_BLOCK_ERASE);
            if (capabilities.nvmeOverwrite == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::NVME_OVERWRITE);
        }
        if (category == SanitizationCategory::CLEAR) {
            if (capabilities.nvmeBlockErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::NVME_BLOCK_ERASE);
            if (capabilities.nvmeOverwrite == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::NVME_OVERWRITE);
        }
    }

    if (device.transport == TransportType::USB) {
        // USB is decided apart from SATA because a bridge chip sits between the
        // host and the media. Whether a device-level mechanism is reachable at
        // all is established by the capability detector's probe, and the answer
        // arrives as SUPPORTED, UNSUPPORTED or UNKNOWN.
        //
        // The refusal rule is not weakened for USB. PURGE without a verified
        // device-level mechanism is refused, never downgraded to a host
        // overwrite: a bridge that answers an identity request and then drops
        // the sanitize command would otherwise let this tool report a Purge it
        // never performed.
        if (category == SanitizationCategory::PURGE) {
            if (capabilities.ataSanitizeCryptoErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE);
            if (capabilities.ataSanitizeBlockErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE);
            if (capabilities.ataSanitizeOverwrite == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_OVERWRITE);
            if (capabilities.ataEnhancedSecureErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_ENHANCED_SECURE_ERASE);
            if (capabilities.ataSecureErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SECURE_ERASE);
        }
        if (category == SanitizationCategory::CLEAR) {
            if (capabilities.ataSanitizeBlockErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE);
            if (capabilities.ataSanitizeOverwrite == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_OVERWRITE);
            if (capabilities.ataSecureErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SECURE_ERASE);
        }
        // Falls through to the host-overwrite rule below, which accepts CLEAR
        // only. A PURGE request reaches no method here and returns UNSUPPORTED,
        // which createPlan turns into an explicit refusal.
    }

    if (device.transport == TransportType::SATA || device.transport == TransportType::SCSI) {
        if (category == SanitizationCategory::PURGE) {
            if (capabilities.ataEnhancedSecureErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_ENHANCED_SECURE_ERASE);
            if (capabilities.ataSecureErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SECURE_ERASE);
            if (capabilities.ataSanitizeBlockErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE);
            if (capabilities.ataSanitizeCryptoErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE);
            if (capabilities.ataSanitizeOverwrite == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_OVERWRITE);
        }
        if (category == SanitizationCategory::CLEAR) {
            if (capabilities.ataSecureErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SECURE_ERASE);
            if (capabilities.ataSanitizeBlockErase == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE);
            if (capabilities.ataSanitizeOverwrite == CapabilityStatus::SUPPORTED)
                return Result<SanitizationMethod>::ok(SanitizationMethod::ATA_SANITIZE_OVERWRITE);
        }
    }

    // A host-level overwrite only ever satisfies CLEAR.
    //
    // Per NIST SP 800-88 Rev. 2 and CLAUDE.md s11, overwriting the logical
    // block address space is a Clear-level technique: it cannot reach NAND
    // overprovisioning, wear-levelled or retired blocks, so it cannot deliver
    // Purge assurance on solid-state media. Offering it for a PURGE request
    // would be the silent downgrade that s9 forbids, so PURGE without a
    // device-level method is refused rather than downgraded.
    if (category == SanitizationCategory::CLEAR &&
        capabilities.overwriteHost == CapabilityStatus::SUPPORTED &&
        config_.allowHostOverwrite) {
        return Result<SanitizationMethod>::ok(SanitizationMethod::OVERWRITE_HOST);
    }

    return Result<SanitizationMethod>::ok(SanitizationMethod::UNSUPPORTED);
}

CapabilityStatus SanitizationPolicyEngine::capabilityStatusFor(
    SanitizationMethod method, const CapabilityInfo& caps) {
    switch (method) {
        case SanitizationMethod::NVME_BLOCK_ERASE: return caps.nvmeBlockErase;
        case SanitizationMethod::NVME_CRYPTO_ERASE: return caps.nvmeCryptoErase;
        case SanitizationMethod::NVME_OVERWRITE: return caps.nvmeOverwrite;
        case SanitizationMethod::ATA_SECURE_ERASE: return caps.ataSecureErase;
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE: return caps.ataEnhancedSecureErase;
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE: return caps.ataSanitizeBlockErase;
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE: return caps.ataSanitizeCryptoErase;
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE: return caps.ataSanitizeOverwrite;
        case SanitizationMethod::OVERWRITE_HOST: return caps.overwriteHost;
        case SanitizationMethod::CRYPTO_ERASE_HOST: return caps.cryptoEraseHost;
        default: return CapabilityStatus::UNKNOWN;
    }
}

bool SanitizationPolicyEngine::isMethodSupported(SanitizationMethod method, const CapabilityInfo& caps) const {
    switch (method) {
        case SanitizationMethod::NVME_BLOCK_ERASE:
            return caps.nvmeBlockErase == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::NVME_CRYPTO_ERASE:
            return caps.nvmeCryptoErase == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::NVME_OVERWRITE:
            return caps.nvmeOverwrite == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::ATA_SECURE_ERASE:
            return caps.ataSecureErase == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
            return caps.ataEnhancedSecureErase == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
            return caps.ataSanitizeBlockErase == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
            return caps.ataSanitizeCryptoErase == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            return caps.ataSanitizeOverwrite == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::OVERWRITE_HOST:
            return caps.overwriteHost == CapabilityStatus::SUPPORTED;
        case SanitizationMethod::CRYPTO_ERASE_HOST:
            return caps.cryptoEraseHost == CapabilityStatus::SUPPORTED;
        default:
            return false;
    }
}

std::vector<std::string> SanitizationPolicyEngine::getMethodRationale(SanitizationMethod method,
                                                                        const DeviceInfo& device [[maybe_unused]],
                                                                        const CapabilityInfo& capabilities [[maybe_unused]],
                                                                        SanitizationCategory category) {
    std::vector<std::string> rationale;

    std::string methodStr = methodToString(method);
    std::string catStr = categoryToString(category);

    rationale.push_back("Selected " + methodStr + " for " + catStr + " category sanitization.");

    switch (method) {
        case SanitizationMethod::NVME_CRYPTO_ERASE:
            rationale.push_back("Device reports support for NVMe Crypto Erase via Sanitize command.");
            rationale.push_back("Cryptographic erasure invalidates the encryption key, rendering all data unreadable.");
            break;
        case SanitizationMethod::NVME_BLOCK_ERASE:
            rationale.push_back("Device reports support for NVMe Block Erase via Sanitize command.");
            rationale.push_back("Block erase instructs the controller to erase all user-accessible blocks.");
            break;
        case SanitizationMethod::NVME_OVERWRITE:
            rationale.push_back("Device reports support for NVMe Overwrite via Sanitize command.");
            rationale.push_back("Controller performs overwrite pattern(s) on all user-accessible blocks.");
            break;
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
            rationale.push_back("Device supports ATA Enhanced Secure Erase.");
            rationale.push_back("Vendor-specific enhanced erase pattern applied to all user-accessible areas.");
            break;
        case SanitizationMethod::ATA_SECURE_ERASE:
            rationale.push_back("Device supports ATA Secure Erase.");
            rationale.push_back("Standard secure erase command applied to user-accessible areas.");
            break;
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
            rationale.push_back("Device supports ATA Sanitize Block Erase.");
            rationale.push_back("Block erase per ATA Sanitize command set.");
            break;
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
            rationale.push_back("Device supports ATA Sanitize Crypto Erase.");
            rationale.push_back("Cryptographic erasure per ATA Sanitize command set.");
            break;
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            rationale.push_back("Device supports ATA Sanitize Overwrite.");
            rationale.push_back("Overwrite pattern(s) per ATA Sanitize command set.");
            break;
        case SanitizationMethod::OVERWRITE_HOST:
            rationale.push_back("Host-managed overwrite selected.");
            rationale.push_back("This is a CLEAR-level technique: it rewrites only the logical block address space visible to the host.");
            rationale.push_back("It cannot reach NAND overprovisioning, wear-levelled, spare or retired blocks, and is therefore not valid for PURGE.");
            if (device.transport == TransportType::USB) {
                rationale.push_back("Selected for USB media because no device-level mechanism could be confirmed through the bridge, and a host overwrite is the only technique this tool can both perform and evidence on that path.");
            }
            break;
        default:
            rationale.push_back("No suitable method could be determined.");
            break;
    }

    return rationale;
}

std::vector<std::string> SanitizationPolicyEngine::getStandardReferences(SanitizationMethod method) {
    std::vector<std::string> refs;
    refs.push_back("NIST SP 800-88 Rev. 2");

    switch (method) {
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
            refs.push_back("NVMe Base Specification (Sanitize Command)");
            refs.push_back("IEEE 2883-2022");
            break;
        case SanitizationMethod::ATA_SECURE_ERASE:
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            refs.push_back("ACS-4 / ATA8-ACS (Security Feature Set, Sanitize Feature Set)");
            refs.push_back("IEEE 2883-2022");
            break;
        case SanitizationMethod::OVERWRITE_HOST:
            refs.push_back("NIST SP 800-88 Rev. 2 (Clear - Overwrite)");
            break;
        default:
            break;
    }
    return refs;
}

std::vector<std::string> SanitizationPolicyEngine::getVerificationPlan(SanitizationMethod method) {
    std::vector<std::string> plan;
    plan.push_back("Verify device-reported completion status");
    plan.push_back("Check device status registers for errors");

    switch (method) {
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
            plan.push_back("Poll NVMe Sanitize Status log for completion");
            plan.push_back("Verify sanitize operation status field indicates success");
            break;
        case SanitizationMethod::ATA_SECURE_ERASE:
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            plan.push_back("Poll ATA Sanitize Status for completion");
            plan.push_back("Verify no error bits set in status register");
            break;
        case SanitizationMethod::OVERWRITE_HOST:
            plan.push_back("Verify write completion and flush");
            plan.push_back("Read back sampled sectors and confirm the written pattern");
            plan.push_back("Record the sample locations and the fraction of the "
                           "device they cover, so the scope of the evidence is explicit");
            break;
        default:
            break;
    }
    return plan;
}

std::vector<std::string> SanitizationPolicyEngine::getValidationPlan(SanitizationMethod method) {
    std::vector<std::string> plan;
    plan.push_back("Validate device-reported success against requested assurance level");
    plan.push_back("Confirm no errors reported during execution");
    plan.push_back("Document known limitations of the method");

    switch (method) {
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
            plan.push_back("Accept device-reported completion as evidence");
            plan.push_back("Note: Host cannot verify controller-managed areas (overprovisioning, retired blocks)");
            break;
        case SanitizationMethod::OVERWRITE_HOST:
            plan.push_back("Accept overwrite completion as Clear-level evidence only");
            plan.push_back("Note: Cannot verify overprovisioned or controller-managed areas");
            break;
        default:
            break;
    }
    return plan;
}

LimitationSet SanitizationPolicyEngine::getLimitations(const DeviceInfo& device,
                                                        const CapabilityInfo& capabilities,
                                                        SanitizationMethod method) {
    LimitationSet limitations;

    if (device.transport == TransportType::NVME) {
        limitations.add(LimitationId::HOST_SCOPE_ONLY);
        limitations.add(LimitationId::DEVICE_SELF_REPORT);
        if (method == SanitizationMethod::NVME_CRYPTO_ERASE) {
            limitations.add(LimitationId::CRYPTO_ERASE_KEYS_ONLY);
            limitations.add(LimitationId::CRYPTO_ERASE_NEEDS_FDE);
        }
    }

    if (device.transport == TransportType::SATA || device.transport == TransportType::USB) {
        limitations.add(LimitationId::HOST_SCOPE_ONLY);
        limitations.add(LimitationId::DEVICE_SELF_REPORT);
        if (method == SanitizationMethod::OVERWRITE_HOST) {
            limitations.add(LimitationId::HOST_SCOPE_ONLY);
            limitations.add(LimitationId::CLEAR_ONLY);
        }
    }

    if (method == SanitizationMethod::OVERWRITE_HOST) {
        limitations.add(LimitationId::CLEAR_ONLY);
        limitations.add(LimitationId::CLEAR_ONLY);
    }

    // merge() keeps IDs unique across the two sources, so a capability fact
    // and a plan fact that say the same thing collapse to one entry.
    limitations.merge(capabilities.limitations);

    return limitations;
}

std::vector<MethodAssessment> SanitizationPolicyEngine::assessCandidates(
    const DeviceInfo& device,
    const CapabilityInfo& capabilities,
    SanitizationCategory category,
    SanitizationMethod selected) {

    // Ordered from the strongest device-level mechanism downwards, so the
    // record reads as a descending order of preference.
    static const std::vector<SanitizationMethod> kCandidates = {
        SanitizationMethod::NVME_CRYPTO_ERASE,
        SanitizationMethod::NVME_BLOCK_ERASE,
        SanitizationMethod::NVME_OVERWRITE,
        SanitizationMethod::ATA_ENHANCED_SECURE_ERASE,
        SanitizationMethod::ATA_SECURE_ERASE,
        SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE,
        SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE,
        SanitizationMethod::ATA_SANITIZE_OVERWRITE,
        SanitizationMethod::CRYPTO_ERASE_HOST,
        SanitizationMethod::OVERWRITE_HOST,
    };

    std::vector<MethodAssessment> assessments;
    assessments.reserve(kCandidates.size());

    for (const SanitizationMethod method : kCandidates) {
        MethodAssessment assessment;
        assessment.method = method;
        assessment.selected = (method == selected);
        assessment.deviceSupported = isMethodSupported(method, capabilities);

        // A method that does not belong to this device's transport is not a
        // real candidate; it is recorded as such rather than omitted, so the
        // bundle shows the full decision space.
        const bool transportApplies =
            (method == SanitizationMethod::NVME_BLOCK_ERASE ||
             method == SanitizationMethod::NVME_CRYPTO_ERASE ||
             method == SanitizationMethod::NVME_OVERWRITE)
                ? device.transport == TransportType::NVME
                : (method == SanitizationMethod::ATA_SECURE_ERASE ||
                   method == SanitizationMethod::ATA_ENHANCED_SECURE_ERASE ||
                   method == SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE ||
                   method == SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE ||
                   method == SanitizationMethod::ATA_SANITIZE_OVERWRITE)
                    ? (device.transport == TransportType::SATA ||
                       device.transport == TransportType::SCSI ||
                       device.transport == TransportType::USB)
                    : true;

        assessment.permittedByPolicy = true;
        std::string reason;

        if (!transportApplies) {
            assessment.permittedByPolicy = false;
            // For a file or an image there is no bus, no device interface and
            // no controller to ask, so "the interface is Unknown" is not a
            // fact about the target - it is a fact about a question that was
            // never meaningful. Saying so anyway reads as a capability gap in
            // something that has no capabilities.
            const bool isMedia =
                device.transport == TransportType::UNKNOWN &&
                DeviceManager::isDiskImage(device.path);
            if (isMedia) {
                reason =
                    "Not applicable: this is a file, not a device. A " +
                    std::string(method == SanitizationMethod::OVERWRITE_HOST ||
                                        method == SanitizationMethod::CRYPTO_ERASE_HOST
                                    ? "host-side"
                                    : "device-level") +
                    " mechanism needs a device.";
            } else {
                reason = "Not applicable: device interface is " +
                         transportToString(device.transport) + ", this is a " +
                         (method == SanitizationMethod::OVERWRITE_HOST ||
                                  method == SanitizationMethod::CRYPTO_ERASE_HOST
                              ? "host-side"
                              : "device-level") +
                         " mechanism";
            }
        } else if (!assessment.deviceSupported) {
            const CapabilityStatus status = capabilityStatusFor(method, capabilities);
            reason = "Device does not report support (" + capabilityToString(status) + ")";
        } else if (method == SanitizationMethod::OVERWRITE_HOST &&
                   category != SanitizationCategory::CLEAR) {
            // Host overwrite of the logical block address space cannot deliver
            // Purge or Destroy assurance on solid-state media.
            assessment.permittedByPolicy = false;
            reason = "Host overwrite is a Clear-level technique; it cannot deliver " +
                     categoryToString(category) +
                     " assurance because it cannot reach controller-managed areas";
        } else if (method == SanitizationMethod::CRYPTO_ERASE_HOST &&
                   !config_.allowHostCryptoErase) {
            assessment.permittedByPolicy = false;
            reason = "Host-managed cryptographic erase is not enabled by policy";
        } else if (method == SanitizationMethod::OVERWRITE_HOST &&
                   !config_.allowHostOverwrite) {
            assessment.permittedByPolicy = false;
            reason = "Host overwrite is not enabled by policy";
        } else if (assessment.selected) {
            reason = "Selected: strongest available mechanism for " +
                     categoryToString(category);
        } else {
            // Available but outranked. Say which mechanism won, otherwise the
            // record leaves the reader guessing why a usable method was passed
            // over.
            reason = "Available, but not selected: " + methodToString(selected) +
                     " provides stronger assurance for " +
                     categoryToString(category);
        }

        assessment.reason = std::move(reason);
        assessments.push_back(std::move(assessment));
    }

    return assessments;
}

std::vector<std::string> SanitizationPolicyEngine::getRisks(const DeviceInfo& device,
                                                             const CapabilityInfo& capabilities,
                                                             SanitizationMethod method) {
    std::vector<std::string> risks;

    if (device.systemDisk || device.bootDisk) {
        risks.push_back("CRITICAL: Target is system/boot disk - sanitization will render system unbootable.");
    }
    if (device.mounted) {
        risks.push_back("Target has mounted partitions - data loss on mounted filesystems.");
    }
    if (device.readOnly) {
        risks.push_back("Device is read-only - sanitization will fail.");
    }

    if (method == SanitizationMethod::NVME_CRYPTO_ERASE && capabilities.encryptionStatus == EncryptionStatus::UNKNOWN) {
        risks.push_back("Encryption status unknown - Crypto Erase effectiveness cannot be verified.");
    }

    // A partition target is legitimate, but it is not the same operation as
    // wiping the disk, and the two are easy to confuse at a glance. Stated as a
    // risk so it appears in the plan and in the certificate.
    if (platform::linux::looksLikePartition(device.path)) {
        const std::string disk = platform::linux::containingWholeDisk(device.path);
        risks.push_back(
            "TARGET IS A PARTITION, NOT A WHOLE DISK. Only " + device.path +
            " would be sanitized" +
            (disk.empty() ? std::string("; the containing disk could not be identified")
                          : "; the containing disk is " + disk +
                                " and would be left intact") +
            ". If the intent was to sanitize the whole disk, stop and re-run "
            "against " + (disk.empty() ? device.path : disk) + ".");
    }

    if (device.transport == TransportType::USB) {
        risks.push_back(
            "USB bridge in the path: a device-level sanitize command may be accepted "
            "and silently dropped. Device-level mechanisms are only selected for USB "
            "when positively confirmed supported.");
        risks.push_back(
            "Removable media: this device may have been connected to other systems. "
            "Confirm the disposition of every copy before treating this as Purge.");
    }

    return risks;
}

PolicyConfig SanitizationPolicyEngine::createDefaultPolicy() {
    PolicyConfig config;
    config.strictMode = false;
    config.allowUnknownCapabilities = false;
    config.allowHostOverwrite = true;
    config.allowHostCryptoErase = false;

    // The table below is not consulted unless strictMode is true, and it is
    // false here: the ladder in selectMethod() is the decision path for the
    // shipped binary. The table is kept as the declarative form an operator can
    // switch on with createStrictPolicy(), and it is tested there.
    PolicyRule purgeRule;
    purgeRule.category = SanitizationCategory::PURGE;
    purgeRule.allowedMethods = {
        SanitizationMethod::NVME_CRYPTO_ERASE,
        SanitizationMethod::NVME_BLOCK_ERASE,
        SanitizationMethod::NVME_OVERWRITE,
        SanitizationMethod::ATA_ENHANCED_SECURE_ERASE,
        SanitizationMethod::ATA_SECURE_ERASE,
        SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE,
        SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE,
        SanitizationMethod::ATA_SANITIZE_OVERWRITE
    };
    config.rules.push_back(purgeRule);

    PolicyRule clearRule;
    clearRule.category = SanitizationCategory::CLEAR;
    clearRule.allowedMethods = {
        SanitizationMethod::NVME_BLOCK_ERASE,
        SanitizationMethod::NVME_OVERWRITE,
        SanitizationMethod::ATA_SECURE_ERASE,
        SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE,
        SanitizationMethod::ATA_SANITIZE_OVERWRITE,
        SanitizationMethod::OVERWRITE_HOST
    };
    config.rules.push_back(clearRule);

    return config;
}

PolicyConfig SanitizationPolicyEngine::createStrictPolicy() {
    PolicyConfig config = createDefaultPolicy();
    config.strictMode = true;
    config.allowHostOverwrite = false;
    config.allowUnknownCapabilities = false;

    for (auto& rule : config.rules) {
        rule.allowedMethods.erase(
            std::remove(rule.allowedMethods.begin(), rule.allowedMethods.end(),
                       SanitizationMethod::OVERWRITE_HOST),
            rule.allowedMethods.end());
    }
    return config;
}

PolicyConfig SanitizationPolicyEngine::createPermissivePolicy() {
    PolicyConfig config = createDefaultPolicy();
    config.strictMode = false;
    config.allowUnknownCapabilities = true;
    config.allowHostOverwrite = true;
    config.allowHostCryptoErase = true;
    return config;
}

class SanitizationPlanner::Impl {
public:
    Impl(SanitizationPolicyEngine& e) : engine(e) {}
    SanitizationPolicyEngine& engine;
};

SanitizationPlanner::SanitizationPlanner(SanitizationPolicyEngine& engine)
    : pImpl_(std::make_unique<Impl>(engine)), engine_(engine) {}
SanitizationPlanner::~SanitizationPlanner() = default;

Result<SanitizationPlan> SanitizationPlanner::plan(const DeviceInfo& device,
                                                   const CapabilityInfo& capabilities,
                                                   SanitizationCategory category,
                                                   bool dryRun,
                                                   SanitizationMethod requestedMethod) {
    return engine_.createPlan(device, capabilities, category, dryRun, requestedMethod);
}

namespace {

// First sentence of a rationale, which is written as several.
std::string firstSentence(const std::string& text) {
    const std::size_t stop = text.find(". ");
    if (stop == std::string::npos) {
        return text;
    }
    return text.substr(0, stop + 1);
}

bool isDeviceLevelMethod(SanitizationMethod method) {
    switch (method) {
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
        case SanitizationMethod::ATA_SECURE_ERASE:
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
        case SanitizationMethod::CRYPTO_ERASE_HOST:
            return true;
        default:
            return false;
    }
}

// A rule-out worth stating is one whose reason the reader could not have
// guessed from the device line alone.
//
// On a USB device, "no device-level mechanism" follows from the transport and
// needs no explanation. On a device whose interface was never established, it
// is the single most important thing the plan has to say, so it is stated.
bool ruleOutNeedsExplaining(const SanitizationPlan& plan) {
    return plan.device.transport == TransportType::UNKNOWN;
}

std::string ruleOutSummary(const SanitizationPlan& plan) {
    if (!ruleOutNeedsExplaining(plan)) {
        return {};
    }
    std::vector<std::string> names;
    for (const MethodAssessment& candidate : plan.alternativesConsidered) {
        if (candidate.selected || !isDeviceLevelMethod(candidate.method)) {
            continue;
        }
        names.push_back(methodToString(candidate.method));
    }
    if (names.empty()) {
        return {};
    }
    // Naming all eight individually is as long as the table it replaces, so
    // the families are named and the count carries the detail.
    bool nvme = false;
    bool ataSecure = false;
    bool ataSanitize = false;
    for (const std::string& name : names) {
        nvme = nvme || name.find("NVMe") != std::string::npos;
        ataSecure = ataSecure || name.find("Secure Erase") != std::string::npos;
        ataSanitize =
            ataSanitize || name.find("Sanitize") != std::string::npos ||
            name.find("Crypto Erase") != std::string::npos;
    }
    std::string families;
    if (nvme) {
        families = "NVMe";
    }
    if (ataSecure) {
        families += families.empty() ? "ATA secure erase" : ", ATA secure erase";
    }
    if (ataSanitize) {
        families += families.empty() ? "ATA sanitize" : ", ATA sanitize";
    }
    // A file is not a device, so "an interface this device does not report" is
    // a question that was never meaningful. The rule-out is still worth stating
    // - it is why the selected method is a host write - but the reason has to be
    // about what the target actually is.
    const bool isMedia =
        plan.device.transport == TransportType::UNKNOWN &&
        DeviceManager::isDiskImage(plan.device.path);
    return "Ruled out: " + std::to_string(names.size()) +
           " device-level methods (" + families + ")" +
           (isMedia ? " need a device, and the target is a file"
                    : " need an interface this device does not report");
}

} // namespace

Result<std::string> SanitizationPlanner::generatePlanReport(const SanitizationPlan& plan,
                                                            bool verbose) {
    if (!verbose) {
        std::ostringstream short_oss;
        short_oss << "Sanitization plan\n";
        // Integer gigabytes made every test image read "0 GB", which is
        // accurate and useless. Below a gibibyte the size is shown in MiB.
        const uint64_t gib = 1024ull * 1024 * 1024;
        std::string size =
            plan.device.capacityBytes >= gib
                ? std::to_string(plan.device.capacityBytes / gib) + " GB"
                : std::to_string(plan.device.capacityBytes / (1024 * 1024)) + " MB";
        short_oss << "  Device:     " << plan.device.path << "  ("
                  << plan.device.model << ", " << plan.device.serial << ", "
                  << size << ", "
                  << transportToString(plan.device.transport) << ")\n";
        short_oss << "  Requested:  "
                  << categoryToString(plan.requestedCategory) << "\n";
        // Where the level came from, on the same screen as the level. The three
        // level names are the standard's, so a bare "PURGE" is ambiguous about
        // whether NIST required it or the organisation's policy did - and the
        // answer changes what an assessor is being asked to check. This line is
        // why the distinction survives into the report.
        {
            const auto& b = plan.assuranceBasis;
            if (b.source == "local-policy") {
                short_oss << "  Basis:      local policy (input: "
                          << securityCategorizationToString(b.categorization)
                          << " confidentiality / reuse="
                          << triStateToString(b.reuseMedia)
                          << " / leaving-org="
                          << triStateToString(b.leavingOrgControl)
                          << ")\n";
            } else if (b.source == "operator") {
                short_oss << "  Basis:      selected by the operator "
                             "(--assurance), overriding local policy\n";
            } else {
                short_oss << "  Basis:      default; no --assurance and no "
                             "complete policy input\n";
            }
            if (b.source != "default" && !b.rationale.empty()) {
                short_oss << "  Why that:   " << firstSentence(b.rationale)
                          << "\n";
            }
        }
        short_oss << "  Method:     " << methodToString(plan.selectedMethod);
        if (plan.selectedMethod == SanitizationMethod::OVERWRITE_HOST ||
            plan.selectedMethod == SanitizationMethod::NVME_OVERWRITE ||
            plan.selectedMethod == SanitizationMethod::ATA_SANITIZE_OVERWRITE) {
            short_oss << ", " << static_cast<unsigned>(plan.overwritePassCount)
                      << (plan.overwritePassCount == 1 ? " pass" : " passes");
        }
        short_oss << "\n";
        short_oss << "  Why:        " << firstSentence(plan.rationale) << "\n";
        if (!plan.risks.empty()) {
            short_oss << "  Risk:       " << firstSentence(plan.risks.front())
                      << "\n";
        }
        const std::string ruledOut = ruleOutSummary(plan);
        if (!ruledOut.empty()) {
            short_oss << "  " << ruledOut << "\n";
        }
        short_oss << "  Limits:     " << plan.limitations.size()
                  << " recorded (--verbose lists them)\n";
        // The plan's verification steps are five lines of procedure. The short
        // form names what will be checked, not the order.
        short_oss << "  Verify:     device-reported completion and "
                     "read-back of sampled sectors";
        if (plan.verificationPlan.size() > 2) {
            short_oss << " (" << plan.verificationPlan.size() << " steps)";
        }
        short_oss << "\n";
        if (!plan.standardReferences.empty()) {
            short_oss << "  Standard:   " << plan.standardReferences.front()
                      << "\n";
        }
        // The level names (clear/purge/destroy) are the standard's, so the
        // "Standard:" line above sits directly under a level this tool chose.
        // Without this the two lines together read as "the standard requires
        // this level", which is the one claim that must never be made here.
        if (plan.assuranceBasis.source == "local-policy") {
            short_oss << "              (the level names are the standard's; the "
                         "level itself was chosen by\n"
                         "               local policy, which is this project's "
                         "own design and not something the\n"
                         "               standard specifies - see "
                         "docs/STANDARDS.md)\n";
        }
        return Result<std::string>::ok(short_oss.str());
    }

    std::ostringstream oss;
    oss << "=== SANITIZATION PLAN ===\n\n";
    oss << "Job ID: " << plan.jobId << "\n";
    oss << "Device: " << plan.device.path << " (" << plan.device.model << " " << plan.device.serial << ")\n";
    oss << "Capacity: " << (plan.device.capacityBytes / (1024*1024*1024)) << " GB\n";
    oss << "Transport: " << transportToString(plan.device.transport) << "\n";
    oss << "Media Type: " << mediaTypeToString(plan.device.mediaType) << "\n\n";

    oss << "Requested Category: " << categoryToString(plan.requestedCategory) << "\n";
    oss << "Selected Method: " << methodToString(plan.selectedMethod) << "\n";
    if (plan.selectedMethod == SanitizationMethod::NVME_OVERWRITE ||
        plan.selectedMethod == SanitizationMethod::ATA_SANITIZE_OVERWRITE) {
        oss << "Overwrite Passes: " << static_cast<unsigned>(plan.overwritePassCount)
            << " (encoded in the 4-bit OWPASS field; 1-15)\n";
    } else if (plan.selectedMethod == SanitizationMethod::OVERWRITE_HOST) {
        // Stated for the host overwrite too, because the number of passes is
        // something the operator chose and the plan is where they should see
        // what it will be. The controller-level methods get it free from
        // OWPASS; this one has to be told.
        oss << "Overwrite Passes: " << static_cast<unsigned>(plan.overwritePassCount)
            << " (full passes over the host-visible address space; 1-15)\n";
    }
    oss << "\n";

    oss << "Rationale:\n" << plan.rationale << "\n\n";

    oss << "Standard References:\n";
    for (const auto& ref : plan.standardReferences) {
        oss << "  - " << ref << "\n";
    }
    oss << "\n";

    oss << "Verification Plan:\n";
    for (const auto& step : plan.verificationPlan) {
        oss << "  - " << step << "\n";
    }
    oss << "\n";

    oss << "Validation Plan:\n";
    for (const auto& step : plan.validationPlan) {
        oss << "  - " << step << "\n";
    }
    oss << "\n";

    oss << "Limitations:\n";
    for (const auto& lim : plan.limitations) {
        oss << "  - " << lim << "\n";   // rendered: "ID: text"
    }
    oss << "\n";

    oss << "Risks:\n";
    for (const auto& risk : plan.risks) {
        oss << "  - " << risk << "\n";
    }
    oss << "\n";

    // The full decision space. An assessor should be able to see which
    // mechanisms were available and why the weaker ones were not used, rather
    // than having to accept a single asserted rationale.
    if (!plan.alternativesConsidered.empty()) {
        oss << "Methods considered:\n";
        for (const auto& candidate : plan.alternativesConsidered) {
            oss << "  " << (candidate.selected ? "[SELECTED] " : "[         ] ")
                << std::left << std::setw(30) << methodToString(candidate.method)
                << candidate.reason << "\n";
        }
        oss << "\n";
    }

    if (plan.dryRun) {
        oss << "*** DRY RUN MODE - NO DESTRUCTIVE ACTIONS WILL BE PERFORMED ***\n";
    }

    return Result<std::string>::ok(oss.str());
}

void SanitizationPlanner::applyOverwritePassCount(SanitizationPlan& plan,
                                                 uint8_t passCount) {
    const bool isOverwrite =
        plan.selectedMethod == SanitizationMethod::NVME_OVERWRITE ||
        plan.selectedMethod == SanitizationMethod::ATA_SANITIZE_OVERWRITE ||
        plan.selectedMethod == SanitizationMethod::OVERWRITE_HOST;

    plan.overwritePassCount = passCount;

    // NIST SP 800-88 Rev. 2 3.1.1: "For certain ISM (e.g., SSDs with
    // overprovisioning), such practices should be avoided as very little
    // confidentiality protection is achieved." That is about multi-pass
    // overwrite on flash.
    //
    // Attached, not refused: the operator may have a reason the standard does
    // not know about, and the sentence says the practice "should be avoided",
    // not that it achieves nothing. What it must not be is a fact discovered
    // later from a certificate, so it is in the plan, the CLI report and the
    // evidence.
    if (!isOverwrite || passCount <= 1) {
        return;
    }
    if (plan.device.mediaType != MediaType::SSD &&
        plan.device.mediaType != MediaType::HYBRID) {
        return;
    }
    const char* mediaWord =
        plan.device.mediaType == MediaType::SSD ? "SSD" : "hybrid";
    plan.risks.push_back(
        "Multi-pass overwrite (" + std::to_string(static_cast<unsigned>(passCount)) +
        " passes) was requested for " + mediaWord +
        " media. NIST SP 800-88 Rev. 2 3.1.1 states that for ISM such as SSDs "
        "with overprovisioning, multi-pass overwrite 'should be avoided as very "
        "little confidentiality protection is achieved'.");
    plan.risks.push_back(
        "The standard's alternative for additional assurance is a stronger "
        "sanitization method, not more passes: 'If additional assurances are "
        "needed, a more secure sanitization method in the form of purge or "
        "destroy should be used' (3.1.1). A device-level purge technique is the "
        "one to consider on this media.");
    plan.limitations.addText(
        "Multi-pass overwrite on flash is recorded as requested and completed, "
        "but the standard states it should be avoided on ISM with "
        "overprovisioning, where a host cannot address all areas that may hold "
        "the target data. The extra passes do not reach media the host cannot "
        "address.");
}

} // namespace ledgerase
