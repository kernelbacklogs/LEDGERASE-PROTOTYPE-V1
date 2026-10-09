#include "ledgerase/types.hpp"
#include <sstream>
#include <iomanip>

namespace ledgerase {

std::string transportToString(TransportType t) {
    switch (t) {
        case TransportType::SATA: return "SATA";
        case TransportType::NVME: return "NVMe";
        case TransportType::USB: return "USB";
        case TransportType::SCSI: return "SCSI";
        case TransportType::VIRTIO: return "VirtIO";
        case TransportType::MMC: return "MMC/eMMC";
        case TransportType::NVME_OVER_FABRICS: return "NVMe-oF";
        default: return "Unknown";
    }
}

std::string mediaTypeToString(MediaType t) {
    switch (t) {
        case MediaType::HDD: return "HDD";
        case MediaType::SSD: return "SSD";
        case MediaType::HYBRID: return "Hybrid";
        case MediaType::REMOVABLE: return "Removable";
        case MediaType::OPTICAL: return "Optical";
        default: return "Unknown";
    }
}

std::string categoryToString(SanitizationCategory c) {
    switch (c) {
        case SanitizationCategory::CLEAR: return "CLEAR";
        case SanitizationCategory::PURGE: return "PURGE";
        case SanitizationCategory::DESTROY: return "DESTROY";
    }
    return "Unknown";
}

std::string securityCategorizationToString(SecurityCategorization c) {
    switch (c) {
        case SecurityCategorization::UNSET:    return "unset";
        case SecurityCategorization::LOW:      return "Low";
        case SecurityCategorization::MODERATE: return "Moderate";
        case SecurityCategorization::HIGH:     return "High";
    }
    return "unset";
}

std::string triStateToString(TriState t) {
    switch (t) {
        case TriState::UNSET: return "unset";
        case TriState::YES:   return "yes";
        case TriState::NO:    return "no";
    }
    return "unset";
}

// The documented local policy.
//
// Read this before changing a branch below: this function decides a
// sanitization level, and every branch is a judgement about risk, not a
// computation. There is no source that mandates it. NIST SP 800-88 Rev. 2
// defines the three levels (3.1.1, 3.1.2, 3.1.3) and then requires a
// "risk-based decision" (4.3.6) while listing considerations to weigh rather
// than a rule to apply (2.4). The specific mapping below is this project's, and
// every caller is required to say so.
//
// Why these three inputs and not more: they are the ones an operator can answer
// about a specific piece of media without a threat model, and they cover the
// cases where the stronger level is genuinely required. An adversary-capability
// axis and a lifecycle-stage axis would model 4.3.6 more closely, but both
// were available only from a secondary summary here, and a vocabulary that
// cannot be checked against a primary document does not belong in a tool whose
// whole argument is that its claims are checkable.
AssurancePolicyDecision deriveAssuranceTier(SecurityCategorization categorization,
                                            TriState reuseMedia,
                                            TriState leavingOrgControl) {
    AssurancePolicyDecision decision;
    decision.categorization = categorization;
    decision.reuseMedia = reuseMedia;
    decision.leavingOrgControl = leavingOrgControl;

    // Partial input is not a partial decision. "Reuse = yes" alone does not say
    // whether the data is sensitive, and the rule needs both. Returning
    // derived = false makes --assurance govern, which is the honest outcome:
    // the policy declines to answer rather than answering with a default it was
    // not given.
    if (categorization == SecurityCategorization::UNSET ||
        reuseMedia == TriState::UNSET ||
        leavingOrgControl == TriState::UNSET) {
        decision.rationale =
            "Not derived: the policy needs all three of security "
            "categorization, reuse and leaving-organization-control, and at "
            "least one was not supplied. It does not guess the rest.";
        return decision;
    }

    decision.derived = true;
    const std::string cat = securityCategorizationToString(categorization);
    const bool reuse = reuseMedia == TriState::YES;
    const bool leaving = leavingOrgControl == TriState::YES;

    // 1. Media that leaves organizational control cannot be tracked after the
    //    fact, so the only level that is not merely a lower assurance target is
    //    destruction. This outranks everything else, including low sensitivity:
    //    the argument is loss of control, not the content.
    if (leaving) {
        decision.tier = SanitizationCategory::DESTROY;
        decision.rationale =
            "Local policy: media is leaving organizational control, which is a "
            "loss of control the organisation cannot monitor afterwards, so "
            "DESTROY is required regardless of confidentiality (" + cat + ").";
        return decision;
    }

    // 2. High-sensitivity data is destroyed on the strength of its
    //    categorisation alone. The organisation is the only party that can judge
    //    whether high-sensitivity data may exist in a reusable medium, and
    //    leaving that judgement to the operator of the tool would be a way of
    //    not making it. This holds whether or not the medium is reused.
    if (categorization == SecurityCategorization::HIGH) {
        decision.tier = SanitizationCategory::DESTROY;
        decision.rationale =
            "Local policy: security categorization is " + cat +
            ", which is destroyed rather than sanitized for reuse, whether or "
            "not the media is reused.";
        return decision;
    }

    // 3. Not high, and staying in the organisation. The medium is reused, so it
    //    must be sanitized rather than destroyed, and the level follows
    //    sensitivity. MODERATE separates from LOW because they are different
    //    cases, not a matter of degree to be smoothed over: a reused medium
    //    holding low-sensitivity data is the case the standard treats as
    //    acceptable to clear, and moderate is not.
    if (categorization == SecurityCategorization::MODERATE) {
        decision.tier = SanitizationCategory::PURGE;
        decision.rationale =
            "Local policy: security categorization is " + cat +
            " and the media is reused inside the organisation, so PURGE is "
            "required to make recovery of the data infeasible.";
        return decision;
    }

    // 4. Low-sensitivity data that is being reused inside the organisation.
    //    CLEAR is the level the standard's own 4.5.2 discussion treats as
    //    acceptable for low-sensitivity data in a reused medium: the recipient
    //    is the same organisation, and reuse is the whole reason the media is
    //    being sanitized rather than destroyed.
    if (reuse) {
        decision.tier = SanitizationCategory::CLEAR;
        decision.rationale =
            "Local policy: security categorization is " + cat +
            ", the media is reused inside the organisation, and it is not "
            "leaving organizational control, so CLEAR is the required level.";
        return decision;
    }

    // 5. Low-sensitivity data that is not being reused. The medium is not going
    //    anywhere else, so there is no new owner to protect it from, but it is
    //    also not destroyed over low-sensitivity data. PURGE is the middle
    //    answer: strong enough that a discarded medium does not carry a
    //    recoverable record, without destroying stock that the organisation may
    //    still hold. This is the only branch where reuse changes the answer,
    //    and it does so between CLEAR and PURGE, not between PURGE and DESTROY.
    decision.tier = SanitizationCategory::PURGE;
    decision.rationale =
        "Local policy: security categorization is " + cat +
        " and the media is not being reused, so it is not destroyed, but a "
        "discarded medium should not carry a recoverable record; PURGE is the "
        "required level.";
    return decision;
}


std::string methodToString(SanitizationMethod m) {
    switch (m) {
        case SanitizationMethod::NVME_BLOCK_ERASE: return "NVMe Block Erase";
        case SanitizationMethod::NVME_CRYPTO_ERASE: return "NVMe Crypto Erase";
        case SanitizationMethod::NVME_OVERWRITE: return "NVMe Overwrite";
        case SanitizationMethod::ATA_SECURE_ERASE: return "ATA Secure Erase";
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE: return "ATA Enhanced Secure Erase";
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE: return "ATA Sanitize Block Erase";
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE: return "ATA Sanitize Crypto Erase";
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE: return "ATA Sanitize Overwrite";
        case SanitizationMethod::CRYPTO_ERASE_HOST: return "Host Crypto Erase";
        case SanitizationMethod::OVERWRITE_HOST: return "Host Overwrite";
        case SanitizationMethod::UNSUPPORTED: return "Unsupported";
        case SanitizationMethod::DESTROY_MANUAL: return "Manual Destruction";
        default: return "None";
    }
}

std::string capabilityToString(CapabilityStatus c) {
    switch (c) {
        case CapabilityStatus::SUPPORTED: return "SUPPORTED";
        case CapabilityStatus::UNSUPPORTED: return "UNSUPPORTED";
        default: return "UNKNOWN";
    }
}

std::string jobStateToString(JobState s) {
    switch (s) {
        case JobState::DISCOVERING: return "Discovering";
        case JobState::PLANNING: return "Planning";
        case JobState::AWAITING_CONFIRMATION: return "Awaiting Confirmation";
        case JobState::EXECUTING: return "Executing";
        case JobState::MONITORING: return "Monitoring";
        case JobState::VERIFYING: return "Verifying";
        case JobState::VALIDATING: return "Validating";
        case JobState::COMPLETED: return "Completed";
        case JobState::FAILED: return "Failed";
        case JobState::REJECTED: return "Rejected";
        case JobState::BLOCKED: return "Blocked";
        default: return "Unknown";
    }
}

std::string verificationToString(VerificationResult v) {
    switch (v) {
        case VerificationResult::PASS: return "PASS";
        case VerificationResult::FAIL: return "FAIL";
        default: return "INCONCLUSIVE";
    }
}

std::string validationToString(ValidationResult v) {
    switch (v) {
        case ValidationResult::ACCEPTED: return "ACCEPTED";
        case ValidationResult::REJECTED: return "REJECTED";
        case ValidationResult::ACCEPTED_WITH_LIMITATIONS: return "ACCEPTED_WITH_LIMITATIONS";
        default: return "INCONCLUSIVE";
    }
}

std::string encryptionToString(EncryptionStatus e) {
    switch (e) {
        case EncryptionStatus::ENCRYPTED: return "ENCRYPTED";
        case EncryptionStatus::NOT_ENCRYPTED: return "NOT_ENCRYPTED";
        default: return "UNKNOWN";
    }
}

} // namespace ledgerase