#pragma once

#include "ledgerase/safety.hpp"

// nlohmann::json serialization adapters for the sanitizer domain types.
//
// Enums are serialized by their stable uppercase string form (never by ordinal)
// so that a stored audit record remains readable and comparable across builds
// that add enum members. Timestamps are serialized as RFC 3339 / ISO 8601 UTC
// strings with second precision, which is what an auditor needs, and are parsed
// back leniently.

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>

namespace ledgerase {

// ---------------------------------------------------------------------------
// LimitationSet <-> JSON
//
// A set writes as an array of objects carrying the ID, so a reader can tell
// which fact a line refers to. Bundles written by schema 1 wrote an array of
// plain strings; from_json still accepts that shape, so old bundles keep
// loading and keep verifying.
// ---------------------------------------------------------------------------

// nlohmann only discovers to_json in the two-argument form, so this writes
// into j rather than returning a json by value.
inline void to_json(nlohmann::json& j, const LimitationSet& set) {
    j = nlohmann::json::array();
    for (const LimitationEntry& entry : set.entries()) {
        nlohmann::json object;
        if (entry.idText.empty()) {
            object["id"] = nullptr;
            object["text"] = entry.text;
        } else {
            object["id"] = entry.idText;
            object["text"] = entry.text;
            object["group"] = entry.group;
        }
        if (!entry.detail.empty()) {
            object["detail"] = entry.detail;
        }
        j.push_back(std::move(object));
    }
}

inline void from_json(const nlohmann::json& j, LimitationSet& set) {
    if (!j.is_array()) {
        return;
    }
    for (const nlohmann::json& item : j) {
        if (item.is_string()) {
            // Schema 1: a bare sentence. No ID to recover, so it is kept as
            // text rather than guessed at.
            set.addText(item.get<std::string>());
            continue;
        }
        if (!item.is_object()) {
            continue;
        }
        const std::string text =
            item.value("text", std::string());
        const std::string detail = item.value("detail", std::string());
        const bool hasId = item.contains("id") && item.at("id").is_string();
        if (hasId) {
            const std::string idText = item.at("id").get<std::string>();
            for (const LimitationEntry& candidate : knownLimitationEntries()) {
                if (candidate.idText == idText) {
                    set.add(candidate.id, detail);
                    break;
                }
            }
            if (!set.texts().empty()) {
                continue;
            }
        }
        if (!text.empty()) {
            set.addText(text);
        }
    }
}


// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

inline std::string formatTimestamp(std::chrono::system_clock::time_point tp) {
    if (tp == std::chrono::system_clock::time_point{}) {
        return {};
    }
    const auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    if (gmtime_r(&t, &tm) == nullptr) {
        return {};
    }
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        return {};
    }
    return std::string(buf);
}

inline std::chrono::system_clock::time_point parseTimestamp(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    std::tm tm{};
    if (strptime(s.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm) == nullptr) {
        return {};
    }
    return std::chrono::system_clock::from_time_t(timegm(&tm));
}

// ---------------------------------------------------------------------------
// Enum adapters
// ---------------------------------------------------------------------------

#define LEDGERASE_JSON_ENUM(EnumType, ToStrFn, FromStrTable)                 \
    inline void to_json(nlohmann::json& j, EnumType v) { j = ToStrFn(v); }    \
    inline void from_json(const nlohmann::json& j, EnumType& v) {            \
        const auto s = j.is_string() ? j.get<std::string>() : std::string{};  \
        v = FromStrTable(s);                                                  \
    }

LEDGERASE_JSON_ENUM(TransportType, transportToString,
    ([](const std::string& s) -> TransportType {
        if (s == "SATA") return TransportType::SATA;
        if (s == "NVMe") return TransportType::NVME;
        if (s == "USB") return TransportType::USB;
        if (s == "SCSI") return TransportType::SCSI;
        if (s == "VirtIO") return TransportType::VIRTIO;
        if (s == "MMC/eMMC") return TransportType::MMC;
        if (s == "NVMe-oF") return TransportType::NVME_OVER_FABRICS;
        return TransportType::UNKNOWN;
    }))

LEDGERASE_JSON_ENUM(MediaType, mediaTypeToString,
    ([](const std::string& s) -> MediaType {
        if (s == "HDD") return MediaType::HDD;
        if (s == "SSD") return MediaType::SSD;
        if (s == "Hybrid") return MediaType::HYBRID;
        if (s == "Removable") return MediaType::REMOVABLE;
        if (s == "Optical") return MediaType::OPTICAL;
        return MediaType::UNKNOWN;
    }))

// The two types the local assurance policy uses for its inputs. They appear in
// the evidence bundle so the inputs a level was derived from are readable, and
// they are strings in the record rather than these enums, so the schema does not
// gain a dependency on the policy's vocabulary. The adapters exist for the plan
// document, which does use the enums.
NLOHMANN_JSON_SERIALIZE_ENUM(ledgerase::SecurityCategorization, {
    {ledgerase::SecurityCategorization::UNSET, "unset"},
    {ledgerase::SecurityCategorization::LOW, "Low"},
    {ledgerase::SecurityCategorization::MODERATE, "Moderate"},
    {ledgerase::SecurityCategorization::HIGH, "High"},
})

NLOHMANN_JSON_SERIALIZE_ENUM(ledgerase::TriState, {
    {ledgerase::TriState::UNSET, "unset"},
    {ledgerase::TriState::YES, "yes"},
    {ledgerase::TriState::NO, "no"},
})

// An unrecognised category string becomes PURGE, not CLEAR.
//
// The default used to be CLEAR, which meant a corrupted or truncated record
// read back as "a Clear-level sanitization was requested and accepted" - the
// weaker category, presented as the weaker *requirement*, which is the direction
// that hides a shortfall. PURGE is the conservative default because a plan that
// claims Purge and delivered less will fail its own validation, whereas one that
// claims Clear will not be re-examined.
LEDGERASE_JSON_ENUM(SanitizationCategory, categoryToString,
    ([](const std::string& s) -> SanitizationCategory {
        if (s == "CLEAR") return SanitizationCategory::CLEAR;
        if (s == "DESTROY") return SanitizationCategory::DESTROY;
        return SanitizationCategory::PURGE;
    }))

LEDGERASE_JSON_ENUM(CapabilityStatus, capabilityToString,
    ([](const std::string& s) -> CapabilityStatus {
        if (s == "SUPPORTED") return CapabilityStatus::SUPPORTED;
        if (s == "UNSUPPORTED") return CapabilityStatus::UNSUPPORTED;
        return CapabilityStatus::UNKNOWN;
    }))

LEDGERASE_JSON_ENUM(JobState, jobStateToString,
    ([](const std::string& s) -> JobState {
        if (s == "Discovering") return JobState::DISCOVERING;
        if (s == "Planning") return JobState::PLANNING;
        if (s == "Awaiting Confirmation") return JobState::AWAITING_CONFIRMATION;
        if (s == "Executing") return JobState::EXECUTING;
        if (s == "Monitoring") return JobState::MONITORING;
        if (s == "Verifying") return JobState::VERIFYING;
        if (s == "Validating") return JobState::VALIDATING;
        if (s == "Completed") return JobState::COMPLETED;
        if (s == "Failed") return JobState::FAILED;
        if (s == "Rejected") return JobState::REJECTED;
        if (s == "Blocked") return JobState::BLOCKED;
        return JobState::UNKNOWN;
    }))

LEDGERASE_JSON_ENUM(VerificationResult, verificationToString,
    ([](const std::string& s) -> VerificationResult {
        if (s == "PASS") return VerificationResult::PASS;
        if (s == "FAIL") return VerificationResult::FAIL;
        return VerificationResult::INCONCLUSIVE;
    }))

LEDGERASE_JSON_ENUM(ValidationResult, validationToString,
    ([](const std::string& s) -> ValidationResult {
        if (s == "ACCEPTED") return ValidationResult::ACCEPTED;
        if (s == "REJECTED") return ValidationResult::REJECTED;
        if (s == "ACCEPTED_WITH_LIMITATIONS")
            return ValidationResult::ACCEPTED_WITH_LIMITATIONS;
        return ValidationResult::INCONCLUSIVE;
    }))

LEDGERASE_JSON_ENUM(EncryptionStatus, encryptionToString,
    ([](const std::string& s) -> EncryptionStatus {
        if (s == "ENCRYPTED") return EncryptionStatus::ENCRYPTED;
        if (s == "NOT_ENCRYPTED") return EncryptionStatus::NOT_ENCRYPTED;
        return EncryptionStatus::UNKNOWN;
    }))

#undef LEDGERASE_JSON_ENUM

// SanitizationMethod has no to-string helper, so it is handled explicitly.
inline void to_json(nlohmann::json& j, SanitizationMethod v) {
    switch (v) {
        case SanitizationMethod::NVME_BLOCK_ERASE:               j = "NVMe Block Erase"; break;
        case SanitizationMethod::NVME_CRYPTO_ERASE:              j = "NVMe Crypto Erase"; break;
        case SanitizationMethod::NVME_OVERWRITE:                 j = "NVMe Overwrite"; break;
        case SanitizationMethod::ATA_SECURE_ERASE:                j = "ATA Secure Erase"; break;
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:       j = "ATA Enhanced Secure Erase"; break;
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:        j = "ATA Sanitize Block Erase"; break;
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:       j = "ATA Sanitize Crypto Erase"; break;
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:          j = "ATA Sanitize Overwrite"; break;
        case SanitizationMethod::CRYPTO_ERASE_HOST:              j = "Host Crypto Erase"; break;
        case SanitizationMethod::OVERWRITE_HOST:                 j = "Host Overwrite"; break;
        case SanitizationMethod::UNSUPPORTED:                    j = "Unsupported"; break;
        case SanitizationMethod::DESTROY_MANUAL:                 j = "Manual Destruction"; break;
        case SanitizationMethod::NONE:
        default:                                                j = "None"; break;
    }
}

inline void from_json(const nlohmann::json& j, SanitizationMethod& v) {
    const auto s = j.is_string() ? j.get<std::string>() : std::string{};
    if (s == "NVMe Block Erase")                     v = SanitizationMethod::NVME_BLOCK_ERASE;
    else if (s == "NVMe Crypto Erase")               v = SanitizationMethod::NVME_CRYPTO_ERASE;
    else if (s == "NVMe Overwrite")                  v = SanitizationMethod::NVME_OVERWRITE;
    else if (s == "ATA Secure Erase")                v = SanitizationMethod::ATA_SECURE_ERASE;
    else if (s == "ATA Enhanced Secure Erase")       v = SanitizationMethod::ATA_ENHANCED_SECURE_ERASE;
    else if (s == "ATA Sanitize Block Erase")        v = SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE;
    else if (s == "ATA Sanitize Crypto Erase")       v = SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE;
    else if (s == "ATA Sanitize Overwrite")          v = SanitizationMethod::ATA_SANITIZE_OVERWRITE;
    else if (s == "Host Crypto Erase")               v = SanitizationMethod::CRYPTO_ERASE_HOST;
    else if (s == "Host Overwrite")                  v = SanitizationMethod::OVERWRITE_HOST;
    else if (s == "Unsupported")                     v = SanitizationMethod::UNSUPPORTED;
    else if (s == "Manual Destruction")              v = SanitizationMethod::DESTROY_MANUAL;
    else                                             v = SanitizationMethod::NONE;
}

// ---------------------------------------------------------------------------
// Struct adapters
// ---------------------------------------------------------------------------

inline void to_json(nlohmann::json& j, const PartitionInfo& p) {
    j = {
        {"path", p.path},
        {"start_sector", p.startSector},
        {"size_sectors", p.sizeSectors},
        {"size_bytes", p.sizeBytes},
        {"filesystem_type", p.filesystemType},
        {"label", p.label},
        {"uuid", p.uuid},
        {"mounted", p.mounted},
        {"mount_point", p.mountPoint},
        {"is_boot", p.isBoot},
        {"is_system", p.isSystem}
    };
}

inline void from_json(const nlohmann::json& j, PartitionInfo& p) {
    j.at("path").get_to(p.path);
    if (j.contains("start_sector")) j.at("start_sector").get_to(p.startSector);
    if (j.contains("size_sectors")) j.at("size_sectors").get_to(p.sizeSectors);
    if (j.contains("size_bytes")) j.at("size_bytes").get_to(p.sizeBytes);
    if (j.contains("filesystem_type")) j.at("filesystem_type").get_to(p.filesystemType);
    if (j.contains("label")) j.at("label").get_to(p.label);
    if (j.contains("uuid")) j.at("uuid").get_to(p.uuid);
    if (j.contains("mounted")) j.at("mounted").get_to(p.mounted);
    if (j.contains("mount_point")) j.at("mount_point").get_to(p.mountPoint);
    if (j.contains("is_boot")) j.at("is_boot").get_to(p.isBoot);
    if (j.contains("is_system")) j.at("is_system").get_to(p.isSystem);
}

inline void to_json(nlohmann::json& j, const FilesystemInfo& f) {
    j = {
        {"type", f.type},
        {"label", f.label},
        {"uuid", f.uuid},
        {"total_bytes", f.totalBytes},
        {"free_bytes", f.freeBytes},
        {"mount_point", f.mountPoint}
    };
}

inline void from_json(const nlohmann::json& j, FilesystemInfo& f) {
    j.at("type").get_to(f.type);
    if (j.contains("label")) j.at("label").get_to(f.label);
    if (j.contains("uuid")) j.at("uuid").get_to(f.uuid);
    if (j.contains("total_bytes")) j.at("total_bytes").get_to(f.totalBytes);
    if (j.contains("free_bytes")) j.at("free_bytes").get_to(f.freeBytes);
    if (j.contains("mount_point")) j.at("mount_point").get_to(f.mountPoint);
}

inline void to_json(nlohmann::json& j, const DeviceInfo& d) {
    j = {
        {"path", d.path},
        {"model", d.model},
        {"vendor", d.vendor},
        {"serial", d.serial},
        {"firmware", d.firmware},
        {"wwn", d.wwn},
        {"identity_source", d.identitySource},
        {"capacity_bytes", d.capacityBytes},
        {"logical_block_size", d.logicalBlockSize},
        {"physical_block_size", d.physicalBlockSize},
        {"transport", d.transport},
        {"media_type", d.mediaType},
        {"rotational", d.rotational},
        {"removable", d.removable},
        {"read_only", d.readOnly},
        {"mounted", d.mounted},
        {"system_disk", d.systemDisk},
        {"boot_disk", d.bootDisk},
        {"sysfs_path", d.sysfsPath},
        {"usb_device_node", d.usbDeviceNode},
        {"discovered_at", formatTimestamp(d.discoveryTime)},
        {"partitions", d.partitions},
        {"filesystems", d.filesystems}
    };
}

inline void from_json(const nlohmann::json& j, DeviceInfo& d) {
    j.at("path").get_to(d.path);
    if (j.contains("model")) j.at("model").get_to(d.model);
    if (j.contains("vendor")) j.at("vendor").get_to(d.vendor);
    if (j.contains("serial")) j.at("serial").get_to(d.serial);
    if (j.contains("firmware")) j.at("firmware").get_to(d.firmware);
    if (j.contains("wwn")) j.at("wwn").get_to(d.wwn);
    if (j.contains("identity_source")) j.at("identity_source").get_to(d.identitySource);
    if (j.contains("capacity_bytes")) j.at("capacity_bytes").get_to(d.capacityBytes);
    if (j.contains("logical_block_size")) j.at("logical_block_size").get_to(d.logicalBlockSize);
    if (j.contains("physical_block_size")) j.at("physical_block_size").get_to(d.physicalBlockSize);
    if (j.contains("transport")) j.at("transport").get_to(d.transport);
    if (j.contains("media_type")) j.at("media_type").get_to(d.mediaType);
    if (j.contains("rotational")) j.at("rotational").get_to(d.rotational);
    if (j.contains("removable")) j.at("removable").get_to(d.removable);
    if (j.contains("read_only")) j.at("read_only").get_to(d.readOnly);
    if (j.contains("mounted")) j.at("mounted").get_to(d.mounted);
    if (j.contains("system_disk")) j.at("system_disk").get_to(d.systemDisk);
    if (j.contains("boot_disk")) j.at("boot_disk").get_to(d.bootDisk);
    if (j.contains("sysfs_path")) j.at("sysfs_path").get_to(d.sysfsPath);
    if (j.contains("usb_device_node")) j.at("usb_device_node").get_to(d.usbDeviceNode);
    if (j.contains("discovered_at")) d.discoveryTime = parseTimestamp(j.at("discovered_at").get<std::string>());
    if (j.contains("partitions")) j.at("partitions").get_to(d.partitions);
    if (j.contains("filesystems")) j.at("filesystems").get_to(d.filesystems);
}

inline void to_json(nlohmann::json& j, const CapabilityInfo& c) {
    j = {
        {"nvme_block_erase", c.nvmeBlockErase},
        {"nvme_crypto_erase", c.nvmeCryptoErase},
        {"nvme_overwrite", c.nvmeOverwrite},
        {"ata_secure_erase", c.ataSecureErase},
        {"ata_enhanced_secure_erase", c.ataEnhancedSecureErase},
        {"ata_sanitize_block_erase", c.ataSanitizeBlockErase},
        {"ata_sanitize_crypto_erase", c.ataSanitizeCryptoErase},
        {"ata_sanitize_overwrite", c.ataSanitizeOverwrite},
        {"crypto_erase_host", c.cryptoEraseHost},
        {"overwrite_host", c.overwriteHost},
        {"encryption_status", c.encryptionStatus},
        {"nvme_controller_model", c.nvmeControllerModel},
        {"nvme_firmware", c.nvmeFirmware},
        {"nvme_namespace_id", c.nvmeNamespaceId},
        {"nvme_sanitize_supported", c.nvmeSanitizeSupported},
        {"nvme_max_sanitize_actions", c.nvmeMaxSanitizeActions},
        {"supported_sanitize_actions", c.supportedSanitizeActions},
        {"limitations", c.limitations}
    };
}

inline void from_json(const nlohmann::json& j, CapabilityInfo& c) {
    if (j.contains("nvme_block_erase")) j.at("nvme_block_erase").get_to(c.nvmeBlockErase);
    if (j.contains("nvme_crypto_erase")) j.at("nvme_crypto_erase").get_to(c.nvmeCryptoErase);
    if (j.contains("nvme_overwrite")) j.at("nvme_overwrite").get_to(c.nvmeOverwrite);
    if (j.contains("ata_secure_erase")) j.at("ata_secure_erase").get_to(c.ataSecureErase);
    if (j.contains("ata_enhanced_secure_erase")) j.at("ata_enhanced_secure_erase").get_to(c.ataEnhancedSecureErase);
    if (j.contains("ata_sanitize_block_erase")) j.at("ata_sanitize_block_erase").get_to(c.ataSanitizeBlockErase);
    if (j.contains("ata_sanitize_crypto_erase")) j.at("ata_sanitize_crypto_erase").get_to(c.ataSanitizeCryptoErase);
    if (j.contains("ata_sanitize_overwrite")) j.at("ata_sanitize_overwrite").get_to(c.ataSanitizeOverwrite);
    if (j.contains("crypto_erase_host")) j.at("crypto_erase_host").get_to(c.cryptoEraseHost);
    if (j.contains("overwrite_host")) j.at("overwrite_host").get_to(c.overwriteHost);
    if (j.contains("encryption_status")) j.at("encryption_status").get_to(c.encryptionStatus);
    if (j.contains("nvme_controller_model")) j.at("nvme_controller_model").get_to(c.nvmeControllerModel);
    if (j.contains("nvme_firmware")) j.at("nvme_firmware").get_to(c.nvmeFirmware);
    if (j.contains("nvme_namespace_id")) j.at("nvme_namespace_id").get_to(c.nvmeNamespaceId);
    if (j.contains("nvme_sanitize_supported")) j.at("nvme_sanitize_supported").get_to(c.nvmeSanitizeSupported);
    if (j.contains("nvme_max_sanitize_actions")) j.at("nvme_max_sanitize_actions").get_to(c.nvmeMaxSanitizeActions);
    if (j.contains("supported_sanitize_actions")) j.at("supported_sanitize_actions").get_to(c.supportedSanitizeActions);
    if (j.contains("limitations")) j.at("limitations").get_to(c.limitations);
}

inline void to_json(nlohmann::json& j, const SafetyCheck& c) {
    j = {
        {"name", c.name},
        {"result", c.result == SafetyCheckResult::PASS ? "PASS"
                    : c.result == SafetyCheckResult::FAIL ? "FAIL" : "WARNING"},
        {"message", c.message},
        {"recommendation", c.recommendation},
        {"critical", c.critical}
    };
}

inline void from_json(const nlohmann::json& j, SafetyCheck& c) {
    j.at("name").get_to(c.name);
    if (j.contains("message")) j.at("message").get_to(c.message);
    if (j.contains("recommendation")) j.at("recommendation").get_to(c.recommendation);
    if (j.contains("critical")) j.at("critical").get_to(c.critical);
    if (j.contains("result")) {
        const std::string value = j.at("result").get<std::string>();
        c.result = value == "PASS" ? SafetyCheckResult::PASS
                 : value == "FAIL" ? SafetyCheckResult::FAIL
                                   : SafetyCheckResult::WARNING;
    }
}

inline void to_json(nlohmann::json& j, const MethodAssessment& a) {
    j = {
        {"method", a.method},
        {"device_supported", a.deviceSupported},
        {"permitted_by_policy", a.permittedByPolicy},
        {"selected", a.selected},
        {"reason", a.reason}
    };
}

inline void from_json(const nlohmann::json& j, MethodAssessment& a) {
    j.at("method").get_to(a.method);
    if (j.contains("device_supported")) j.at("device_supported").get_to(a.deviceSupported);
    if (j.contains("permitted_by_policy")) j.at("permitted_by_policy").get_to(a.permittedByPolicy);
    if (j.contains("selected")) j.at("selected").get_to(a.selected);
    if (j.contains("reason")) j.at("reason").get_to(a.reason);
}

inline void to_json(nlohmann::json& j, const SanitizationPlan& p) {
    j = {
        {"job_id", p.jobId},
        {"device", p.device},
        {"capabilities", p.capabilities},
        {"requested_category", p.requestedCategory},
        {"selected_method", p.selectedMethod},
        {"overwrite_pass_count", p.overwritePassCount},
        {"rationale", p.rationale},
        {"standard_references", p.standardReferences},
        {"verification_plan", p.verificationPlan},
        {"validation_plan", p.validationPlan},
        {"limitations", p.limitations},
        {"risks", p.risks},
        {"alternatives_considered", p.alternativesConsidered},
        {"dry_run", p.dryRun},
        {"created_at", formatTimestamp(p.createdAt)}
    };
}

inline void from_json(const nlohmann::json& j, SanitizationPlan& p) {
    j.at("job_id").get_to(p.jobId);
    if (j.contains("device")) j.at("device").get_to(p.device);
    if (j.contains("capabilities")) j.at("capabilities").get_to(p.capabilities);
    if (j.contains("requested_category")) j.at("requested_category").get_to(p.requestedCategory);
    if (j.contains("selected_method")) j.at("selected_method").get_to(p.selectedMethod);
    if (j.contains("overwrite_pass_count")) j.at("overwrite_pass_count").get_to(p.overwritePassCount);
    if (j.contains("rationale")) j.at("rationale").get_to(p.rationale);
    if (j.contains("standard_references")) j.at("standard_references").get_to(p.standardReferences);
    if (j.contains("verification_plan")) j.at("verification_plan").get_to(p.verificationPlan);
    if (j.contains("validation_plan")) j.at("validation_plan").get_to(p.validationPlan);
    if (j.contains("limitations")) j.at("limitations").get_to(p.limitations);
    if (j.contains("risks")) j.at("risks").get_to(p.risks);
    if (j.contains("alternatives_considered")) j.at("alternatives_considered").get_to(p.alternativesConsidered);
    if (j.contains("dry_run")) j.at("dry_run").get_to(p.dryRun);
    if (j.contains("created_at")) p.createdAt = parseTimestamp(j.at("created_at").get<std::string>());
}

inline void to_json(nlohmann::json& j, const JobStatus& s) {
    j = {
        {"job_id", s.jobId},
        {"state", s.state},
        {"progress_percent", s.progressPercent},
        {"progress_valid", s.progressValid},
        {"bytes_processed", s.bytesProcessed},
        {"total_bytes", s.totalBytes},
        {"start_time", formatTimestamp(s.startTime)},
        {"end_time", formatTimestamp(s.endTime)},
        {"elapsed_seconds", s.elapsedTime.count()},
        {"current_operation", s.currentOperation},
        {"device_path", s.devicePath},
        {"error_message", s.errorMessage},
        {"error_code", s.errorCode},
        {"simulated", s.simulated}
    };
}

inline void from_json(const nlohmann::json& j, JobStatus& s) {
    j.at("job_id").get_to(s.jobId);
    if (j.contains("state")) j.at("state").get_to(s.state);
    if (j.contains("progress_percent")) j.at("progress_percent").get_to(s.progressPercent);
    if (j.contains("progress_valid")) j.at("progress_valid").get_to(s.progressValid);
    if (j.contains("bytes_processed")) j.at("bytes_processed").get_to(s.bytesProcessed);
    if (j.contains("total_bytes")) j.at("total_bytes").get_to(s.totalBytes);
    if (j.contains("start_time")) s.startTime = parseTimestamp(j.at("start_time").get<std::string>());
    if (j.contains("end_time")) s.endTime = parseTimestamp(j.at("end_time").get<std::string>());
    if (j.contains("elapsed_seconds")) s.elapsedTime = std::chrono::seconds(j.at("elapsed_seconds").get<long long>());
    if (j.contains("current_operation")) j.at("current_operation").get_to(s.currentOperation);
    if (j.contains("device_path")) j.at("device_path").get_to(s.devicePath);
    if (j.contains("error_message")) j.at("error_message").get_to(s.errorMessage);
    if (j.contains("error_code")) j.at("error_code").get_to(s.errorCode);
    if (j.contains("simulated")) j.at("simulated").get_to(s.simulated);
}

inline void to_json(nlohmann::json& j, const VerificationEvidence& e) {
    j = {
        {"method", e.method},
        {"description", e.description},
        {"passed", e.passed},
        {"details", e.details},
        {"limitations", e.limitations}
    };
}

inline void from_json(const nlohmann::json& j, VerificationEvidence& e) {
    j.at("method").get_to(e.method);
    if (j.contains("description")) j.at("description").get_to(e.description);
    if (j.contains("passed")) j.at("passed").get_to(e.passed);
    if (j.contains("details")) j.at("details").get_to(e.details);
    if (j.contains("limitations")) j.at("limitations").get_to(e.limitations);
}

inline void to_json(nlohmann::json& j, const VerificationReport& r) {
    j = {
        {"job_id", r.jobId},
        {"result", r.result},
        {"evidence", r.evidence},
        {"scope", r.scope},
        {"limitations", r.limitations},
        {"timestamp", formatTimestamp(r.timestamp)}
    };
}

inline void from_json(const nlohmann::json& j, VerificationReport& r) {
    j.at("job_id").get_to(r.jobId);
    if (j.contains("result")) j.at("result").get_to(r.result);
    if (j.contains("evidence")) j.at("evidence").get_to(r.evidence);
    if (j.contains("scope")) j.at("scope").get_to(r.scope);
    if (j.contains("limitations")) j.at("limitations").get_to(r.limitations);
    if (j.contains("timestamp")) r.timestamp = parseTimestamp(j.at("timestamp").get<std::string>());
}

inline void to_json(nlohmann::json& j, const ValidationReport& r) {
    j = {
        {"job_id", r.jobId},
        {"result", r.result},
        {"reasoning", r.reasoning},
        {"accepted_criteria", r.acceptedCriteria},
        {"rejected_criteria", r.rejectedCriteria},
        {"limitations", r.limitations},
        {"timestamp", formatTimestamp(r.timestamp)}
    };
}

inline void from_json(const nlohmann::json& j, ValidationReport& r) {
    j.at("job_id").get_to(r.jobId);
    if (j.contains("result")) j.at("result").get_to(r.result);
    if (j.contains("reasoning")) j.at("reasoning").get_to(r.reasoning);
    if (j.contains("accepted_criteria")) j.at("accepted_criteria").get_to(r.acceptedCriteria);
    if (j.contains("rejected_criteria")) j.at("rejected_criteria").get_to(r.rejectedCriteria);
    if (j.contains("limitations")) j.at("limitations").get_to(r.limitations);
    if (j.contains("timestamp")) r.timestamp = parseTimestamp(j.at("timestamp").get<std::string>());
}

inline void to_json(nlohmann::json& j, const RecoveryTestFile& f) {
    j = {
        {"filename", f.filename},
        {"size", f.size},
        {"sha256", f.sha256},
        {"file_type", f.fileType}
    };
}

inline void from_json(const nlohmann::json& j, RecoveryTestFile& f) {
    j.at("filename").get_to(f.filename);
    if (j.contains("size")) j.at("size").get_to(f.size);
    if (j.contains("sha256")) j.at("sha256").get_to(f.sha256);
    if (j.contains("file_type")) j.at("file_type").get_to(f.fileType);
}

inline void to_json(nlohmann::json& j, const RecoveryMetrics& m) {
    j = {
        {"known_files", m.knownFiles},
        {"complete_recoveries", m.completeRecoveries},
        {"partial_recoveries", m.partialRecoveries},
        {"failed_recoveries", m.failedRecoveries},
        {"false_positives", m.falsePositives},
        {"hash_matches", m.hashMatches},
        {"signature_detections", m.signatureDetections},
        {"recovery_rate", m.recoveryRate},
        {"complete_recovery_rate", m.completeRecoveryRate},
        {"hash_match_rate", m.hashMatchRate}
    };
}

inline void from_json(const nlohmann::json& j, RecoveryMetrics& m) {
    if (j.contains("known_files")) j.at("known_files").get_to(m.knownFiles);
    if (j.contains("complete_recoveries")) j.at("complete_recoveries").get_to(m.completeRecoveries);
    if (j.contains("partial_recoveries")) j.at("partial_recoveries").get_to(m.partialRecoveries);
    if (j.contains("failed_recoveries")) j.at("failed_recoveries").get_to(m.failedRecoveries);
    if (j.contains("false_positives")) j.at("false_positives").get_to(m.falsePositives);
    if (j.contains("hash_matches")) j.at("hash_matches").get_to(m.hashMatches);
    if (j.contains("signature_detections")) j.at("signature_detections").get_to(m.signatureDetections);
    if (j.contains("recovery_rate")) j.at("recovery_rate").get_to(m.recoveryRate);
    if (j.contains("complete_recovery_rate")) j.at("complete_recovery_rate").get_to(m.completeRecoveryRate);
    if (j.contains("hash_match_rate")) j.at("hash_match_rate").get_to(m.hashMatchRate);
}

inline void to_json(nlohmann::json& j, const RecoveryTestResult& r) {
    j = {
        {"job_id", r.jobId},
        {"test_id", r.testId},
        {"baseline_files", r.baselineFiles},
        {"recovered_files", r.recoveredFiles},
        {"before_metrics", r.beforeMetrics},
        {"after_metrics", r.afterMetrics},
        {"baseline_time", formatTimestamp(r.baselineTime)},
        {"recovery_time", formatTimestamp(r.recoveryTime)}
    };
}

inline void from_json(const nlohmann::json& j, RecoveryTestResult& r) {
    if (j.contains("job_id")) j.at("job_id").get_to(r.jobId);
    if (j.contains("test_id")) j.at("test_id").get_to(r.testId);
    if (j.contains("baseline_files")) j.at("baseline_files").get_to(r.baselineFiles);
    if (j.contains("recovered_files")) j.at("recovered_files").get_to(r.recoveredFiles);
    if (j.contains("before_metrics")) j.at("before_metrics").get_to(r.beforeMetrics);
    if (j.contains("after_metrics")) j.at("after_metrics").get_to(r.afterMetrics);
    if (j.contains("baseline_time")) r.baselineTime = parseTimestamp(j.at("baseline_time").get<std::string>());
    if (j.contains("recovery_time")) r.recoveryTime = parseTimestamp(j.at("recovery_time").get<std::string>());
}

inline void to_json(nlohmann::json& j, const AuditRecord& r) {
    j = {
        {"schema", "ledgerase.audit_record/1"},
        {"job_id", r.jobId},
        {"timestamp", r.timestamp},
        {"operator_name", r.operatorName},
        {"application_version", r.applicationVersion},
        {"device", r.device},
        {"capabilities", r.capabilities},
        {"plan", r.plan},
        {"execution", r.execution},
        {"verification", r.verification},
        {"validation", r.validation},
    };
}

inline void from_json(const nlohmann::json& j, AuditRecord& r) {
    if (j.contains("job_id")) j.at("job_id").get_to(r.jobId);
    if (j.contains("timestamp")) j.at("timestamp").get_to(r.timestamp);
    if (j.contains("operator_name")) j.at("operator_name").get_to(r.operatorName);
    if (j.contains("application_version")) j.at("application_version").get_to(r.applicationVersion);
    if (j.contains("device")) j.at("device").get_to(r.device);
    if (j.contains("capabilities")) j.at("capabilities").get_to(r.capabilities);
    if (j.contains("plan")) j.at("plan").get_to(r.plan);
    if (j.contains("execution")) j.at("execution").get_to(r.execution);
    if (j.contains("verification")) j.at("verification").get_to(r.verification);
    if (j.contains("validation")) j.at("validation").get_to(r.validation);
}

} // namespace ledgerase
