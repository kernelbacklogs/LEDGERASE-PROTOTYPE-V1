#include "ledgerase/limitations.hpp"

#include <algorithm>
#include <ostream>
#include <utility>

namespace ledgerase {

namespace {

// One row per ID. The sentence is the whole point of the entry, so it is
// written to stand alone: short, declarative, and free of the phrasing that
// made the old list read as though a committee wrote it.
struct Row {
    LimitationId id;
    const char* idText;
    const char* group;
    const char* text;
};

const Row kTable[] = {
    // --- Scope ---
    {LimitationId::HOST_SCOPE_ONLY, "HOST_SCOPE_ONLY", "Scope",
     "Host-visible address space only. Overprovisioned, reallocated and "
     "controller-managed areas are neither written nor read."},
    {LimitationId::REMOVABLE_HISTORY, "REMOVABLE_MEDIA_HISTORY", "Scope",
     "Removable media may have been attached elsewhere. Only what is attached "
     "now is in scope."},

    // --- Verification ---
    {LimitationId::SELF_VERIFIED, "SELF_VERIFIED", "Verification",
     "Checked by this tool in the same run. No independent check was made."},
    {LimitationId::DEVICE_SELF_REPORT, "DEVICE_SELF_REPORT", "Verification",
     "Outcome rests on the device reporting its own completion."},
    {LimitationId::SAMPLED_READBACK, "SAMPLED_READBACK", "Verification",
     "Read-back covers a sample. It does not show the whole device was "
     "written."},
    {LimitationId::NO_VERIFICATION, "NO_VERIFICATION", "Verification",
     "No verification was performed."},
    {LimitationId::VERIFICATION_INCONCLUSIVE, "VERIFICATION_INCONCLUSIVE",
     "Verification",
     "The evidence available does not establish what the media now holds."},
    {LimitationId::VERIFICATION_FAILED, "VERIFICATION_FAILED", "Verification",
     "Verification did not pass."},
    {LimitationId::SIGNATURE_UNCHECKED, "SIGNATURE_UNCHECKED", "Verification",
     "No public key was supplied, so the signature was not checked."},
    {LimitationId::VERIFYLOG_SCOPE, "VERIFYLOG_SCOPE", "Verification",
     "Structural checks show the document is self-consistent. They cannot show "
     "the recorded events happened."},

    // --- Device ---
    {LimitationId::CAPABILITY_UNKNOWN, "CAPABILITY_UNKNOWN", "Device",
     "Capability is unknown. This tool could not query the device."},
    {LimitationId::NO_DEVICE_LEVEL_MECHANISM, "NO_DEVICE_LEVEL_MECHANISM",
     "Device",
     "No device-level erase is available. Only a host write can be performed."},
    {LimitationId::CLEAR_ONLY, "CLEAR_ONLY", "Device",
     "Clear-level method. It is not device-level sanitization."},
    {LimitationId::USB_BRIDGE_OPAQUE, "USB_BRIDGE_OPAQUE", "Device",
     "A USB bridge mediates every command. Results describe the bridge's view "
     "of the media."},
    {LimitationId::USB_BRIDGE_PROBE_PRESENT, "USB_BRIDGE_PROBE_PRESENT",
     "Device",
     "The bridge passed an identify request. Whether it passes an erase "
     "command is untested."},
    {LimitationId::USB_BRIDGE_PROBE_ABSENT, "USB_BRIDGE_PROBE_ABSENT",
     "Device",
     "The bridge answered no identify request. It exposes the SCSI command set "
     "only."},
    {LimitationId::USB_BRIDGE_UNIDENTIFIED, "USB_BRIDGE_UNIDENTIFIED", "Device",
     "The USB device behind this block device could not be identified."},
    {LimitationId::PROBE_FAILED, "PROBE_FAILED", "Device",
     "A device query failed."},
    {LimitationId::NVME_NO_SANITIZE, "NVME_NO_SANITIZE", "Device",
     "The controller does not advertise the Sanitize command (OACS bit 13 "
     "clear)."},
    {LimitationId::NVME_NAMESPACE_ASSUMED, "NVME_NAMESPACE_ASSUMED", "Device",
     "The Sanitize command targets namespace 1. On a multi-namespace "
     "controller that may be the wrong one."},
    {LimitationId::CRYPTO_ERASE_KEYS_ONLY, "CRYPTO_ERASE_KEYS_ONLY", "Device",
     "Crypto erase discards keys. Encrypted data stays on the media."},
    {LimitationId::CRYPTO_ERASE_NEEDS_FDE, "CRYPTO_ERASE_NEEDS_FDE", "Device",
     "Crypto erase needs full-disk encryption configured beforehand."},
    {LimitationId::ENCRYPTION_UNKNOWN, "ENCRYPTION_UNKNOWN", "Device",
     "Encryption state is unknown, so key destruction cannot be assessed."},
    {LimitationId::NOT_IMPLEMENTED, "NOT_IMPLEMENTED", "Device",
     "Not implemented in this version."},

    // --- Not recorded ---
    {LimitationId::NO_AUTHORIZATION, "NO_AUTHORIZATION", "Not recorded",
     "No authorization reference was recorded."},
    {LimitationId::COPIES_NOT_ATTESTED, "COPIES_NOT_ATTESTED", "Not recorded",
     "No copy scope was attested. Backups and replicas are not discoverable."},
    {LimitationId::NO_RETENTION_POLICY, "NO_RETENTION_POLICY", "Not recorded",
     "No retention period was set."},
    {LimitationId::NO_IDENTITY_CONFIRMATION, "NO_IDENTITY_CONFIRMATION",
     "Not recorded",
     "Device identity was not confirmed before the run."},

    // --- Run context ---
    {LimitationId::SIMULATED_RUN, "SIMULATED_RUN", "Not recorded",
     "Simulated run against a mock device. No real media was sanitized."},
};


// The short label the grouped terminal view uses.
//
// Kept beside the table rather than inside it, keyed by ID: adding a row to the
// table then cannot leave its label unset, and the compiler checks the switch
// for a case per enum member.
const char* shortLabelFor(LimitationId id) {
    switch (id) {
        case LimitationId::HOST_SCOPE_ONLY:
            return "host-visible address space only";
        case LimitationId::REMOVABLE_HISTORY:
            return "removable media may be attached elsewhere";
        case LimitationId::SELF_VERIFIED:
            return "checked in this run, not independently";
        case LimitationId::DEVICE_SELF_REPORT:
            return "outcome rests on the device self-report";
        case LimitationId::SAMPLED_READBACK:
            return "sampled read-back, not the whole device";
        case LimitationId::NO_VERIFICATION:
            return "no verification performed";
        case LimitationId::VERIFICATION_INCONCLUSIVE:
            return "verification inconclusive";
        case LimitationId::VERIFICATION_FAILED:
            return "verification did not pass";
        case LimitationId::SIGNATURE_UNCHECKED:
            return "signature not checked, no key given";
        case LimitationId::VERIFYLOG_SCOPE:
            return "self-consistency only, not proof of events";
        case LimitationId::CAPABILITY_UNKNOWN:
            return "capability not established";
        case LimitationId::NO_DEVICE_LEVEL_MECHANISM:
            return "no device-level erase available";
        case LimitationId::CLEAR_ONLY:
            return "clear level only, not device-level";
        case LimitationId::USB_BRIDGE_OPAQUE:
            return "results reflect the bridge's view";
        case LimitationId::USB_BRIDGE_PROBE_PRESENT:
            return "bridge passed an identify request";
        case LimitationId::USB_BRIDGE_PROBE_ABSENT:
            return "bridge exposes the SCSI command set only";
        case LimitationId::USB_BRIDGE_UNIDENTIFIED:
            return "USB device not identified";
        case LimitationId::PROBE_FAILED:
            return "a device query failed";
        case LimitationId::NVME_NO_SANITIZE:
            return "controller advertises no Sanitize command";
        case LimitationId::NVME_NAMESPACE_ASSUMED:
            return "namespace 1 assumed";
        case LimitationId::CRYPTO_ERASE_KEYS_ONLY:
            return "keys discarded, ciphertext remains";
        case LimitationId::CRYPTO_ERASE_NEEDS_FDE:
            return "needs pre-existing encryption";
        case LimitationId::ENCRYPTION_UNKNOWN:
            return "encryption state unknown";
        case LimitationId::NOT_IMPLEMENTED:
            return "not implemented in this version";
        case LimitationId::NO_AUTHORIZATION:
            return "authorization";
        case LimitationId::COPIES_NOT_ATTESTED:
            return "copy scope";
        case LimitationId::NO_RETENTION_POLICY:
            return "retention";
        case LimitationId::NO_IDENTITY_CONFIRMATION:
            return "identity confirmation";
        case LimitationId::SIMULATED_RUN:
            return "simulated run, no real media";
    }
    return "";
}

const LimitationEntry kFallback{};

} // namespace

const LimitationEntry& limitationEntry(LimitationId id) {
    // Built once from the const table above. Returning a reference into a
    // function-local static keeps it a single allocation and immune to static
    // initialisation order, since nothing here runs before main().
    static const std::vector<LimitationEntry> table = [] {
        std::vector<LimitationEntry> built;
        built.reserve(sizeof(kTable) / sizeof(kTable[0]));
        for (const Row& row : kTable) {
            LimitationEntry entry;
            entry.id = row.id;
            entry.idText = row.idText;
            entry.group = row.group;
            entry.text = row.text;
            entry.shortLabel = shortLabelFor(row.id);
            built.push_back(std::move(entry));
        }
        return built;
    }();

    for (const LimitationEntry& entry : table) {
        if (entry.id == id) {
            return entry;
        }
    }
    // Unreachable: every enum member is in the table, and the switch that
    // builds shortLabelFor covers each one. Kept as a defensive value rather
    // than a throw, because a lookup must not be able to abort a run.
    return kFallback;
}

const std::vector<LimitationEntry>& knownLimitationEntries() {
    // Same table, exposed by value. limitationEntry() resolves a single ID;
    // this is the whole set, needed to walk an ID string back to its enum.
    static const std::vector<LimitationEntry> table = [] {
        std::vector<LimitationEntry> built;
        built.reserve(sizeof(kTable) / sizeof(kTable[0]));
        for (const Row& row : kTable) {
            LimitationEntry entry;
            entry.id = row.id;
            entry.idText = row.idText;
            entry.group = row.group;
            entry.text = row.text;
            entry.shortLabel = shortLabelFor(row.id);
            built.push_back(std::move(entry));
        }
        return built;
    }();
    return table;
}

std::string limitationText(LimitationId id) {
    return limitationEntry(id).text;
}

std::string renderLimitation(const LimitationEntry& entry) {
    std::string out = entry.idText + ": " + entry.text;
    if (!entry.detail.empty()) {
        out += " (" + entry.detail + ")";
    }
    return out;
}

void LimitationSet::add(LimitationId id) {
    add(id, std::string());
}

void LimitationSet::add(LimitationId id, std::string detail) {
    const LimitationEntry& base = limitationEntry(id);
    const auto key = std::make_pair(base.idText, detail);
    if (!seen_.insert(key).second) {
        return;
    }
    LimitationEntry entry = base;
    entry.detail = std::move(detail);
    entries_.push_back(std::move(entry));
    idNames_.insert(entries_.back().idText);
    reindex();
}

void LimitationSet::addText(std::string text) {
    if (text.empty()) {
        return;
    }

    // A rendered line from a stored bundle looks like "HOST_SCOPE_ONLY: <text>".
    // Recovering the ID restores the entry's group, which is what lets the
    // terminal group the list by topic. A schema-1 bundle has no ID and takes
    // the path below, unchanged.
    for (const LimitationEntry& known : knownLimitationEntries()) {
        const std::string prefix = known.idText + ": ";
        if (text.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        std::string body = text.substr(prefix.size());
        // "ID: sentence (detail)" - keep the detail so two probe failures stay
        // distinguishable after a round trip through the file.
        std::string detail;
        if (body.size() > known.text.size() + 2 &&
            body.compare(0, known.text.size(), known.text) == 0 &&
            body[known.text.size()] == ' ' && body.back() == ')') {
            detail = body.substr(known.text.size() + 2,
                                 body.size() - known.text.size() - 3);
        }
        add(known.id, detail);
        return;
    }

    // Keyed on the text itself, and stored without an ID prefix, so this can
    // never collide with an ID entry's key.
    const auto key = std::make_pair(std::string(), text);
    if (!seen_.insert(key).second) {
        return;
    }
    LimitationEntry entry;
    entry.id = LimitationId::NOT_IMPLEMENTED;  // no ID claimed
    entry.idText.clear();
    entry.group = "Device";
    entry.text = std::move(text);
    entries_.push_back(std::move(entry));
    reindex();
}

void LimitationSet::merge(const LimitationSet& other) {
    for (const LimitationEntry& entry : other.entries_) {
        if (entry.idText.empty()) {
            addText(entry.text);
        } else {
            LimitationId id = LimitationId::NOT_IMPLEMENTED;
            for (const Row& row : kTable) {
                if (entry.idText == row.idText) {
                    id = row.id;
                    break;
                }
            }
            add(id, entry.detail);
        }
    }
}

bool LimitationSet::contains(LimitationId id) const {
    return idNames_.find(limitationEntry(id).idText) != idNames_.end();
}

bool LimitationSet::empty() const { return entries_.empty(); }

std::size_t LimitationSet::size() const { return entries_.size(); }

void LimitationSet::clear() {
    entries_.clear();
    seen_.clear();
    texts_.clear();
    idNames_.clear();
}

void LimitationSet::reindex() {
    texts_.clear();
    texts_.reserve(entries_.size());
    for (const LimitationEntry& entry : entries_) {
        texts_.push_back(renderLimitation(entry));
    }
}


std::ostream& operator<<(std::ostream& out, const LimitationEntry& entry) {
    return out << renderLimitation(entry);
}

const std::vector<std::string>& limitationGroups() {
    static const std::vector<std::string> kGroups{
        "Scope", "Verification", "Device", "Not recorded"};
    return kGroups;
}

} // namespace ledgerase
