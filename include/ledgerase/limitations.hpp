// Limitation registry.
//
// Every limitation a job can record has a stable ID and one canonical
// sentence. Code adds IDs to a LimitationSet; the set renders the text. Two
// places that record the same fact therefore produce the same ID, and a set
// admits an ID once, so the same sentence cannot appear twice in one report.
//
// The alternative - free-text strings appended to a vector - is what produced
// a 26-entry list where five facts appeared six times each.

#ifndef LEDGERASE_LIMITATIONS_HPP
#define LEDGERASE_LIMITATIONS_HPP

#include <cstddef>
#include <ostream>
#include <initializer_list>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ledgerase {

// Stable identifiers. Values are never renumbered: an ID that appears in a
// signed evidence bundle has to keep meaning the same thing forever.
enum class LimitationId {
    // Scope
    HOST_SCOPE_ONLY,
    REMOVABLE_HISTORY,

    // Verification
    SELF_VERIFIED,
    DEVICE_SELF_REPORT,
    SAMPLED_READBACK,
    NO_VERIFICATION,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_FAILED,
    SIGNATURE_UNCHECKED,
    VERIFYLOG_SCOPE,

    // Device
    CAPABILITY_UNKNOWN,
    NO_DEVICE_LEVEL_MECHANISM,
    CLEAR_ONLY,
    USB_BRIDGE_OPAQUE,
    USB_BRIDGE_PROBE_PRESENT,
    USB_BRIDGE_PROBE_ABSENT,
    USB_BRIDGE_UNIDENTIFIED,
    PROBE_FAILED,
    NVME_NO_SANITIZE,
    NVME_NAMESPACE_ASSUMED,
    CRYPTO_ERASE_KEYS_ONLY,
    CRYPTO_ERASE_NEEDS_FDE,
    ENCRYPTION_UNKNOWN,
    NOT_IMPLEMENTED,

    // Not recorded
    NO_AUTHORIZATION,
    COPIES_NOT_ATTESTED,
    NO_RETENTION_POLICY,
    NO_IDENTITY_CONFIRMATION,

    // Run context
    SIMULATED_RUN,
};

struct LimitationEntry {
    LimitationId id = LimitationId::HOST_SCOPE_ONLY;
    std::string idText;    // e.g. "HOST_SCOPE_ONLY"
    std::string group;     // one of: Scope, Verification, Device, Not recorded
    std::string text;      // canonical sentence
    // A short topic label, used only by the grouped terminal view. Joining full
    // sentences to fit four lines produced text like "Clear-level method. It is
    // not device-level sanitization, Capability is unknown", which reads as one
    // claim rather than two. A label keeps the grouping honest: the full
    // sentence is still in the evidence file and under --verbose.
    std::string shortLabel;
    std::string detail;    // optional context, e.g. the underlying error
};

// Registry lookup. Returns the entry for an ID; never fails.
const LimitationEntry& limitationEntry(LimitationId id);

// Canonical text for an ID, without any detail.
std::string limitationText(LimitationId id);

// Renders one entry as "ID: text" or "ID: text (detail)".
std::string renderLimitation(const LimitationEntry& entry);

// Aggregate for inline construction: {{LimitationId::X, "detail"}}.
struct LimitationInit {
    LimitationId id;
    std::string detail;
};

// An insertion-ordered set of limitations, unique by (id, detail).
class LimitationSet {
public:
    // Braced initialisation stays typed. There is deliberately no
    // constructor from a list of strings, which is what would let free text
    // back in through an aggregate member initialiser.
    LimitationSet() = default;
    LimitationSet(std::initializer_list<LimitationId> ids) {
        for (const LimitationId id : ids) {
            add(id);
        }
    }
    LimitationSet(std::initializer_list<LimitationInit> inits) {
        for (const LimitationInit& init : inits) {
            add(init.id, init.detail);
        }
    }

    void add(LimitationId id);
    void add(LimitationId id, std::string detail);
    // Escape hatch for a fact with no ID yet. Deduped by exact text, so it
    // cannot duplicate an ID entry either, because ID entries always carry the
    // "ID: " prefix and this is stored without one.
    void addText(std::string text);

    void merge(const LimitationSet& other);

    bool contains(LimitationId id) const;
    bool empty() const;
    std::size_t size() const;
    void clear();

    const std::vector<LimitationEntry>& entries() const { return entries_; }
    // Rendered text per entry, in the same order. Iterating a LimitationSet
    // yields these, so `for (const auto& l : set) l.find(...)` works.
    const std::vector<std::string>& texts() const { return texts_; }

    // Plain text for the evidence file: one "ID: text" per line.

    // Iteration yields the rendered text, so callers that want to search a
    // limitation do `for (const auto& l : set) l.find(...)`. entries() is the
    // way to reach the ID and group.
    std::vector<std::string>::const_iterator begin() const {
        return texts_.begin();
    }
    std::vector<std::string>::const_iterator end() const {
        return texts_.end();
    }

private:
    void reindex();

    std::vector<LimitationEntry> entries_;
    std::set<std::pair<std::string, std::string>> seen_;
    std::vector<std::string> texts_;
    std::set<std::string> idNames_;
};

// Every entry in the registry, in table order. Used to map a stored ID string
// back to its enum value when reading a bundle.
const std::vector<LimitationEntry>& knownLimitationEntries();

// So a LimitationEntry streams correctly in the report and plan writers.
std::ostream& operator<<(std::ostream& out, const LimitationEntry& entry);

// Group headings, in display order, covering every ID.
const std::vector<std::string>& limitationGroups();

} // namespace ledgerase

#endif // LEDGERASE_LIMITATIONS_HPP
