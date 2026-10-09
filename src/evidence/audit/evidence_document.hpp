// Shared plumbing for the two evidence documents.
//
// A sanitization certificate and a carve record are different documents with
// different schemas, but they are written and read the same way: atomically,
// mode 0600, never through a symlink, never clobbering without an explicit
// request. That is one set of rules, so it is implemented once here rather than
// copied into a second writer that would drift from the first.
#pragma once

#include "ledgerase/error.hpp"
#include "ledgerase/evidence.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace ledgerase::detail {

// Writes `payload` to `path` as a 0600 file: temporary in the destination
// directory, fsync, then link() (which refuses to clobber) or rename().
Result<void> writeEvidenceDocument(const std::string& path,
                                    const std::string& payload,
                                    bool overwrite);

// Reads a JSON object from `path`, refusing to follow a symlink.
Result<nlohmann::json> readEvidenceDocument(const std::string& path);

// One link's worth of chain state, so a caller that holds only the records and
// the declared length/head - which is every caller - can be checked the same
// way.
struct ChainCheck {
    bool intact = false;
    uint64_t recordsChecked = 0;
    std::string headHash;
    std::string failureReason;
    std::string failureAtSequence;
};

// Walks an embedded chain: length, head, and every record's own hash and link
// to its predecessor. This is the part both bundle types share, and the part
// that catches an edit, a reorder, an interior deletion and a tail truncation.
ChainCheck verifyChainRecords(const std::vector<EvidenceRecord>& records,
                              uint64_t declaredLength,
                              const std::string& declaredHead);

} // namespace ledgerase::detail
