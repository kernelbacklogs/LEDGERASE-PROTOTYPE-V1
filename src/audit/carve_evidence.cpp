// Carve evidence: the hash-chained record of a recovery run.
//
// A carve job sanitizes nothing, so it produces no certificate. It does produce
// a set of claims a third party would want checked the same way a certificate's
// claims are: that this source, in this state, was read; that reading it did
// not change it; and that each recovered file has this digest. Those claims go
// into the same chain as a sanitization, under their own record types and their
// own schema, so `verify-log` checks them with the machinery that already
// exists rather than a second, weaker path.
//
// The chain carries one record per recovered file as well as one per phase.
// That is deliberate: a summary record saying "40 files recovered" commits to a
// number, while per-file records commit to 40 digests. An assessor can then
// re-hash a carved file and check it against the record without trusting the
// count.

#include "ledgerase/evidence.hpp"
#include "ledgerase/json_adapters.hpp"

#include "evidence_document.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <unistd.h>

namespace ledgerase {

namespace {

std::string formatCarveTimestamp(std::chrono::system_clock::time_point when) {
    const std::time_t now = std::chrono::system_clock::to_time_t(when);
    std::tm tmValue{};
    gmtime_r(&now, &tmValue);
    std::ostringstream out;
    out << std::put_time(&tmValue, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

} // namespace

// ---------------------------------------------------------------------------
// Shared chain walk
// ---------------------------------------------------------------------------

detail::ChainCheck detail::verifyChainRecords(const std::vector<EvidenceRecord>& records,
                                      uint64_t declaredLength,
                                      const std::string& declaredHead) {
    ChainCheck result;
    result.recordsChecked = records.size();
    result.headHash = records.empty() ? EvidenceJournal::kGenesisHash
                                      : records.back().recordHash;

    // A chain shorter than the document declares means records were removed from
    // the end; the head check alone would not catch that, because the remaining
    // records still link correctly to each other.
    if (records.size() != declaredLength) {
        result.failureReason =
            "Chain length mismatch: the document declares " +
            std::to_string(declaredLength) + " records but carries " +
            std::to_string(records.size()) + ". Records appear to have been "
            "removed.";
        return result;
    }
    if (result.headHash != declaredHead) {
        result.failureReason =
            "Chain head mismatch: the declared head does not match the last "
            "record in the chain.";
        return result;
    }

    std::string expectedPrev = EvidenceJournal::kGenesisHash;
    for (const EvidenceRecord& record : records) {
        const auto recomputed = EvidenceJournal::recordHash(record);
        if (recomputed.isError() || recomputed.value() != record.recordHash) {
            result.failureAtSequence = std::to_string(record.sequence);
            result.failureReason = "Record " + std::to_string(record.sequence) +
                                   " does not match its recorded hash.";
            return result;
        }
        if (record.prevHash != expectedPrev) {
            result.failureAtSequence = std::to_string(record.sequence);
            result.failureReason = "Record " + std::to_string(record.sequence) +
                                   " does not commit to its predecessor.";
            return result;
        }
        expectedPrev = record.recordHash;
    }

    result.intact = true;
    return result;
}

void to_json(nlohmann::json& j, const CarveSourceRecord& s) {
    j = {
        {"path", s.path},
        {"kind", s.kind},
        {"size_bytes", s.sizeBytes},
        {"sha256_before_scan", s.sha256BeforeScan},
        {"sha256_after_scan", s.sha256AfterScan},
        {"unchanged", s.unchanged},
        {"opened_read_only", s.openedReadOnly},
    };
}

void from_json(const nlohmann::json& j, CarveSourceRecord& s) {
    if (j.contains("path")) j.at("path").get_to(s.path);
    if (j.contains("kind")) j.at("kind").get_to(s.kind);
    if (j.contains("size_bytes")) j.at("size_bytes").get_to(s.sizeBytes);
    if (j.contains("sha256_before_scan")) j.at("sha256_before_scan").get_to(s.sha256BeforeScan);
    if (j.contains("sha256_after_scan")) j.at("sha256_after_scan").get_to(s.sha256AfterScan);
    if (j.contains("unchanged")) j.at("unchanged").get_to(s.unchanged);
    if (j.contains("opened_read_only")) j.at("opened_read_only").get_to(s.openedReadOnly);
}

void to_json(nlohmann::json& j, const CarveParameters& p) {
    j = {
        {"chunk_size", p.chunkSize},
        {"overlap", p.overlap},
        {"max_candidates", p.maxCandidates},
        {"max_total_output_bytes", p.maxTotalOutputBytes},
        {"max_inferred_length", p.maxInferredLength},
        {"minimum_score", p.minimumScore},
        {"category_filter", p.categoryFilter},
        {"output_directory", p.outputDirectory},
    };
}

void from_json(const nlohmann::json& j, CarveParameters& p) {
    if (j.contains("chunk_size")) j.at("chunk_size").get_to(p.chunkSize);
    if (j.contains("overlap")) j.at("overlap").get_to(p.overlap);
    if (j.contains("max_candidates")) j.at("max_candidates").get_to(p.maxCandidates);
    if (j.contains("max_total_output_bytes")) j.at("max_total_output_bytes").get_to(p.maxTotalOutputBytes);
    if (j.contains("max_inferred_length")) j.at("max_inferred_length").get_to(p.maxInferredLength);
    if (j.contains("minimum_score")) j.at("minimum_score").get_to(p.minimumScore);
    if (j.contains("category_filter")) j.at("category_filter").get_to(p.categoryFilter);
    if (j.contains("output_directory")) j.at("output_directory").get_to(p.outputDirectory);
}

void to_json(nlohmann::json& j, const CarveRecoveredEntry& e) {
    j = {
        {"offset", e.offset},
        {"length", e.length},
        {"signature", e.signatureName},
        {"extension", e.extension},
        {"category", e.category},
        {"confidence", e.confidence},
        {"score", e.score},
        {"sha256", e.sha256},
        {"truncated", e.truncated},
        {"length_inferred", e.lengthInferred},
        {"structure_valid", e.structureValid},
        {"reasons", e.reasons},
        {"extracted_path", e.extractedPath},
        {"extracted_bytes", e.extractedBytes},
    };
}

void from_json(const nlohmann::json& j, CarveRecoveredEntry& e) {
    if (j.contains("offset")) j.at("offset").get_to(e.offset);
    if (j.contains("length")) j.at("length").get_to(e.length);
    if (j.contains("signature")) j.at("signature").get_to(e.signatureName);
    if (j.contains("extension")) j.at("extension").get_to(e.extension);
    if (j.contains("category")) j.at("category").get_to(e.category);
    if (j.contains("confidence")) j.at("confidence").get_to(e.confidence);
    if (j.contains("score")) j.at("score").get_to(e.score);
    if (j.contains("sha256")) j.at("sha256").get_to(e.sha256);
    if (j.contains("truncated")) j.at("truncated").get_to(e.truncated);
    if (j.contains("length_inferred")) j.at("length_inferred").get_to(e.lengthInferred);
    if (j.contains("structure_valid")) j.at("structure_valid").get_to(e.structureValid);
    if (j.contains("reasons")) j.at("reasons").get_to(e.reasons);
    if (j.contains("extracted_path")) j.at("extracted_path").get_to(e.extractedPath);
    if (j.contains("extracted_bytes")) j.at("extracted_bytes").get_to(e.extractedBytes);
}

void to_json(nlohmann::json& j, const CarveEvidenceBundle& b) {
    j = {
        {"schema", b.schema},
        {"job_id", b.jobId},
        {"generated_at", b.generatedAt},

        {"tool", {
            {"application_version", b.applicationVersion},
            {"carver_version", b.carverVersion},
        }},

        {"operator", b.operatorName},
        {"operator_invoking_user", b.invokingUser},
        {"operator_invoking_uid", b.invokingUid},
        {"operator_effective_user", b.effectiveUser},
        {"operator_effective_uid", b.effectiveUid},
        {"operator_elevated", b.elevated},

        {"source", b.source},
        {"parameters", b.parameters},

        {"scan", {
            {"candidates_examined", b.candidatesExamined},
            {"files_recovered", b.filesRecovered},
            {"bytes_recovered", b.bytesRecovered},
            {"files_extracted", b.filesExtracted},
            {"bytes_extracted", b.bytesExtracted},
            {"files_not_extracted", b.filesNotExtracted},
            {"extraction_failures", b.extractionFailures},
        }},

        {"recovered", b.recovered},
        {"notes", b.notes},

        {"integrity", {
            {"chain_length", b.chainLength},
            {"chain_head", b.chainHead},
            {"event_chain", b.eventChain},
        }},

        {"canonical_hash", b.canonicalHash},
    };
}

void from_json(const nlohmann::json& j, CarveEvidenceBundle& b) {
    if (j.contains("schema")) j.at("schema").get_to(b.schema);
    if (j.contains("job_id")) j.at("job_id").get_to(b.jobId);
    if (j.contains("generated_at")) j.at("generated_at").get_to(b.generatedAt);

    if (j.contains("tool")) {
        const auto& t = j.at("tool");
        if (t.contains("application_version")) t.at("application_version").get_to(b.applicationVersion);
        if (t.contains("carver_version")) t.at("carver_version").get_to(b.carverVersion);
    }

    if (j.contains("operator")) j.at("operator").get_to(b.operatorName);
    if (j.contains("operator_invoking_user")) j.at("operator_invoking_user").get_to(b.invokingUser);
    if (j.contains("operator_invoking_uid")) j.at("operator_invoking_uid").get_to(b.invokingUid);
    if (j.contains("operator_effective_user")) j.at("operator_effective_user").get_to(b.effectiveUser);
    if (j.contains("operator_effective_uid")) j.at("operator_effective_uid").get_to(b.effectiveUid);
    if (j.contains("operator_elevated")) j.at("operator_elevated").get_to(b.elevated);

    if (j.contains("source")) j.at("source").get_to(b.source);
    if (j.contains("parameters")) j.at("parameters").get_to(b.parameters);

    if (j.contains("scan")) {
        const auto& s = j.at("scan");
        if (s.contains("candidates_examined")) s.at("candidates_examined").get_to(b.candidatesExamined);
        if (s.contains("files_recovered")) s.at("files_recovered").get_to(b.filesRecovered);
        if (s.contains("bytes_recovered")) s.at("bytes_recovered").get_to(b.bytesRecovered);
        if (s.contains("files_extracted")) s.at("files_extracted").get_to(b.filesExtracted);
        if (s.contains("bytes_extracted")) s.at("bytes_extracted").get_to(b.bytesExtracted);
        if (s.contains("files_not_extracted")) s.at("files_not_extracted").get_to(b.filesNotExtracted);
        if (s.contains("extraction_failures")) s.at("extraction_failures").get_to(b.extractionFailures);
    }

    if (j.contains("recovered")) j.at("recovered").get_to(b.recovered);
    if (j.contains("notes")) j.at("notes").get_to(b.notes);
    if (j.contains("canonical_hash")) j.at("canonical_hash").get_to(b.canonicalHash);

    if (j.contains("integrity")) {
        const auto& i = j.at("integrity");
        if (i.contains("chain_length")) i.at("chain_length").get_to(b.chainLength);
        if (i.contains("chain_head")) i.at("chain_head").get_to(b.chainHead);
        if (i.contains("event_chain")) i.at("event_chain").get_to(b.eventChain);
    }
}

// ---------------------------------------------------------------------------
// CarveEvidenceBuilder
// ---------------------------------------------------------------------------

std::string CarveEvidenceBuilder::generateJobId() {
    static thread_local std::mt19937 engine(std::random_device{}());
    std::uniform_int_distribution<int> dist(1000, 9999);
    const auto now = std::chrono::system_clock::now();
    const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
    std::tm tmValue{};
    gmtime_r(&seconds, &tmValue);

    std::ostringstream out;
    out << "CARVE-" << std::put_time(&tmValue, "%Y%m%dT%H%M%SZ") << "-"
        << dist(engine);
    return out.str();
}

Result<CarveEvidenceBundle> CarveEvidenceBuilder::build(
    const CarveEvidenceBundle& inputs,
    const std::vector<std::string>& extractionFailures) {

    CarveEvidenceBundle bundle = inputs;
    bundle.generatedAt = formatCarveTimestamp(std::chrono::system_clock::now());
    bundle.filesNotExtracted = extractionFailures.size();
    bundle.extractionFailures = extractionFailures;
    // Recomputed from the entries rather than trusted from the caller, so the
    // totals in the header and the list underneath cannot disagree.
    bundle.filesRecovered = bundle.recovered.size();
    bundle.bytesRecovered = 0;
    bundle.filesExtracted = 0;
    bundle.bytesExtracted = 0;
    for (const CarveRecoveredEntry& entry : bundle.recovered) {
        bundle.bytesRecovered += entry.length;
        if (!entry.extractedPath.empty()) {
            ++bundle.filesExtracted;
            bundle.bytesExtracted += entry.extractedBytes;
        }
    }

    // The chain is assembled here so that each record commits to the digests of
    // the values that are actually stored above.
    EvidenceJournal journal;
    const auto append = [&journal, &bundle](const char* type,
                                            nlohmann::json payload) -> Result<void> {
        const auto appended = journal.append(type, bundle.jobId, std::move(payload));
        if (appended.isError()) {
            return Result<void>::err(appended.error());
        }
        return Result<void>::success();
    };

    auto opened = append("carve_job_opened", {
        {"tool", {{"application_version", bundle.applicationVersion},
                  {"carver_version", bundle.carverVersion}}},
        {"source", {{"path", bundle.source.path},
                    {"kind", bundle.source.kind},
                    {"size_bytes", bundle.source.sizeBytes},
                    {"opened_read_only", bundle.source.openedReadOnly}}},
        {"parameters", bundle.parameters},
    });
    if (opened.isError()) {
        return Result<CarveEvidenceBundle>::err(opened.error());
    }

    auto hashed = append("carve_source_hashed",
                         {{"phase", "before scan"},
                          {"sha256", bundle.source.sha256BeforeScan}});
    if (hashed.isError()) {
        return Result<CarveEvidenceBundle>::err(hashed.error());
    }

    auto scanned = append(
        "carve_scan_completed",
        {{"candidates_examined", bundle.candidatesExamined},
         {"files_recovered", bundle.filesRecovered},
         {"bytes_recovered", bundle.bytesRecovered}});
    if (scanned.isError()) {
        return Result<CarveEvidenceBundle>::err(scanned.error());
    }

    for (const CarveRecoveredEntry& entry : bundle.recovered) {
        auto found = append("carve_file_recovered", {
                                           {"offset", entry.offset},
                                           {"length", entry.length},
                                           {"signature", entry.signatureName},
                                           {"category", entry.category},
                                           {"confidence", entry.confidence},
                                           {"score", entry.score},
                                           {"sha256", entry.sha256},
                                           {"truncated", entry.truncated},
                                           {"length_inferred", entry.lengthInferred},
                                           {"structure_valid", entry.structureValid},
                                           {"extracted_path", entry.extractedPath},
                                           {"extracted_bytes", entry.extractedBytes},
                                       });
        if (found.isError()) {
            return Result<CarveEvidenceBundle>::err(found.error());
        }
    }

    for (const std::string& failure : extractionFailures) {
        auto failed = append("carve_file_not_extracted", {{"reason", failure}});
        if (failed.isError()) {
            return Result<CarveEvidenceBundle>::err(failed.error());
        }
    }

    auto rehashed =
        append("carve_source_rehashed",
               {{"phase", "after scan"},
                {"sha256", bundle.source.sha256AfterScan},
                {"unchanged", bundle.source.unchanged}});
    if (rehashed.isError()) {
        return Result<CarveEvidenceBundle>::err(rehashed.error());
    }

    auto closed = append("carve_job_closed",
                         {{"files_recovered", bundle.filesRecovered},
                          {"files_extracted", bundle.filesExtracted},
                          {"bytes_extracted", bundle.bytesExtracted},
                          {"files_not_extracted", bundle.filesNotExtracted},
                          {"source_unchanged", bundle.source.unchanged}});
    if (closed.isError()) {
        return Result<CarveEvidenceBundle>::err(closed.error());
    }

    bundle.eventChain = journal.records();
    bundle.chainLength = journal.count();
    bundle.chainHead = journal.head();

    auto hash = canonicalHash(bundle);
    if (hash.isError()) {
        return Result<CarveEvidenceBundle>::err(hash.error());
    }
    bundle.canonicalHash = hash.value();
    return bundle;
}

Result<std::string> CarveEvidenceBuilder::canonicalJson(
    const CarveEvidenceBundle& bundle) {
    nlohmann::json j = bundle;
    j.erase("canonical_hash");
    return j.dump();
}

Result<std::string> CarveEvidenceBuilder::canonicalHash(
    const CarveEvidenceBundle& bundle) {
    const auto canonical = canonicalJson(bundle);
    if (canonical.isError()) {
        return Result<std::string>::err(canonical.error());
    }
    return sha256HexBytes(
        reinterpret_cast<const uint8_t*>(canonical.value().data()),
        canonical.value().size());
}

Result<std::string> CarveEvidenceBuilder::canonicalHashOfDocument(
    const nlohmann::json& document) {
    nlohmann::json copy = document;
    copy.erase("canonical_hash");
    const std::string dumped = copy.dump();
    return sha256HexBytes(reinterpret_cast<const uint8_t*>(dumped.data()),
                          dumped.size());
}

// ---------------------------------------------------------------------------
// CarveEvidenceWriter
// ---------------------------------------------------------------------------

Result<void> CarveEvidenceWriter::write(const CarveEvidenceBundle& bundle,
                                        const std::string& path,
                                        bool overwrite) {
    // The stored document must contain the hash that covers it, or a verifier
    // has nothing to compare against.
    CarveEvidenceBundle document = bundle;
    auto hash = CarveEvidenceBuilder::canonicalHash(document);
    if (hash.isError()) {
        return Result<void>::err(hash.error());
    }
    document.canonicalHash = hash.value();

    std::string payload = nlohmann::json(document).dump(2);
    payload.push_back('\n');
    return detail::writeEvidenceDocument(path, payload, overwrite);
}

Result<CarveEvidenceBundle> CarveEvidenceWriter::read(const std::string& path) {
    auto document = detail::readEvidenceDocument(path);
    if (document.isError()) {
        return Result<CarveEvidenceBundle>::err(document.error());
    }
    CarveEvidenceBundle bundle;
    try {
        document.value().get_to(bundle);
    } catch (const std::exception& e) {
        return Result<CarveEvidenceBundle>::err(
            ErrorCode::INVALID_ARGUMENT,
            std::string("Carve evidence file is malformed: ") + e.what());
    }
    return bundle;
}

// ---------------------------------------------------------------------------
// CarveEvidenceVerifier
// ---------------------------------------------------------------------------

Result<EvidenceVerification> CarveEvidenceVerifier::verifyStructure(
    const std::string& path) {
    auto document = detail::readEvidenceDocument(path);
    if (document.isError()) {
        return Result<EvidenceVerification>::err(document.error());
    }

    CarveEvidenceBundle bundle;
    try {
        document.value().get_to(bundle);
    } catch (const std::exception& e) {
        return Result<EvidenceVerification>::err(
            ErrorCode::INVALID_ARGUMENT,
            std::string("Carve evidence file is malformed: ") + e.what());
    }

    EvidenceVerification report;
    // Current schema, or any spelling an earlier build wrote. The name lives in
    // the string and not in the format, so the old bundles are the same format.
    report.schemaRecognised = (bundle.schema == CarveEvidenceBundle::kSchema);
    for (const char* legacy : CarveEvidenceBundle::kLegacySchemas) {
        if (bundle.schema == legacy) {
            report.schemaRecognised = true;
        }
    }
    if (!report.schemaRecognised) {
        report.findings.push_back("Unrecognised schema: " + bundle.schema);
        return report;
    }

    // The stored document is hashed, not a re-serialisation of this build's
    // structs, for the same reason the sanitization path does it that way: the
    // result then depends only on the bytes on disk.
    const auto recomputed =
        CarveEvidenceBuilder::canonicalHashOfDocument(document.value());
    if (recomputed.isError()) {
        return Result<EvidenceVerification>::err(recomputed.error());
    }
    report.canonicalHashMatches = recomputed.value() == bundle.canonicalHash;
    report.findings.push_back(
        report.canonicalHashMatches
            ? "Canonical hash matches: content is unaltered"
            : "Canonical hash MISMATCH: content was modified after it was "
              "produced");

    const detail::ChainCheck chain = detail::verifyChainRecords(
        bundle.eventChain, bundle.chainLength, bundle.chainHead);
    report.chainConsistent = chain.intact;
    report.chainLength = bundle.chainLength;
    report.findings.push_back(chain.intact
                                  ? "Event chain is intact (" +
                                        std::to_string(chain.recordsChecked) +
                                        " records)"
                                  : "Event chain FAILED: " + chain.failureReason);

    report.signaturePresent = false;
    report.findings.push_back(
        "No signature present. A carve record is unsigned by design, so integrity "
        "here rests on the hash alone, which detects accidental change but proves "
        "nothing about origin.");

    // A carve record says the source was read and not changed. It cannot say
    // the recovered files are the right files, nor that a quick format removed
    // anything - only that these digests came out of these bytes.
    report.limitations.add(LimitationId::VERIFYLOG_SCOPE);
    return report;
}

} // namespace ledgerase
