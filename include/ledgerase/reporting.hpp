#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/evidence.hpp"
#include "ledgerase/limitations.hpp"
#include <memory>
#include <string>
#include <vector>

namespace ledgerase {

// The evidence bundle is the only system of record: hash-chained, per job,
// verifiable by a third party, and actually written.
//
// A second record alongside it does not work. An append-only JSONL log is the
// obvious candidate, and readAuditLog() parsed each line and then discarded it,
// so it always returned an empty vector; getAuditHash() returned a hash of the
// whole file regardless of the job id it was asked about; and no code path ever
// opened the file it writes to. A class that appears to offer a query and
// silently returns nothing is worse than one that is absent.
//
// See include/ledgerase/evidence.hpp.

class CertificateGenerator {
public:
    CertificateGenerator();
    ~CertificateGenerator();


    // Canonical JSON (sorted keys, no insignificant whitespace) used as the
    // pre-image for the tamper-evident SHA-256 in CLAUDE.md s32. Deterministic:
    // the same record always produces the same bytes.

    // SHA-256 of generateCanonicalJson(record), lowercase hex. Returns an empty
    // string if hashing is unavailable; callers must treat "" as unknown.


    Result<void> generateReport(const AuditRecord& record,
                                const std::string& outputPath,
                                const std::string& format = "json");

    // Renders a certificate from an evidence bundle.
    //
    // The bundle is the tool's system of record, so a report must be a
    // rendering of that document rather than of a separate in-memory record
    // that could disagree with it. These take the bundle directly and include
    // its canonical hash, so a report can always be traced back to the exact
    // document it came from.
    Result<std::string> generateEvidenceText(const EvidenceBundle& bundle);
    Result<void> writeEvidencePdf(const EvidenceBundle& bundle,
                                  const std::string& outputPath);

    static std::string generateCertificateId();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// The only string-returning report still in the build.
//
// The other seven existed beside it and were called from nowhere: the CLI writes
// device, capability, plan, status, verification and validation output through
// OutputFormatter, and every certificate and report it produces goes through
// CertificateGenerator. Two report writers that can disagree is the failure this
// file's own header warns about, so the unused one is gone rather than left
// waiting to be used by mistake.
class ReportGenerator {
public:
    ReportGenerator();
    ~ReportGenerator();

    Result<std::string> generateExecutionReport(const JobStatus& status);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class OutputFormatter {
public:
    OutputFormatter();
    ~OutputFormatter();

    void setJsonOutput(bool enabled);
    void setVerbose(bool enabled);

    // Typed writers. There is deliberately no generic output<T>(): every
    // consumer needs domain-specific formatting, and a catch-all writer would
    // silently lose fields.
    Result<void> outputDeviceList(const std::vector<DeviceInfo>& devices);
    Result<void> outputDeviceInfo(const DeviceInfo& device);
    Result<void> outputCapabilityInfo(const CapabilityInfo& capabilities);
    Result<void> outputPlan(const SanitizationPlan& plan);
    Result<void> outputJobStatus(const JobStatus& status);
    Result<void> outputVerificationReport(const VerificationReport& report);
    Result<void> outputValidationReport(const ValidationReport& report);
    Result<void> outputAuditRecord(const AuditRecord& record);
    Result<void> outputError(const SanitizerError& error);
    Result<void> outputMessage(const std::string& message);
    Result<void> outputWarning(const std::string& message);

    // The terminal limitation view: grouped under at most four headings and
    // capped at a few lines, with a pointer to the evidence file for the full
    // list. Under --verbose the full list is printed here instead, with IDs,
    // and it is not printed again at the end of the run.
    //
    // `evidencePath` is the file the full list is in. `alreadyPrinted` tells
    // the caller whether the full list has already gone to the terminal, so
    // the same list is never shown twice in one run.
    Result<void> outputLimitations(const LimitationSet& limitations,
                                   const std::string& evidencePath);
    bool fullLimitationListPrinted() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    bool jsonOutput_ = false;
    bool verbose_ = false;
    // Set once the full limitation list has gone to the terminal, so the
    // end-of-run summary does not print it a second time.
    bool fullListPrinted_ = false;
};

} // namespace ledgerase
