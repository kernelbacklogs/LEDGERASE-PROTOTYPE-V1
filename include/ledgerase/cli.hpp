#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/evidence.hpp"
#include "ledgerase/carving.hpp"
#include "ledgerase/erasure.hpp"
#include <optional>
#include <string>
#include <vector>
#include <functional>

namespace ledgerase {

// The directory an evidence bundle is written to when the operator does not
// name one. Every sanitization job produces a bundle, so this is the tool's
// single system of record: there is no second, disposable log, and no way to
// run a sanitization that leaves no record behind.
constexpr const char* kDefaultEvidenceDirectory = "evidence";

// Resolves the absolute directory a bundle is written to when --evidence is
// not given, in this order:
//
//   $LEDGERASE_EVIDENCE_DIR   explicit override, used as-is
//   /var/lib/ledgerase/evidence        when running as root
//   $XDG_STATE_HOME/ledgerase/evidence  otherwise
//   ~/.local/state/ledgerase/evidence   otherwise
//
// The pre-rename .../sanitizer/... locations are still tried, after the
// ledgerase ones, so renaming the tool does not strand an existing record set.
//   ./evidence                         only if none of the above is writable
//
// The point is that the location does not depend on the directory the command
// happened to be run from. A relative ./evidence meant a bundle written during
// testing landed in a temp directory, and one written from a container
// vanished with the container. An absolute path can be written down once and
// found again.
std::string defaultEvidenceDirectory();

// Who ran the job, and who the process ran as. Under sudo these differ, and
// the difference is what a certificate has to record: "root" names no person.
// Not a credential and not an authentication mechanism - an attribution label.
struct OperatorIdentity {
    std::string invokingUser = "unknown-operator";
    uint32_t invokingUid = 0;
    std::string effectiveUser = "unknown";
    uint32_t effectiveUid = 0;
    // True when the effective user is not the invoking user.
    bool elevated = false;
};

// Exposed so the behaviour can be tested: the point of the function is what it
// does when SUDO_USER is set, and that cannot be checked while it is hidden.
OperatorIdentity currentOperatorIdentity();

struct CliOptions {
    std::string command;
    std::string devicePath;
    std::string jobId;
    SanitizationCategory assurance = SanitizationCategory::PURGE;
    // False when --assurance was not given, so the refusal can say "the default
    // could not be met" rather than "your request is impossible" - the two
    // need different advice from the operator.
    bool assuranceExplicit = false;
    // Local policy inputs. Supplying all three derives the assurance level;
    // --assurance overrides whatever the policy derives. Partial input derives
    // nothing and says so, rather than filling the gap with a default.
    //
    // These choose a sanitization level by this project's documented policy.
    // They are not a NIST SP 800-88 Rev. 2 mechanism: Rev. 2 defines the three
    // levels (3.1.1-3.1.3) and requires a risk-based decision (4.3.6) without
    // specifying how to reach it, listing considerations to weigh (2.4) rather
    // than a rule to apply. The provenance is carried into the plan, the CLI
    // output and the evidence so the level is never read as the standard's
    // requirement.
    SecurityCategorization policyCategorization = SecurityCategorization::UNSET;
    TriState policyReuseMedia = TriState::UNSET;
    TriState policyLeavingOrgControl = TriState::UNSET;
    SanitizationMethod method = SanitizationMethod::NONE;
    bool dryRun = false;
    bool verbose = false;
    bool jsonOutput = false;
    // Suppresses the progress bar. The bar is also suppressed automatically
    // when stdout is not a terminal or when --json is given.
    bool noProgress = false;
    std::string outputFormat = "text";
    std::string outputFile;
    // File and folder erasure. Each is engaged, not merely declared: a probe
    // count of zero would mean no content check at all, and a pass count is
    // recorded as requested *and* as completed so a partial run is visible.
    uint32_t erasePasses = 1;
    size_t probeCount = 6;
    uint64_t searchLimitBytes = 0;
    // The erase technique, shared with the device eraser. "zero" or "random".
    std::string eraseMethod;
    // The medium to run the residual search over. Empty means the device that
    // holds the file's filesystem, resolved from the mount table. A file inside
    // a disk image needs the image named explicitly, because the image is the
    // medium and the host filesystem it happens to live on is not.
    std::string residualSearchTarget;
    // Skip the residual search. The search is the only step that says what is
    // actually still on the medium, so skipping it is a real loss of assurance -
    // it prints a warning and records the skip and the reason in the evidence.
    bool noResidualSearch = false;
    // Why the operator gave for skipping the residual search, recorded verbatim.
    std::string residualSearchSkipReason;

    // Module 2 (folder). Recursion, pattern filtering and symlink policy. The
    // defaults are the conservative ones: recursive, but never following a
    // symlink out of the folder unless asked.
    bool recursive = false;
    bool followSymlinks = false;
    // --include and --exclude. Empty means "no filter of that kind". A name
    // matches if it matches an --include pattern (when any are given) and no
    // --exclude pattern. Applied to the base name and to the path under the
    // target folder, so "*.log" and "cache/*" both behave as written.
    std::vector<std::string> includePatterns;
    std::vector<std::string> excludePatterns;

    // Module 3 (carve): where recovered files are written. Empty means the
    // report is produced and nothing is written, which is the safe default for
    // a read-only evidence source.
    std::string outputDirectory;
    // Scan tuning. Zero means "use the default".
    size_t chunkSizeBytes = 0;
    uint64_t maxRecoveredBytes = 0;
    // carve only: --minimum-score <0..1>. Engaged rather than optional, because
    // an option that is silently ignored is worse than one that does not exist:
    // an operator who filtered on score and got everything would not know the
    // filter never ran.
    std::optional<double> minimumScore;
    std::string logFile;
    bool simulationMode = false;
    int serialSuffixLength = 6;
    // Non-interactive confirmation. A block device is checked against
    // expectSerial; a file or image against expectName. Both are for scripts,
    // where a prompt cannot be answered.
    std::string expectSerial;
    std::string expectName;
    // --verify sampled|full. SAMPLED reads 64 sectors and reports the coverage;
    // FULL reads every sector, which is a full read of the medium.
    std::string verifyDepth = "sampled";
    bool force = false;
    // Overwrite passes to request, 1..15. Only meaningful for an overwrite
    // method; the policy engine rejects it out of range and the NVMe Sanitize
    // command carries it in the 4-bit OWPASS field.
    uint8_t overwritePassCount = 1;

    // Evidence collection. Every one of these is an operator assertion about
    // something this tool cannot observe for itself, so each one that is
    // omitted becomes a recorded limitation instead of an implicit pass.
    //
    // evidenceFile is an *override* of the default path, not a switch that
    // decides whether a record is written. A job always produces one.
    std::string evidenceFile;        // override the default evidence path
    std::string authorizationRef;    // change ticket / disposition order id
    std::string authorizedBy;
    std::string authorizationBasis;
    std::string scopeRationale;
    std::string copiesNotAddressed;
    std::string verifierName;        // who performed verification
    std::string publicKeyFile;       // Ed25519 public key for verify-log
    std::string privateKeyFile;      // Ed25519 private key for signing
    std::string retentionPolicy;     // organization-defined | contractual | legal-hold
    std::string retainUntil;
    // Set only by an explicit flag. All-copies coverage cannot be inferred.
    bool attestAllCopies = false;
    // Declares that verification was witnessed or performed independently.
    bool attestIndependentVerification = false;
    // Records that identity was confirmed against the physical label.
    bool attestIdentityConfirmed = false;
};

class CliApplication {
public:
    CliApplication();
    ~CliApplication();

    int run(int argc, char* argv[]);

    // Interactive session. Useful for running several commands against the same
    // process, but nothing is held in memory between them: every job's record
    // is the evidence bundle on disk, so a job survives the session and a
    // one-shot invocation produces exactly the same record.
    int runShell();

    Result<void> listDevices(const CliOptions& options);
    Result<void> inspectDevice(const CliOptions& options);
    Result<void> showCapabilities(const CliOptions& options);
    Result<void> createPlan(const CliOptions& options);
    Result<void> sanitize(const CliOptions& options);
    Result<void> verifyJob(const CliOptions& options);
    Result<void> validateJob(const CliOptions& options);
    Result<void> recoverTest(const CliOptions& options);
    Result<void> showReport(const CliOptions& options);
    Result<void> showAudit(const CliOptions& options);
    // Module 2: file and folder erasure, refused per the filesystem matrix.
    Result<void> eraseFileOrFolder(const CliOptions& options);
    // Module 3: signature carving of a medium opened read-only.
    Result<void> carve(const CliOptions& options);
    Result<void> showVersion(const CliOptions& options);

    // Renders the evidence bundle for a job, optionally signing it. Durable,
    // hash-chained, verifiable, and the tool's only system of record.
    Result<void> showEvidence(const CliOptions& options);

    // Verifies an evidence file produced by another run or another tool.
    Result<void> verifyEvidenceFile(const CliOptions& options);

    // The directory the evidence bundles this run produced were written to.
    const std::string& evidenceDirectory() const;

    void setSimulationMode(bool enabled);
    void setVerbose(bool enabled);

    // True when mock devices are in use. Callers must surface this.
    bool isSimulationMode() const;

    // Writes the command summary to stdout.
    static void printUsage();

    // Default evidence path for a job: <evidence dir>/<job id>.json
    static std::string defaultEvidencePath(const std::string& jobId,
                                           const std::string& directory);

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