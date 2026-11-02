#pragma once

// The evidence index.
//
// The bundles on disk are the system of record: a third party verifies one
// without this database, and every command that answers a question about
// authenticity reads the file. SQLite holds only an index of those bundles -
// the stable Evidence ID, a description the operator can search on, and
// references to the files - so a lost or corrupt database costs discovery, not
// evidence.
//
// The two stores are kept consistent in one direction: a bundle is written and
// verified first, then registered here. A registration that fails leaves a
// valid bundle and a stale index, which `evidence check` reports. The reverse
// (a database row with no bundle) is reported the same way and is never
// presented as verified evidence.

#include "ledgerase/error.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ledgerase {

// A stable, human-readable identifier. It is allocated once and never reused,
// so a description can change without the record's identity changing.
std::string evidenceIdForNumber(int64_t number);

// Where the index lives when the operator does not name a path.
std::string defaultDatabasePath();

struct EvidenceJobRow {
    std::string jobId;
    std::string operation;
    std::string status;
    std::string startedAt;
    std::string completedAt;
    std::string applicationVersion;
    std::string evidenceFormatVersion;
    std::string deviceId;
    std::string method;
    std::string result;
    std::string error;
};

struct EvidenceDeviceRow {
    std::string deviceId;
    std::string deviceType;
    std::string manufacturer;
    std::string model;
    uint64_t capacityBytes = 0;
    uint64_t logicalSectorSize = 0;
    // A display label, not a hardware serial. Serial numbers are deliberately
    // not indexed: the bundle already carries what the device reported, and a
    // searchable copy of a hardware identifier is a disclosure the index does
    // not need.
    std::string identifiers;
};

struct EvidenceArtifactRow {
    int64_t artifactId = 0;
    std::string evidenceId;
    std::string jobId;
    std::string artifactType;
    std::string path;
    uint64_t fileSize = 0;
    std::string sha256;
    std::string formatVersion;
    std::string createdAt;
    std::string signatureKeyId;
    bool signaturePresent = false;
};

struct EvidenceChainRow {
    uint64_t sequence = 0;
    std::string timestamp;
    std::string type;
    std::string payload;
    std::string prevHash;
    std::string recordHash;
};

struct EvidenceRecordRow {
    std::string evidenceId;
    std::string jobId;
    std::string description;
    std::string operation;
    std::string target;
    std::string targetType;
    std::string deviceModel;
    std::string status;
    std::string createdAt;
    std::string bundlePath;
    std::string bundleSha256;
    std::string formatVersion;
};

struct EvidenceRegistration {
    EvidenceRecordRow record;
    EvidenceJobRow job;
    std::optional<EvidenceDeviceRow> device;
    std::vector<EvidenceChainRow> events;
    std::vector<EvidenceArtifactRow> artifacts;
};

struct EvidenceSearchQuery {
    std::string query;
    std::string evidenceId;
    std::string operation;
    std::string status;
    std::string targetType;
    std::string deviceModel;
    std::string jobId;
    std::string date;
    std::string fromDate;
    std::string toDate;
};

struct EvidencePage {
    std::vector<EvidenceRecordRow> records;
    int total = 0;
};

struct VerificationResultRow {
    std::string evidenceId;
    std::string jobId;
    std::string timestamp;
    std::string status;
    std::string verifiedHash;
    std::string signatureStatus;
    std::string error;
};

struct EvidenceMigrationRow {
    std::string evidenceId;
    std::string originalBundle;
    std::string originalHash;
    std::string resultingBundle;
    std::string resultingHash;
    std::string sourceVersion;
    std::string destinationVersion;
    std::string status;
    std::string timestamp;
};

struct DatabaseStatus {
    std::string path;
    bool exists = false;
    int schemaVersion = 0;
    int evidenceCount = 0;
    int jobCount = 0;
    int artifactCount = 0;
    int verificationCount = 0;
    int migrationCount = 0;
    std::string journalMode;
    uint64_t sizeBytes = 0;
};

struct ConsistencyFinding {
    std::string evidenceId;
    std::string kind;
    std::string detail;
};

struct ConsistencyReport {
    int checked = 0;
    std::vector<ConsistencyFinding> findings;
    bool ok() const { return findings.empty(); }
};

// The index. One connection is opened per command and closed with it; the
// database is initialised on first use and upgraded through explicit
// migrations, never by recreating a table.
class EvidenceDatabase {
public:
    // `create` controls whether a missing file is made. Opening an existing
    // database never overwrites it.
    static Result<EvidenceDatabase> open(const std::string& path, bool create);

    EvidenceDatabase(EvidenceDatabase&&) noexcept;
    EvidenceDatabase& operator=(EvidenceDatabase&&) noexcept;
    ~EvidenceDatabase();

    EvidenceDatabase(const EvidenceDatabase&) = delete;
    EvidenceDatabase& operator=(const EvidenceDatabase&) = delete;

    // Applies pending schema migrations. Safe to call on every open.
    Result<void> initialize();
    int schemaVersion() const;

    // Idempotent by job: registering the same job twice returns the row that
    // already exists rather than allocating a second Evidence ID.
    Result<EvidenceRecordRow> registerEvidence(const EvidenceRegistration& input);

    Result<EvidenceRecordRow> recordForEvidenceId(const std::string& evidenceId) const;
    Result<EvidenceRecordRow> recordForJob(const std::string& jobId) const;
    Result<std::vector<EvidenceArtifactRow>> artifactsFor(const std::string& evidenceId) const;
    Result<std::vector<EvidenceChainRow>> chainFor(const std::string& evidenceId) const;

    Result<EvidencePage> list(int limit, int offset, bool newestFirst) const;
    Result<EvidencePage> search(const EvidenceSearchQuery& query, int limit,
                                int offset, bool newestFirst) const;

    // A description change is an annotation, not an edit of evidence: the
    // previous value and the time of the change are kept.
    Result<void> annotate(const std::string& evidenceId, const std::string& description,
                          const std::string& changedBy);

    Result<void> recordVerification(const VerificationResultRow& row);
    Result<void> recordMigration(const EvidenceMigrationRow& row);

    Result<DatabaseStatus> status() const;

    // Checks every registered artifact with the caller's verifier and reports
    // the rows that disagree with the filesystem.
    Result<ConsistencyReport> consistency(
        const std::function<Result<void>(const EvidenceArtifactRow&)>& verify) const;

    // A backup is a SQLite backup plus a copy of every artifact it references.
    // It reports failure when an artifact is missing, because a database-only
    // copy is not a complete evidence backup.
    Result<void> backupTo(const std::string& directory, bool overwrite);

    // Restores a database from a backup directory to `targetPath`. The backup
    // manifest is checked, and every artifact copy it lists is hashed first, so
    // a truncated backup is refused rather than installed.
    static Result<void> restoreFrom(const std::string& directory,
                                    const std::string& targetPath, bool overwrite);

private:
    class Impl;
    explicit EvidenceDatabase(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> pImpl_;
};

} // namespace ledgerase
