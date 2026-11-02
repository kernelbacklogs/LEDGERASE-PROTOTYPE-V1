// The evidence index: SQLite records that point at evidence bundles, and the
// commands that find, verify and fetch what they point at.
//
// Two layers are tested. The library tests drive the schema, idempotent
// registration, annotations, foreign keys, backup and restore directly. The
// CLI tests drive the same behaviour through the real binary, because the
// command wiring is where a record can be registered under the wrong ID or a
// corrupt bundle can be exported anyway.
//
// Nothing here touches a block device: the sanitization runs are against small
// disk images under the temporary directory, and the evidence store and
// database are both temporary.

#include "ledgerase/database.hpp"
#include "ledgerase/evidence.hpp"

#include "test_support.hpp"

#include <sqlite3.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using namespace ledgerase;

int g_failures = 0;
int g_skipped = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

void skip(const std::string& what) {
    std::printf("  SKIP %s\n", what.c_str());
    ++g_skipped;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string readWhole(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void writeWhole(const fs::path& path, const std::string& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << bytes;
}

int modeOf(const fs::path& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0) {
        return -1;
    }
    return static_cast<int>(info.st_mode & 0777);
}

#ifdef LEDGERASE_CLI_PATH
std::string runCli(const std::vector<std::string>& arguments) {
    std::string command = std::string(LEDGERASE_CLI_PATH);
    for (const std::string& argument : arguments) {
        command += " '" + argument + "'";
    }
    command += " 2>&1";
    std::FILE* pipe = ::popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return {};
    }
    std::string output;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    ::pclose(pipe);
    return output;
}
#endif

#ifdef LEDGERASE_CLI_PATH
fs::path makeImage(const fs::path& dir, const std::string& name) {
    const fs::path target = dir / name;
    std::ofstream out(target, std::ios::binary | std::ios::trunc);
    const std::vector<char> zeros(64 * 1024, 0);
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    return target;
}
#endif

// ---------------------------------------------------------------------------
// Library-level tests
// ---------------------------------------------------------------------------

void testLibrarySchemaAndRegistration(const fs::path& dir) {
    std::printf("library: schema creation, registration, idempotency\n");
    const fs::path dbPath = dir / "lib" / "db-state" / "lib.db";
    const fs::path bundle = dir / "lib" / "bundle.json";
    fs::create_directories(bundle.parent_path());
    writeWhole(bundle, "{\"schema\":\"ledgerase.evidence_bundle/3\"}\n");

    auto opened = EvidenceDatabase::open(dbPath.string(), true);
    check(opened.ok(), "the database can be created");
    if (opened.isError()) {
        return;
    }
    auto initialised = opened.value().initialize();
    check(initialised.ok(), "schema migrations apply");
    check(opened.value().schemaVersion() == 1, "the schema version is 1");
    check(modeOf(dbPath) == 0600, "the database file is owner-only");
    check(modeOf(dbPath.parent_path()) == 0700,
          "the database directory is owner-only");

    EvidenceRegistration registration;
    registration.record.jobId = "JOB-LIB-1";
    registration.record.operation = "drive-erasure";
    registration.record.target = "/dev/example";
    registration.record.targetType = "USB";
    registration.record.deviceModel = "Example Stick";
    registration.record.status = "SUCCESS";
    registration.record.createdAt = "2026-01-02T03:04:05Z";
    registration.record.bundlePath = bundle.string();
    registration.record.bundleSha256 = std::string(64, 'a');
    registration.record.formatVersion = "ledgerase.evidence_bundle/3";
    registration.job.jobId = "JOB-LIB-1";
    registration.job.operation = "drive-erasure";
    registration.job.status = "SUCCESS";
    EvidenceArtifactRow artifact;
    artifact.artifactType = "sanitization-bundle";
    artifact.path = bundle.string();
    artifact.fileSize = readWhole(bundle).size();
    artifact.sha256 = std::string(64, 'a');
    registration.artifacts.push_back(artifact);

    auto first = opened.value().registerEvidence(registration);
    check(first.ok(), "an evidence record is registered");
    if (first.isError()) {
        return;
    }
    check(first.value().evidenceId == "EV-00001",
          "the first record gets EV-00001");
    check(first.value().jobId == "JOB-LIB-1", "the job ID is preserved");

    auto again = opened.value().registerEvidence(registration);
    check(again.ok() && again.value().evidenceId == first.value().evidenceId,
          "registering the same job again returns the same evidence ID");

    auto byId = opened.value().recordForEvidenceId("EV-00001");
    check(byId.ok() && byId.value().description.empty(),
          "the record can be read back without a description");
    auto byJob = opened.value().recordForJob("JOB-LIB-1");
    check(byJob.ok() && byJob.value().evidenceId == "EV-00001",
          "the record can be found by job ID");

    auto page = opened.value().list(10, 0, true);
    check(page.ok() && page.value().total == 1,
          "a list reports one matching record");

    auto annotated = opened.value().annotate("EV-00001", "Library test", "tester");
    check(annotated.ok(), "a description can be annotated");
    auto after = opened.value().recordForEvidenceId("EV-00001");
    check(after.ok() && after.value().description == "Library test",
          "the annotation becomes searchable metadata");

    EvidenceSearchQuery query;
    query.query = "library";
    auto found = opened.value().search(query, 10, 0, true);
    check(found.ok() && found.value().total == 1,
          "search by description finds the record");

    auto missing = opened.value().recordForEvidenceId("EV-99999");
    check(missing.isError(), "an unknown evidence ID is refused");
    auto badAnnotation = opened.value().annotate("EV-99999", "x", "tester");
    check(badAnnotation.isError(), "annotating an unknown record is refused");

    VerificationResultRow verification;
    verification.evidenceId = "EV-00001";
    verification.jobId = "JOB-LIB-1";
    verification.status = "VERIFIED";
    verification.verifiedHash = std::string(64, 'a');
    verification.signatureStatus = "not checked";
    check(opened.value().recordVerification(verification).ok(),
          "a verification result is recorded");
    auto status = opened.value().status();
    check(status.ok() && status.value().evidenceCount == 1 &&
              status.value().verificationCount == 1,
          "database status counts the record and verification");

    // Foreign keys are enforced, not merely declared.
    sqlite3* raw = nullptr;
    if (sqlite3_open_v2(dbPath.c_str(), &raw,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX,
                        nullptr) == SQLITE_OK) {
        sqlite3_exec(raw, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
        sqlite3_stmt* statement = nullptr;
        const char* sql =
            "INSERT INTO evidence_artifacts(evidence_id, job_id, artifact_type, "
            "path, file_size, sha256) VALUES('EV-NOPE', 'JOB-NOPE', 'x', '/tmp/x', "
            "1, 'h');";
        if (sqlite3_prepare_v2(raw, sql, -1, &statement, nullptr) == SQLITE_OK) {
            check(sqlite3_step(statement) == SQLITE_CONSTRAINT,
                  "a foreign key rejects an artifact for an unknown evidence ID");
            sqlite3_finalize(statement);
        }
        sqlite3_close(raw);
    }

    // Backup contains the database and the artifact, and restores.
    const fs::path backupDir = dir / "lib-backup";
    auto backup = opened.value().backupTo(backupDir.string(), false);
    if (backup.isError()) {
        // The synthetic artifact's hash does not match the bytes, so the backup
        // must refuse to present itself as complete. That is the point.
        check(contains(backup.error().what(), "incomplete"),
              "a backup with an unverifiable artifact is reported incomplete");
    } else {
        check(fs::exists(backupDir / "ledgerase.db"),
              "the backup contains a SQLite database");
        check(fs::exists(backupDir / "backup.json"),
              "the backup contains a manifest");
        const fs::path restored = dir / "lib-restored.db";
        auto restoredResult =
            EvidenceDatabase::restoreFrom(backupDir.string(), restored.string(),
                                          false);
        check(restoredResult.ok(), "the backup restores to a new path");
        auto reopened = EvidenceDatabase::open(restored.string(), false);
        check(reopened.ok() &&
                  reopened.value().recordForEvidenceId("EV-00001").ok(),
              "the restored database has the record");
    }
}

void testLibraryConsistency(const fs::path& dir) {
    std::printf("library: consistency findings\n");
    const fs::path dbPath = dir / "consistency" / "c.db";
    auto opened = EvidenceDatabase::open(dbPath.string(), true);
    if (opened.isError()) {
        skip("the consistency database could not be created");
        return;
    }
    (void)opened.value().initialize();

    EvidenceRegistration registration;
    registration.record.jobId = "JOB-C-1";
    registration.record.operation = "file-erasure";
    registration.record.status = "SUCCESS";
    registration.record.createdAt = "2026-01-02T03:04:05Z";
    registration.record.bundlePath = (dir / "does-not-exist.json").string();
    registration.record.bundleSha256 = std::string(64, 'b');
    registration.job.jobId = "JOB-C-1";
    registration.job.operation = "file-erasure";
    registration.job.status = "SUCCESS";
    auto registered = opened.value().registerEvidence(registration);
    check(registered.ok(), "a record without artifacts is accepted by the schema");
    if (!registered.ok()) {
        return;
    }

    auto report = opened.value().consistency(
        [](const EvidenceArtifactRow&) { return Result<void>::success(); });
    check(report.ok() && !report.value().ok(),
          "a record with no artifact is a consistency finding");
    check(report.ok() && report.value().findings.front().kind ==
                             "missing-artifact-reference",
          "the finding names the missing artifact reference");
}

#ifdef LEDGERASE_CLI_PATH
// ---------------------------------------------------------------------------
// CLI tests
// ---------------------------------------------------------------------------

void testCliRegistration(const fs::path& dir, const fs::path& dbPath) {
    std::printf("cli: initialisation and registration\n");
    const std::string beforeInit =
        runCli({"evidence", "db", "status", "--db", (dir / "no.db").string()});
    check(contains(beforeInit, "No evidence database"),
          "status on a missing database says there is none");

    const std::string initialised =
        runCli({"evidence", "db", "init", "--db", dbPath.string()});
    check(contains(initialised, "initialised") && contains(initialised, "Schema: 1"),
          "evidence db init creates the index");
    check(fs::exists(dbPath) && modeOf(dbPath) == 0600,
          "the database is private to its owner");

    const fs::path target = makeImage(dir, "first.img");
    const std::string run =
        runCli({"sanitize", target.string(), "--assurance", "clear", "--force",
                "--no-progress", "--description",
                "College laboratory USB sanitization"});
    check(contains(run, "Evidence ID: EV-00001"),
          "a sanitization is registered as EV-00001 (output: " +
              run.substr(0, 80) + ")");

    const std::string listing = runCli({"evidence", "list"});
    check(contains(listing, "EV-00001"), "the record appears in evidence list");
    check(contains(listing, "College laboratory USB sanitization"),
          "the list shows the description");
    check(contains(listing, "drive-erasure"), "the list shows the operation");

    const std::string shown = runCli({"evidence", "show", "EV-00001"});
    check(contains(shown, "SELECTED EVIDENCE: EV-00001"),
          "evidence show finds the record by its permanent ID");
    check(contains(shown, "SANITIZATION") || contains(shown, "sanitization-bundle"),
          "the record names its artifact");
}

void testCliSearch(const fs::path& dir) {
    std::printf("cli: search filters and empty results\n");
    const fs::path second = makeImage(dir, "second.img");
    runCli({"sanitize", second.string(), "--assurance", "clear", "--force",
            "--no-progress", "--description",
            "Personal laptop SSD before resale"});

    const std::string byText = runCli({"evidence", "search", "--query", "laptop"});
    check(contains(byText, "Personal laptop SSD before resale"),
          "a general query matches the description");
    check(!contains(byText, "College laboratory"),
          "a general query does not return unrelated records");

    const std::string byOperation =
        runCli({"evidence", "search", "--operation", "drive-erasure",
                "--status", "SUCCESS"});
    check(contains(byOperation, "EV-00001") && contains(byOperation, "EV-00002"),
          "combined operation and status filters match both records");

    const std::string byDate =
        runCli({"evidence", "search", "--date", "2026-11-02"});
    check(contains(byDate, "EV-0000"), "a date filter matches today's records");

    const std::string fromTo =
        runCli({"evidence", "search", "--from", "2020-01-01", "--to", "2020-01-02"});
    check(contains(fromTo, "No evidence records match"),
          "a date range in the past returns nothing");

    const std::string failed =
        runCli({"evidence", "search", "--status", "FAILED"});
    check(contains(failed, "No evidence records match"),
          "a status filter that matches nothing is empty, not an error");

    const std::string empty = runCli({"evidence", "search", "--query", "zzzz"});
    check(contains(empty, "No evidence records match"),
          "an empty search result is reported clearly");
}

void testCliAnnotation(const fs::path& dbPath) {
    std::printf("cli: descriptions are annotations, not edits\n");
    auto opened = EvidenceDatabase::open(dbPath.string(), false);
    if (opened.isError()) {
        skip("the database could not be reopened");
        return;
    }
    auto before = opened.value().recordForEvidenceId("EV-00001");
    if (before.isError()) {
        skip("EV-00001 is not present");
        return;
    }
    const std::string bytesBefore = readWhole(before.value().bundlePath);

    const std::string described =
        runCli({"evidence", "describe", "EV-00001", "--description",
                "Lab USB, rack 4"});
    check(contains(described, "annotation"), "the change is described as an annotation");

    const std::string shown = runCli({"evidence", "show", "EV-00001"});
    check(contains(shown, "Lab USB, rack 4"), "the new description is shown");
    const std::string searched =
        runCli({"evidence", "search", "--query", "rack 4"});
    check(contains(searched, "EV-00001"), "the new description is searchable");

    const std::string bytesAfter = readWhole(before.value().bundlePath);
    check(bytesBefore == bytesAfter,
          "the signed bundle's bytes are unchanged by a description change");
    const std::string verified = runCli({"evidence", "verify", "EV-00001"});
    check(contains(verified, "verified"),
          "the bundle still verifies after the annotation");
}

void testCliVerificationAndFetch(const fs::path& dir) {
    std::printf("cli: verify, fetch, corruption and missing artifacts\n");
    auto opened = EvidenceDatabase::open(
        (dir / "state" / "ledgerase.db").string(), false);
    if (opened.isError()) {
        skip("the database could not be reopened");
        return;
    }
    auto record = opened.value().recordForEvidenceId("EV-00001");
    if (record.isError()) {
        skip("EV-00001 is not present");
        return;
    }
    const fs::path bundle = record.value().bundlePath;

    const std::string verified = runCli({"evidence", "verify", "EV-00001"});
    check(contains(verified, "verified"), "an intact record verifies");
    check(contains(verified, "not authentication"),
          "hash verification is not presented as authentication");

    const fs::path exportDir = dir / "export-1";
    const std::string fetched =
        runCli({"evidence", "fetch", "EV-00001", "--output", exportDir.string()});
    check(contains(fetched, "Retrieved EV-00001"), "fetch retrieves the record");
    check(contains(fetched, "Integrity: verified"), "fetch verifies before export");
    const fs::path exported = exportDir / bundle.filename();
    check(fs::exists(exported), "the bundle is written to the output directory");
    check(readWhole(exported) == readWhole(bundle),
          "the export is byte-for-byte the original");
    check(readWhole(bundle).size() > 0 && fs::exists(bundle),
          "the original evidence file is preserved");

    const std::string collision =
        runCli({"evidence", "fetch", "EV-00001", "--output", exportDir.string()});
    check(contains(collision, "Refusing to overwrite"),
          "a second fetch does not silently overwrite the export");

    const fs::path exportForced = dir / "export-forced";
    const std::string forced =
        runCli({"evidence", "fetch", "EV-00001", "--output", exportForced.string(),
                "--force"});
    check(contains(forced, "Retrieved EV-00001"), "fetch accepts --force");

    const fs::path shorthandDir = dir / "export-shorthand";
    const std::string shorthand =
        runCli({"--fetch", "EV-00001", "--output", shorthandDir.string()});
    check(contains(shorthand, "Retrieved EV-00001"),
          "the --fetch shorthand runs the same fetch implementation");
    check(fs::exists(shorthandDir / bundle.filename()),
          "the shorthand wrote the evidence");

    const std::string backupDir = (dir / "backup").string();
    const std::string backup = runCli({"evidence", "backup", backupDir});
    check(contains(backup, "Evidence backup written"),
          "a backup is written (or reported incomplete)");
    check(fs::exists(fs::path(backupDir) / "ledgerase.db") || contains(backup, "incomplete"),
          "the backup holds the database when it completes");

    const std::string copy = readWhole(bundle);
    writeWhole(bundle, copy + "tamper");
    const std::string corrupted = runCli({"evidence", "verify", "EV-00001"});
    check(contains(corrupted, "SHA-256 MISMATCH") || contains(corrupted, "NOT verified"),
          "a modified artifact is detected");
    const fs::path badExport = dir / "export-bad";
    const std::string refused =
        runCli({"evidence", "fetch", "EV-00001", "--output", badExport.string()});
    check(contains(refused, "Refusing to export"),
          "a corrupted artifact is not exported as verified evidence");
    check(!fs::exists(badExport / bundle.filename()) ||
              readWhole(badExport / bundle.filename()) != readWhole(bundle),
          "no verified-looking copy of the corrupted file is produced");
    writeWhole(bundle, copy);

    std::error_code ec;
    const fs::path hidden = bundle.string() + ".hidden";
    fs::rename(bundle, hidden, ec);
    const std::string missing = runCli({"evidence", "verify", "EV-00001"});
    check(contains(missing, "missing") || contains(missing, "NOT verified"),
          "a missing artifact is detected");
    fs::rename(hidden, bundle, ec);
    const std::string restored = runCli({"evidence", "verify", "EV-00001"});
    check(contains(restored, "verified"), "the evidence verifies again once restored");
}

void testCliBackupRestore(const fs::path& dir) {
    std::printf("cli: backup and restore consistency\n");
    const fs::path backupDir = dir / "backup-cli";
    const std::string made = runCli({"evidence", "backup", backupDir.string()});
    if (contains(made, "incomplete") || !fs::exists(backupDir / "ledgerase.db")) {
        skip("a complete backup could not be produced here");
        return;
    }
    check(fs::exists(backupDir / "backup.json"),
          "the backup includes a manifest");
    check(fs::exists(backupDir / "artifacts"),
          "the backup includes copies of the artifacts");

    const fs::path restored = dir / "state" / "restored.db";
    const std::string restore =
        runCli({"evidence", "restore", backupDir.string(), "--db", restored.string()});
    check(contains(restore, "restored to"), "the backup restores to a new database");
    const std::string listing =
        runCli({"evidence", "list", "--db", restored.string()});
    check(contains(listing, "EV-00001"), "the restored database lists the record");

    const std::string overwrite =
        runCli({"evidence", "restore", backupDir.string(), "--db", restored.string()});
    check(contains(overwrite, "Refusing to overwrite"),
          "restore does not overwrite an existing database without --force");

    // A backup whose artifact copy was altered is refused, not installed.
    const fs::path damaged = dir / "backup-damaged";
    runCli({"evidence", "backup", damaged.string()});
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(damaged / "artifacts", ec)) {
        const std::string text = readWhole(entry.path());
        writeWhole(entry.path(), text + "tamper");
        break;
    }
    const std::string refused = runCli(
        {"evidence", "restore", damaged.string(), "--db",
         (dir / "state" / "damaged-restore.db").string()});
    check(contains(refused, "does not match") || contains(refused, "incomplete") ||
              contains(refused, "Refusing"),
          "a damaged backup is not restored");
}

void testCliConsistency(const fs::path& dir) {
    std::printf("cli: consistency check and orphan detection\n");
    const std::string healthy = runCli({"evidence", "check"});
    check(contains(healthy, "No inconsistencies found"),
          "a healthy index and evidence store have no findings");

    const fs::path otherDb = dir / "other-state" / "other.db";
    const fs::path target = makeImage(dir, "orphan.img");
    runCli({"sanitize", target.string(), "--assurance", "clear", "--force",
            "--no-progress", "--description", "Orphan candidate", "--db",
            otherDb.string()});

    const std::string checked = runCli({"evidence", "check"});
    check(contains(checked, "orphan-file"),
          "a bundle registered in another database is reported as orphaned");

    // Select the orphan out of the store so the remaining state is clean.
    auto other = EvidenceDatabase::open(otherDb.string(), false);
    if (other.ok()) {
        auto otherPage = other.value().list(10, 0, true);
        if (otherPage.ok()) {
            for (const EvidenceRecordRow& row : otherPage.value().records) {
                std::error_code ec;
                fs::remove(row.bundlePath, ec);
            }
        }
    }
}

void testCliPagination(const fs::path& dir) {
    std::printf("cli: pagination and non-interactive selection\n");
    const fs::path third = makeImage(dir, "third.img");
    runCli({"sanitize", third.string(), "--assurance", "clear", "--force",
            "--no-progress", "--description", "Third record"});
    const std::string firstPage = runCli({"evidence", "list", "--limit", "2"});
    check(contains(firstPage, "Showing 1-"), "the first page is labelled");
    check(contains(firstPage, "Use --page 2"),
          "a next-page hint is shown when more records exist");

    const std::string selected =
        runCli({"evidence", "search", "--query", "e", "--select", "1",
                "--no-interactive"});
    check(contains(selected, "1 MATCHING") || contains(selected, "SELECTED EVIDENCE") ||
              contains(selected, "MATCHING"),
          "a numbered search result can be selected non-interactively");

    const std::string invalid = runCli(
        {"evidence", "search", "--query", "e", "--select", "999",
         "--no-interactive"});
    check(contains(invalid, "out of range"),
          "an invalid selection is refused, not ignored");
}
#endif

} // namespace

int main() {
    const fs::path dir =
        fs::temp_directory_path() /
        ("ledgerase-evidence-db-test-" +
         std::to_string(static_cast<long long>(::getpid())));
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    const fs::path stateDir = dir / "state";
    const fs::path dbPath = stateDir / "ledgerase.db";
    const fs::path evidenceDir = dir / "evidence";
    ::setenv("LEDGERASE_DB", dbPath.c_str(), 1);
    ::setenv("LEDGERASE_EVIDENCE_DIR", evidenceDir.c_str(), 1);

    testLibrarySchemaAndRegistration(dir);
    testLibraryConsistency(dir);

#ifdef LEDGERASE_CLI_PATH
    testCliRegistration(dir, dbPath);
    testCliSearch(dir);
    testCliAnnotation(dbPath);
    testCliVerificationAndFetch(dir);
    testCliBackupRestore(dir);
    testCliConsistency(dir);
    testCliPagination(dir);
#else
    skip("the CLI is not built, so its evidence commands were not exercised.");
#endif

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        if (g_skipped > 0) {
            return kSkipExitCode;
        }
        std::printf("\nAll evidence-database checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
