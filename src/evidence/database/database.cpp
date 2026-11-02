#include "ledgerase/database.hpp"

#include "ledgerase/evidence.hpp"
#include "ledgerase/json_adapters.hpp"

#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ledgerase {
namespace {

namespace fs = std::filesystem;

using Statement = std::unique_ptr<sqlite3_stmt, int (*)(sqlite3_stmt*)>;

constexpr int kCurrentSchemaVersion = 1;

std::string nowTimestamp() {
    return formatTimestamp(std::chrono::system_clock::now());
}

Result<void> execSql(sqlite3* db, const char* sql) {
    char* message = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        std::string text = message != nullptr ? message : "unknown error";
        sqlite3_free(message);
        return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                 "SQLite error: " + text);
    }
    return Result<void>::success();
}

Result<Statement> prepare(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* raw = nullptr;
    const int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr);
    if (rc != SQLITE_OK) {
        return Result<Statement>::err(
            ErrorCode::INTERNAL_ERROR,
            std::string("SQLite prepare failed: ") + sqlite3_errmsg(db) +
                " (statement: " + sql + ")");
    }
    return Result<Statement>::ok(Statement(raw, sqlite3_finalize));
}

Result<void> bindText(sqlite3_stmt* statement, int index, const std::string& value) {
    const int rc = sqlite3_bind_text(statement, index, value.c_str(), -1,
                                     SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                 "SQLite text bind failed");
    }
    return Result<void>::success();
}

Result<void> bindInt64(sqlite3_stmt* statement, int index, int64_t value) {
    const int rc = sqlite3_bind_int64(statement, index, value);
    if (rc != SQLITE_OK) {
        return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                 "SQLite integer bind failed");
    }
    return Result<void>::success();
}

void bindTextOrNull(sqlite3_stmt* statement, int index, const std::string& value) {
    if (value.empty()) {
        sqlite3_bind_null(statement, index);
    } else {
        sqlite3_bind_text(statement, index, value.c_str(), -1, SQLITE_TRANSIENT);
    }
}

std::string columnText(sqlite3_stmt* statement, int index) {
    const unsigned char* text = sqlite3_column_text(statement, index);
    if (text == nullptr) {
        return {};
    }
    return reinterpret_cast<const char*>(text);
}

int64_t columnInt(sqlite3_stmt* statement, int index) {
    return static_cast<int64_t>(sqlite3_column_int64(statement, index));
}

std::string escapeLike(const std::string& input) {
    std::string escaped;
    escaped.reserve(input.size());
    for (char c : input) {
        if (c == '\\' || c == '%' || c == '_') {
            escaped.push_back('\\');
        }
        escaped.push_back(c);
    }
    return escaped;
}

// A transaction that rolls back unless committed.
class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) {}
    ~Transaction() {
        if (active_) {
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        }
    }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    Result<void> begin() {
        const auto started = execSql(db_, "BEGIN IMMEDIATE");
        if (started.isError()) {
            return started;
        }
        active_ = true;
        return Result<void>::success();
    }

    Result<void> commit() {
        const auto done = execSql(db_, "COMMIT");
        if (done.isError()) {
            return done;
        }
        active_ = false;
        return Result<void>::success();
    }

private:
    sqlite3* db_;
    bool active_ = false;
};

constexpr const char* kSelectRecordColumns =
    "evidence_id, job_id, COALESCE(description, ''), operation, "
    "COALESCE(target, ''), COALESCE(target_type, ''), "
    "COALESCE(device_model, ''), status, created_at, bundle_path, "
    "bundle_sha256, COALESCE(format_version, '')";

EvidenceRecordRow readRecord(sqlite3_stmt* statement) {
    EvidenceRecordRow row;
    row.evidenceId = columnText(statement, 0);
    row.jobId = columnText(statement, 1);
    row.description = columnText(statement, 2);
    row.operation = columnText(statement, 3);
    row.target = columnText(statement, 4);
    row.targetType = columnText(statement, 5);
    row.deviceModel = columnText(statement, 6);
    row.status = columnText(statement, 7);
    row.createdAt = columnText(statement, 8);
    row.bundlePath = columnText(statement, 9);
    row.bundleSha256 = columnText(statement, 10);
    row.formatVersion = columnText(statement, 11);
    return row;
}

Result<std::string> sha256OfFile(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return Result<std::string>::err(
            ErrorCode::IO_ERROR,
            "Cannot open " + path + ": " + std::strerror(errno));
    }
    Sha256Stream stream;
    std::vector<uint8_t> buffer(64 * 1024);
    while (true) {
        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            ::close(fd);
            return Result<std::string>::err(
                ErrorCode::IO_ERROR,
                "Failed reading " + path + ": " + std::strerror(saved));
        }
        if (n == 0) {
            break;
        }
        stream.update(buffer.data(), static_cast<size_t>(n));
    }
    ::close(fd);
    return stream.finalHex();
}

std::string randomSuffix() {
    static unsigned counter = 0;
    return std::to_string(static_cast<long long>(::getpid())) + "-" +
           std::to_string(++counter);
}

Result<void> writeAllFd(int fd, const char* data, size_t length) {
    size_t written = 0;
    while (written < length) {
        const ssize_t n = ::write(fd, data + written, length - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     std::string("Write failed: ") +
                                         std::strerror(errno));
        }
        written += static_cast<size_t>(n);
    }
    return Result<void>::success();
}

Result<void> copyFileAtomic(const std::string& source, const std::string& destination,
                            bool overwrite) {
    const int input = ::open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot open " + source + ": " +
                                     std::strerror(errno));
    }

    const fs::path target(destination);
    const fs::path parent = target.parent_path().empty() ? fs::path(".")
                                                         : target.parent_path();
    std::error_code ec;
    if (!fs::exists(parent, ec)) {
        fs::create_directories(parent, ec);
        if (ec) {
            ::close(input);
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + parent.string() + ": " +
                                         ec.message());
        }
        fs::permissions(parent, fs::perms::owner_all,
                        fs::perm_options::replace, ec);
    }

    const std::string temporary =
        (parent / ("." + target.filename().string() + ".tmp-" + randomSuffix())).string();
    const int output = ::open(temporary.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              S_IRUSR | S_IWUSR);
    if (output < 0) {
        ::close(input);
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot create " + temporary + ": " +
                                     std::strerror(errno));
    }

    std::vector<char> buffer(64 * 1024);
    while (true) {
        const ssize_t n = ::read(input, buffer.data(), buffer.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            ::close(input);
            ::close(output);
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Read failed: " + std::string(std::strerror(saved)));
        }
        if (n == 0) {
            break;
        }
        const auto written =
            writeAllFd(output, buffer.data(), static_cast<size_t>(n));
        if (written.isError()) {
            ::close(input);
            ::close(output);
            ::unlink(temporary.c_str());
            return written;
        }
    }
    ::close(input);
    if (::fsync(output) != 0) {
        const int saved = errno;
        ::close(output);
        ::unlink(temporary.c_str());
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Flush failed: " + std::string(std::strerror(saved)));
    }
    ::close(output);

    if (overwrite) {
        if (::rename(temporary.c_str(), destination.c_str()) != 0) {
            const int saved = errno;
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot replace " + destination + ": " +
                                         std::strerror(saved));
        }
    } else {
        if (::link(temporary.c_str(), destination.c_str()) != 0) {
            const int saved = errno;
            ::unlink(temporary.c_str());
            return Result<void>::err(
                ErrorCode::IO_ERROR, "Cannot create " + destination + ": " +
                                         std::strerror(saved),
                saved == EEXIST ? "The file already exists. Use --force to replace it"
                                : "");
        }
        ::unlink(temporary.c_str());
    }
    return Result<void>::success();
}

Result<void> writeTextAtomic(const std::string& path, const std::string& content,
                             bool overwrite) {
    const fs::path target(path);
    const fs::path parent = target.parent_path().empty() ? fs::path(".")
                                                         : target.parent_path();
    std::error_code ec;
    if (!fs::exists(parent, ec)) {
        fs::create_directories(parent, ec);
        if (ec) {
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + parent.string() + ": " +
                                         ec.message());
        }
        fs::permissions(parent, fs::perms::owner_all,
                        fs::perm_options::replace, ec);
    }
    const std::string temporary =
        (parent / ("." + target.filename().string() + ".tmp-" + randomSuffix())).string();
    const int fd = ::open(temporary.c_str(),
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot create " + temporary + ": " +
                                     std::strerror(errno));
    }
    auto written = writeAllFd(fd, content.data(), content.size());
    if (!written.isError()) {
        if (::fsync(fd) != 0) {
            written = Result<void>::err(ErrorCode::IO_ERROR,
                                        std::string("Flush failed: ") +
                                            std::strerror(errno));
        }
    }
    ::close(fd);
    if (written.isError()) {
        ::unlink(temporary.c_str());
        return written;
    }
    if (overwrite) {
        if (::rename(temporary.c_str(), path.c_str()) != 0) {
            const int saved = errno;
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot replace " + path + ": " +
                                         std::strerror(saved));
        }
    } else {
        if (::link(temporary.c_str(), path.c_str()) != 0) {
            const int saved = errno;
            ::unlink(temporary.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + path + ": " +
                                         std::strerror(saved));
        }
        ::unlink(temporary.c_str());
    }
    return Result<void>::success();
}

bool directoryIsEmpty(const fs::path& path) {
    std::error_code ec;
    if (!fs::is_directory(path, ec)) {
        return true;
    }
    return fs::directory_iterator(path, ec) == fs::directory_iterator();
}

} // namespace

class EvidenceDatabase::Impl {
public:
    Impl(sqlite3* connection, std::string path)
        : db_(connection), path_(std::move(path)) {}

    ~Impl() {
        if (db_ != nullptr) {
            sqlite3_close(db_);
        }
    }

    sqlite3* db() const { return db_; }
    const std::string& path() const { return path_; }

private:
    sqlite3* db_ = nullptr;
    std::string path_;
};

std::string evidenceIdForNumber(int64_t number) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "EV-%05lld",
                  static_cast<long long>(number));
    return buffer;
}

std::string defaultDatabasePath() {
    const auto absolute = [](const std::string& path) {
        if (path.empty() || path.front() == '/') {
            return path;
        }
        std::error_code ec;
        const fs::path made = fs::absolute(path, ec);
        return ec ? path : made.lexically_normal().string();
    };

    if (const char* override_path = std::getenv("LEDGERASE_DB")) {
        if (override_path[0] != '\0') {
            return absolute(override_path);
        }
    }

    if (::geteuid() == 0) {
        const fs::path systemPath("/var/lib/ledgerase/ledgerase.db");
        std::error_code ec;
        const fs::path parent = systemPath.parent_path();
        if (fs::exists(parent, ec) || fs::create_directories(parent, ec)) {
            return systemPath.string();
        }
    }

    if (const char* xdg = std::getenv("XDG_STATE_HOME"); xdg != nullptr &&
                                                        xdg[0] != '\0') {
        return absolute(std::string(xdg) + "/ledgerase/ledgerase.db");
    }
    if (const char* home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
        return absolute(std::string(home) + "/.local/state/ledgerase/ledgerase.db");
    }
    // No state directory to anchor to. Relative is a last resort; the help
    // text names it so it is never a silent surprise.
    return "ledgerase.db";
}

EvidenceDatabase::EvidenceDatabase(std::unique_ptr<Impl> impl)
    : pImpl_(std::move(impl)) {}

EvidenceDatabase::EvidenceDatabase(EvidenceDatabase&&) noexcept = default;
EvidenceDatabase& EvidenceDatabase::operator=(EvidenceDatabase&&) noexcept = default;
EvidenceDatabase::~EvidenceDatabase() = default;

Result<EvidenceDatabase> EvidenceDatabase::open(const std::string& path,
                                                bool create) {
    if (path.empty()) {
        return Result<EvidenceDatabase>::err(
            ErrorCode::INVALID_ARGUMENT, "A database path is required");
    }

    std::error_code ec;
    if (!create && !fs::exists(path, ec)) {
        return Result<EvidenceDatabase>::err(
            ErrorCode::DEVICE_NOT_FOUND,
            "No evidence database at " + path,
            "Run 'ledgerase-cli evidence db init' to create one.");
    }

    const fs::path parent = fs::path(path).parent_path();
    if (!parent.empty()) {
        bool created = false;
        if (!fs::exists(parent, ec)) {
            fs::create_directories(parent, ec);
            if (ec) {
                return Result<EvidenceDatabase>::err(
                    ErrorCode::IO_ERROR,
                    "Cannot create the database directory " + parent.string() +
                        ": " + ec.message());
            }
            created = true;
        }
        if (created) {
            std::error_code permEc;
            fs::permissions(parent, fs::perms::owner_all,
                            fs::perm_options::replace, permEc);
        }
    }

    sqlite3* connection = nullptr;
    const int flags = SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0) |
                      SQLITE_OPEN_NOMUTEX;
    const int rc = sqlite3_open_v2(path.c_str(), &connection, flags, nullptr);
    if (rc != SQLITE_OK) {
        const std::string message =
            connection != nullptr ? sqlite3_errmsg(connection) : "unknown error";
        if (connection != nullptr) {
            sqlite3_close(connection);
        }
        return Result<EvidenceDatabase>::err(
            ErrorCode::IO_ERROR, "Cannot open the evidence database " + path +
                                     ": " + message);
    }

    sqlite3_extended_result_codes(connection, 1);
    sqlite3_busy_timeout(connection, 5000);
    (void)::chmod(path.c_str(), S_IRUSR | S_IWUSR);

    const auto foreignKeys = execSql(connection, "PRAGMA foreign_keys = ON;");
    if (foreignKeys.isError()) {
        sqlite3_close(connection);
        return Result<EvidenceDatabase>::err(foreignKeys.error());
    }
    // WAL is used for the index: a reader (list, search) does not block a
    // writer (registration), and the index is written once per job rather than
    // continuously. The database is always closed through the backup API before
    // it is copied, so a WAL file is never mistaken for a complete database.
    const auto journal = execSql(connection, "PRAGMA journal_mode = WAL;");
    if (journal.isError()) {
        sqlite3_close(connection);
        return Result<EvidenceDatabase>::err(journal.error());
    }
    (void)execSql(connection, "PRAGMA synchronous = FULL;");

    return Result<EvidenceDatabase>::ok(
        EvidenceDatabase(std::make_unique<Impl>(connection, path)));
}

int EvidenceDatabase::schemaVersion() const {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(pImpl_->db(), "PRAGMA user_version;", -1, &raw, nullptr) !=
        SQLITE_OK) {
        return 0;
    }
    Statement guard(raw, sqlite3_finalize);
    if (sqlite3_step(guard.get()) != SQLITE_ROW) {
        return 0;
    }
    return static_cast<int>(columnInt(guard.get(), 0));
}

Result<void> EvidenceDatabase::initialize() {
    const int version = schemaVersion();
    if (version > kCurrentSchemaVersion) {
        return Result<void>::err(
            ErrorCode::UNSUPPORTED_OPERATION,
            "The evidence database is at schema version " + std::to_string(version) +
                ", but this build understands " +
                std::to_string(kCurrentSchemaVersion),
            "Upgrade LEDGERASE; an older build must not write to a newer index.");
    }
    if (version == kCurrentSchemaVersion) {
        return Result<void>::success();
    }

    static const char* kSchemaV1 = R"SQL(
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    device_type TEXT,
    manufacturer TEXT,
    model TEXT,
    capacity_bytes INTEGER NOT NULL DEFAULT 0,
    logical_sector_size INTEGER NOT NULL DEFAULT 0,
    identifiers TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    application_version TEXT,
    evidence_format_version TEXT,
    device_id TEXT REFERENCES devices(device_id),
    method TEXT,
    result TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE RESTRICT,
    description TEXT,
    operation TEXT NOT NULL,
    target TEXT,
    target_type TEXT,
    device_model TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    bundle_path TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    format_version TEXT,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_annotations (
    annotation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    changed_by TEXT
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
    job_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    format_version TEXT,
    created_at TEXT,
    signature_key_id TEXT,
    signature_present INTEGER NOT NULL DEFAULT 0,
    UNIQUE(evidence_id, artifact_type, path)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
    job_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    UNIQUE(evidence_id, sequence_number)
);

CREATE TABLE IF NOT EXISTS verification_results (
    verification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
    job_id TEXT,
    verified_at TEXT NOT NULL,
    status TEXT NOT NULL,
    verified_hash TEXT,
    signature_status TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS evidence_migrations (
    migration_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    original_bundle TEXT NOT NULL,
    original_hash TEXT,
    resulting_bundle TEXT,
    resulting_hash TEXT,
    source_version TEXT,
    destination_version TEXT,
    status TEXT NOT NULL,
    migrated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_created
    ON evidence_records(created_at DESC, evidence_id DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_operation ON evidence_records(operation);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence_records(status);
CREATE INDEX IF NOT EXISTS idx_evidence_target_type ON evidence_records(target_type);
CREATE INDEX IF NOT EXISTS idx_evidence_model ON evidence_records(device_model);
CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON evidence_artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_events_evidence
    ON audit_events(evidence_id, sequence_number);
CREATE INDEX IF NOT EXISTS idx_verification_evidence
    ON verification_results(evidence_id, verified_at DESC);
)SQL";

    Transaction transaction(pImpl_->db());
    auto started = transaction.begin();
    if (started.isError()) {
        return started;
    }
    auto created = execSql(pImpl_->db(), kSchemaV1);
    if (created.isError()) {
        return created;
    }
    auto recorded = execSql(pImpl_->db(), "PRAGMA user_version = 1;");
    if (recorded.isError()) {
        return recorded;
    }
    auto statement = prepare(pImpl_->db(),
                             "INSERT OR IGNORE INTO schema_migrations"
                             "(version, applied_at, description) VALUES(?, ?, ?);");
    if (statement.isError()) {
        return statement.error();
    }
    const std::string appliedAt = nowTimestamp();
    (void)bindInt64(statement.value().get(), 1, kCurrentSchemaVersion);
    (void)bindText(statement.value().get(), 2, appliedAt);
    (void)bindText(statement.value().get(), 3,
                   "initial evidence index schema");
    if (sqlite3_step(statement.value().get()) != SQLITE_DONE) {
        return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                 std::string("Cannot record the schema version: ") +
                                     sqlite3_errmsg(pImpl_->db()));
    }
    return transaction.commit();
}

Result<EvidenceRecordRow> EvidenceDatabase::registerEvidence(
    const EvidenceRegistration& input) {
    if (input.record.jobId.empty()) {
        return Result<EvidenceRecordRow>::err(
            ErrorCode::INVALID_ARGUMENT, "A registration needs a job ID");
    }
    if (input.record.bundlePath.empty()) {
        return Result<EvidenceRecordRow>::err(
            ErrorCode::INVALID_ARGUMENT, "A registration needs a bundle path");
    }
    auto initialised = initialize();
    if (initialised.isError()) {
        return Result<EvidenceRecordRow>::err(initialised.error());
    }

    Transaction transaction(pImpl_->db());
    auto started = transaction.begin();
    if (started.isError()) {
        return Result<EvidenceRecordRow>::err(started.error());
    }

    {
        auto existing = prepare(pImpl_->db(),
                                std::string("SELECT ") + kSelectRecordColumns +
                                    " FROM evidence_records WHERE job_id = ?;");
        if (existing.isError()) {
            return Result<EvidenceRecordRow>::err(existing.error());
        }
        (void)bindText(existing.value().get(), 1, input.record.jobId);
        if (sqlite3_step(existing.value().get()) == SQLITE_ROW) {
            const EvidenceRecordRow row = readRecord(existing.value().get());
            auto committed = transaction.commit();
            if (committed.isError()) {
                return Result<EvidenceRecordRow>::err(committed.error());
            }
            return Result<EvidenceRecordRow>::ok(row);
        }
    }

    int64_t number = 1;
    {
        auto next = prepare(pImpl_->db(),
                            "SELECT COALESCE(MAX(CAST(SUBSTR(evidence_id, 4) AS "
                            "INTEGER)), 0) + 1 FROM evidence_records;");
        if (next.isError()) {
            return Result<EvidenceRecordRow>::err(next.error());
        }
        if (sqlite3_step(next.value().get()) == SQLITE_ROW) {
            number = columnInt(next.value().get(), 0);
        }
    }

    EvidenceRecordRow record = input.record;
    record.evidenceId = evidenceIdForNumber(number);
    if (record.createdAt.empty()) {
        record.createdAt = nowTimestamp();
    }

    if (input.device.has_value()) {
        const EvidenceDeviceRow& device = *input.device;
        auto inserted = prepare(
            pImpl_->db(),
            "INSERT INTO devices(device_id, device_type, manufacturer, model, "
            "capacity_bytes, logical_sector_size, identifiers) VALUES(?, ?, ?, ?, "
            "?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET "
            "device_type = excluded.device_type, manufacturer = excluded.manufacturer, "
            "model = excluded.model, capacity_bytes = excluded.capacity_bytes, "
            "logical_sector_size = excluded.logical_sector_size, "
            "identifiers = excluded.identifiers;");
        if (inserted.isError()) {
            return Result<EvidenceRecordRow>::err(inserted.error());
        }
        auto statement = std::move(inserted.value());
        (void)bindText(statement.get(), 1, device.deviceId);
        (void)bindText(statement.get(), 2, device.deviceType);
        (void)bindText(statement.get(), 3, device.manufacturer);
        (void)bindText(statement.get(), 4, device.model);
        (void)bindInt64(statement.get(), 5, static_cast<int64_t>(device.capacityBytes));
        (void)bindInt64(statement.get(), 6,
                        static_cast<int64_t>(device.logicalSectorSize));
        (void)bindText(statement.get(), 7, device.identifiers);
        if (sqlite3_step(statement.get()) != SQLITE_DONE) {
            return Result<EvidenceRecordRow>::err(
                ErrorCode::INTERNAL_ERROR,
                std::string("Cannot record the device: ") + sqlite3_errmsg(pImpl_->db()));
        }
    }

    {
        auto inserted = prepare(
            pImpl_->db(),
            "INSERT INTO jobs(job_id, operation, status, started_at, completed_at, "
            "application_version, evidence_format_version, device_id, method, "
            "result, error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
        if (inserted.isError()) {
            return Result<EvidenceRecordRow>::err(inserted.error());
        }
        auto statement = std::move(inserted.value());
        const EvidenceJobRow& job = input.job;
        (void)bindText(statement.get(), 1, record.jobId);
        (void)bindText(statement.get(), 2,
                       job.operation.empty() ? record.operation : job.operation);
        (void)bindText(statement.get(), 3, job.status.empty() ? record.status : job.status);
        (void)bindText(statement.get(), 4, job.startedAt);
        (void)bindText(statement.get(), 5, job.completedAt);
        (void)bindText(statement.get(), 6, job.applicationVersion);
        (void)bindText(statement.get(), 7,
                       job.evidenceFormatVersion.empty() ? record.formatVersion
                                                         : job.evidenceFormatVersion);
        bindTextOrNull(statement.get(), 8, job.deviceId);
        (void)bindText(statement.get(), 9, job.method);
        (void)bindText(statement.get(), 10, job.result);
        (void)bindText(statement.get(), 11, job.error);
        if (sqlite3_step(statement.get()) != SQLITE_DONE) {
            return Result<EvidenceRecordRow>::err(
                ErrorCode::INTERNAL_ERROR,
                std::string("Cannot record the job: ") + sqlite3_errmsg(pImpl_->db()));
        }
    }

    {
        auto inserted = prepare(
            pImpl_->db(),
            "INSERT INTO evidence_records(evidence_id, job_id, description, "
            "operation, target, target_type, device_model, status, created_at, "
            "bundle_path, bundle_sha256, format_version, recorded_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
        if (inserted.isError()) {
            return Result<EvidenceRecordRow>::err(inserted.error());
        }
        auto statement = std::move(inserted.value());
        (void)bindText(statement.get(), 1, record.evidenceId);
        (void)bindText(statement.get(), 2, record.jobId);
        (void)bindText(statement.get(), 3, record.description);
        (void)bindText(statement.get(), 4, record.operation);
        (void)bindText(statement.get(), 5, record.target);
        (void)bindText(statement.get(), 6, record.targetType);
        (void)bindText(statement.get(), 7, record.deviceModel);
        (void)bindText(statement.get(), 8, record.status);
        (void)bindText(statement.get(), 9, record.createdAt);
        (void)bindText(statement.get(), 10, record.bundlePath);
        (void)bindText(statement.get(), 11, record.bundleSha256);
        (void)bindText(statement.get(), 12, record.formatVersion);
        (void)bindText(statement.get(), 13, nowTimestamp());
        if (sqlite3_step(statement.get()) != SQLITE_DONE) {
            return Result<EvidenceRecordRow>::err(
                ErrorCode::INTERNAL_ERROR,
                std::string("Cannot record the evidence: ") + sqlite3_errmsg(pImpl_->db()));
        }
    }

    for (const EvidenceArtifactRow& artifact : input.artifacts) {
        auto inserted = prepare(
            pImpl_->db(),
            "INSERT INTO evidence_artifacts(evidence_id, job_id, artifact_type, "
            "path, file_size, sha256, format_version, created_at, "
            "signature_key_id, signature_present) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
        if (inserted.isError()) {
            return Result<EvidenceRecordRow>::err(inserted.error());
        }
        auto statement = std::move(inserted.value());
        (void)bindText(statement.get(), 1, record.evidenceId);
        (void)bindText(statement.get(), 2, record.jobId);
        (void)bindText(statement.get(), 3, artifact.artifactType);
        (void)bindText(statement.get(), 4, artifact.path);
        (void)bindInt64(statement.get(), 5, static_cast<int64_t>(artifact.fileSize));
        (void)bindText(statement.get(), 6, artifact.sha256);
        (void)bindText(statement.get(), 7,
                       artifact.formatVersion.empty() ? record.formatVersion
                                                      : artifact.formatVersion);
        (void)bindText(statement.get(), 8,
                       artifact.createdAt.empty() ? record.createdAt : artifact.createdAt);
        (void)bindText(statement.get(), 9, artifact.signatureKeyId);
        (void)bindInt64(statement.get(), 10, artifact.signaturePresent ? 1 : 0);
        if (sqlite3_step(statement.get()) != SQLITE_DONE) {
            return Result<EvidenceRecordRow>::err(
                ErrorCode::INTERNAL_ERROR,
                std::string("Cannot record the artifact: ") + sqlite3_errmsg(pImpl_->db()));
        }
    }

    for (const EvidenceChainRow& event : input.events) {
        auto inserted = prepare(
            pImpl_->db(),
            "INSERT INTO audit_events(evidence_id, job_id, sequence_number, "
            "timestamp, event_type, payload, prev_hash, record_hash) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?);");
        if (inserted.isError()) {
            return Result<EvidenceRecordRow>::err(inserted.error());
        }
        auto statement = std::move(inserted.value());
        (void)bindText(statement.get(), 1, record.evidenceId);
        (void)bindText(statement.get(), 2, record.jobId);
        (void)bindInt64(statement.get(), 3, static_cast<int64_t>(event.sequence));
        (void)bindText(statement.get(), 4, event.timestamp);
        (void)bindText(statement.get(), 5, event.type);
        (void)bindText(statement.get(), 6, event.payload);
        (void)bindText(statement.get(), 7, event.prevHash);
        (void)bindText(statement.get(), 8, event.recordHash);
        if (sqlite3_step(statement.get()) != SQLITE_DONE) {
            return Result<EvidenceRecordRow>::err(
                ErrorCode::INTERNAL_ERROR,
                std::string("Cannot record the chain event: ") +
                    sqlite3_errmsg(pImpl_->db()));
        }
    }

    auto committed = transaction.commit();
    if (committed.isError()) {
        return Result<EvidenceRecordRow>::err(committed.error());
    }
    return Result<EvidenceRecordRow>::ok(record);
}

Result<EvidenceRecordRow> EvidenceDatabase::recordForEvidenceId(
    const std::string& evidenceId) const {
    auto statement = prepare(pImpl_->db(),
                             std::string("SELECT ") + kSelectRecordColumns +
                                 " FROM evidence_records WHERE evidence_id = ?;");
    if (statement.isError()) {
        return Result<EvidenceRecordRow>::err(statement.error());
    }
    (void)bindText(statement.value().get(), 1, evidenceId);
    if (sqlite3_step(statement.value().get()) != SQLITE_ROW) {
        return Result<EvidenceRecordRow>::err(
            ErrorCode::DEVICE_NOT_FOUND,
            "No evidence record with ID " + evidenceId,
            "List the records with 'ledgerase-cli evidence list'.");
    }
    return Result<EvidenceRecordRow>::ok(readRecord(statement.value().get()));
}

Result<EvidenceRecordRow> EvidenceDatabase::recordForJob(
    const std::string& jobId) const {
    auto statement = prepare(pImpl_->db(),
                             std::string("SELECT ") + kSelectRecordColumns +
                                 " FROM evidence_records WHERE job_id = ?;");
    if (statement.isError()) {
        return Result<EvidenceRecordRow>::err(statement.error());
    }
    (void)bindText(statement.value().get(), 1, jobId);
    if (sqlite3_step(statement.value().get()) != SQLITE_ROW) {
        return Result<EvidenceRecordRow>::err(
            ErrorCode::DEVICE_NOT_FOUND,
            "No indexed evidence for job " + jobId,
            "The bundle may exist on disk but not be registered. Run "
            "'ledgerase-cli evidence check'.");
    }
    return Result<EvidenceRecordRow>::ok(readRecord(statement.value().get()));
}

Result<std::vector<EvidenceArtifactRow>> EvidenceDatabase::artifactsFor(
    const std::string& evidenceId) const {
    auto statement = prepare(
        pImpl_->db(),
        "SELECT artifact_id, evidence_id, job_id, artifact_type, path, file_size, "
        "sha256, COALESCE(format_version, ''), COALESCE(created_at, ''), "
        "COALESCE(signature_key_id, ''), signature_present FROM evidence_artifacts "
        "WHERE evidence_id = ? ORDER BY artifact_id;");
    if (statement.isError()) {
        return Result<std::vector<EvidenceArtifactRow>>::err(statement.error());
    }
    (void)bindText(statement.value().get(), 1, evidenceId);
    std::vector<EvidenceArtifactRow> rows;
    while (sqlite3_step(statement.value().get()) == SQLITE_ROW) {
        EvidenceArtifactRow row;
        row.artifactId = columnInt(statement.value().get(), 0);
        row.evidenceId = columnText(statement.value().get(), 1);
        row.jobId = columnText(statement.value().get(), 2);
        row.artifactType = columnText(statement.value().get(), 3);
        row.path = columnText(statement.value().get(), 4);
        row.fileSize = static_cast<uint64_t>(columnInt(statement.value().get(), 5));
        row.sha256 = columnText(statement.value().get(), 6);
        row.formatVersion = columnText(statement.value().get(), 7);
        row.createdAt = columnText(statement.value().get(), 8);
        row.signatureKeyId = columnText(statement.value().get(), 9);
        row.signaturePresent = columnInt(statement.value().get(), 10) != 0;
        rows.push_back(std::move(row));
    }
    return Result<std::vector<EvidenceArtifactRow>>::ok(std::move(rows));
}

Result<std::vector<EvidenceChainRow>> EvidenceDatabase::chainFor(
    const std::string& evidenceId) const {
    auto statement = prepare(
        pImpl_->db(),
        "SELECT sequence_number, timestamp, event_type, payload, prev_hash, "
        "record_hash FROM audit_events WHERE evidence_id = ? "
        "ORDER BY sequence_number;");
    if (statement.isError()) {
        return Result<std::vector<EvidenceChainRow>>::err(statement.error());
    }
    (void)bindText(statement.value().get(), 1, evidenceId);
    std::vector<EvidenceChainRow> rows;
    while (sqlite3_step(statement.value().get()) == SQLITE_ROW) {
        EvidenceChainRow row;
        row.sequence = static_cast<uint64_t>(columnInt(statement.value().get(), 0));
        row.timestamp = columnText(statement.value().get(), 1);
        row.type = columnText(statement.value().get(), 2);
        row.payload = columnText(statement.value().get(), 3);
        row.prevHash = columnText(statement.value().get(), 4);
        row.recordHash = columnText(statement.value().get(), 5);
        rows.push_back(std::move(row));
    }
    return Result<std::vector<EvidenceChainRow>>::ok(std::move(rows));
}

Result<EvidencePage> EvidenceDatabase::list(int limit, int offset,
                                            bool newestFirst) const {
    return search(EvidenceSearchQuery{}, limit, offset, newestFirst);
}

Result<EvidencePage> EvidenceDatabase::search(const EvidenceSearchQuery& query,
                                               int limit, int offset,
                                               bool newestFirst) const {
    if (limit <= 0) {
        limit = 10;
    }
    if (offset < 0) {
        offset = 0;
    }

    std::vector<std::string> conditions;
    std::vector<std::string> bindings;

    const auto textFilter = [&](const std::string& column, const std::string& value) {
        if (!value.empty()) {
            conditions.push_back(column + " = ?");
            bindings.push_back(value);
        }
    };
    const auto likeFilter = [&](const std::string& column, const std::string& value) {
        if (!value.empty()) {
            conditions.push_back(column + " LIKE ? ESCAPE '\\'");
            bindings.push_back("%" + escapeLike(value) + "%");
        }
    };

    textFilter("evidence_id", query.evidenceId);
    textFilter("job_id", query.jobId);
    textFilter("operation", query.operation);
    textFilter("status", query.status);
    textFilter("target_type", query.targetType);
    likeFilter("device_model", query.deviceModel);

    if (!query.date.empty()) {
        conditions.push_back("substr(created_at, 1, 10) = ?");
        bindings.push_back(query.date);
    }
    if (!query.fromDate.empty()) {
        conditions.push_back("substr(created_at, 1, 10) >= ?");
        bindings.push_back(query.fromDate);
    }
    if (!query.toDate.empty()) {
        conditions.push_back("substr(created_at, 1, 10) <= ?");
        bindings.push_back(query.toDate);
    }
    if (!query.query.empty()) {
        conditions.push_back(
            "(description LIKE ? ESCAPE '\\' OR evidence_id LIKE ? ESCAPE '\\' "
            "OR operation LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' "
            "OR job_id LIKE ? ESCAPE '\\' OR device_model LIKE ? ESCAPE '\\')");
        const std::string pattern = "%" + escapeLike(query.query) + "%";
        for (int i = 0; i < 6; ++i) {
            bindings.push_back(pattern);
        }
    }

    std::string where;
    if (!conditions.empty()) {
        where = " WHERE ";
        for (size_t i = 0; i < conditions.size(); ++i) {
            if (i != 0) {
                where += " AND ";
            }
            where += conditions[i];
        }
    }

    const auto countStatement =
        prepare(pImpl_->db(), "SELECT COUNT(*) FROM evidence_records" + where + ";");
    if (countStatement.isError()) {
        return Result<EvidencePage>::err(countStatement.error());
    }
    for (size_t i = 0; i < bindings.size(); ++i) {
        (void)bindText(countStatement.value().get(), static_cast<int>(i + 1),
                       bindings[i]);
    }
    EvidencePage page;
    if (sqlite3_step(countStatement.value().get()) == SQLITE_ROW) {
        page.total = static_cast<int>(columnInt(countStatement.value().get(), 0));
    }

    std::string sql = std::string("SELECT ") + kSelectRecordColumns +
                      " FROM evidence_records" + where + " ORDER BY created_at " +
                      (newestFirst ? "DESC" : "ASC") + ", evidence_id " +
                      (newestFirst ? "DESC" : "ASC") + " LIMIT ? OFFSET ?;";
    auto statement = prepare(pImpl_->db(), sql);
    if (statement.isError()) {
        return Result<EvidencePage>::err(statement.error());
    }
    int index = 1;
    for (const std::string& binding : bindings) {
        (void)bindText(statement.value().get(), index++, binding);
    }
    (void)bindInt64(statement.value().get(), index++, limit);
    (void)bindInt64(statement.value().get(), index++, offset);

    while (sqlite3_step(statement.value().get()) == SQLITE_ROW) {
        page.records.push_back(readRecord(statement.value().get()));
    }
    return Result<EvidencePage>::ok(std::move(page));
}

Result<void> EvidenceDatabase::annotate(const std::string& evidenceId,
                                        const std::string& description,
                                        const std::string& changedBy) {
    Transaction transaction(pImpl_->db());
    auto started = transaction.begin();
    if (started.isError()) {
        return started;
    }

    std::string previous;
    {
        auto statement = prepare(pImpl_->db(),
                                 "SELECT COALESCE(description, '') "
                                 "FROM evidence_records WHERE evidence_id = ?;");
        if (statement.isError()) {
            return statement.error();
        }
        (void)bindText(statement.value().get(), 1, evidenceId);
        if (sqlite3_step(statement.value().get()) != SQLITE_ROW) {
            return Result<void>::err(ErrorCode::DEVICE_NOT_FOUND,
                                     "No evidence record with ID " + evidenceId);
        }
        previous = columnText(statement.value().get(), 0);
    }

    if (previous == description) {
        return transaction.commit();
    }

    {
        auto statement = prepare(pImpl_->db(),
                                 "UPDATE evidence_records SET description = ? "
                                 "WHERE evidence_id = ?;");
        if (statement.isError()) {
            return statement.error();
        }
        (void)bindText(statement.value().get(), 1, description);
        (void)bindText(statement.value().get(), 2, evidenceId);
        if (sqlite3_step(statement.value().get()) != SQLITE_DONE) {
            return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                     std::string("Cannot update the description: ") +
                                         sqlite3_errmsg(pImpl_->db()));
        }
    }

    {
        auto statement = prepare(
            pImpl_->db(),
            "INSERT INTO evidence_annotations(evidence_id, field, old_value, "
            "new_value, changed_at, changed_by) VALUES(?, 'description', ?, ?, ?, ?);");
        if (statement.isError()) {
            return statement.error();
        }
        (void)bindText(statement.value().get(), 1, evidenceId);
        (void)bindText(statement.value().get(), 2, previous);
        (void)bindText(statement.value().get(), 3, description);
        (void)bindText(statement.value().get(), 4, nowTimestamp());
        (void)bindText(statement.value().get(), 5, changedBy);
        if (sqlite3_step(statement.value().get()) != SQLITE_DONE) {
            return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                     std::string("Cannot record the annotation: ") +
                                         sqlite3_errmsg(pImpl_->db()));
        }
    }
    return transaction.commit();
}

Result<void> EvidenceDatabase::recordVerification(
    const VerificationResultRow& row) {
    auto statement = prepare(
        pImpl_->db(),
        "INSERT INTO verification_results(evidence_id, job_id, verified_at, "
        "status, verified_hash, signature_status, error) "
        "VALUES(?, ?, ?, ?, ?, ?, ?);");
    if (statement.isError()) {
        return statement.error();
    }
    (void)bindText(statement.value().get(), 1, row.evidenceId);
    (void)bindText(statement.value().get(), 2, row.jobId);
    (void)bindText(statement.value().get(), 3,
                   row.timestamp.empty() ? nowTimestamp() : row.timestamp);
    (void)bindText(statement.value().get(), 4, row.status);
    (void)bindText(statement.value().get(), 5, row.verifiedHash);
    (void)bindText(statement.value().get(), 6, row.signatureStatus);
    (void)bindText(statement.value().get(), 7, row.error);
    if (sqlite3_step(statement.value().get()) != SQLITE_DONE) {
        return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                 std::string("Cannot record the verification: ") +
                                     sqlite3_errmsg(pImpl_->db()));
    }
    return Result<void>::success();
}

Result<void> EvidenceDatabase::recordMigration(const EvidenceMigrationRow& row) {
    auto statement = prepare(
        pImpl_->db(),
        "INSERT INTO evidence_migrations(evidence_id, original_bundle, "
        "original_hash, resulting_bundle, resulting_hash, source_version, "
        "destination_version, status, migrated_at) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);");
    if (statement.isError()) {
        return statement.error();
    }
    (void)bindText(statement.value().get(), 1, row.evidenceId);
    (void)bindText(statement.value().get(), 2, row.originalBundle);
    (void)bindText(statement.value().get(), 3, row.originalHash);
    (void)bindText(statement.value().get(), 4, row.resultingBundle);
    (void)bindText(statement.value().get(), 5, row.resultingHash);
    (void)bindText(statement.value().get(), 6, row.sourceVersion);
    (void)bindText(statement.value().get(), 7, row.destinationVersion);
    (void)bindText(statement.value().get(), 8, row.status);
    (void)bindText(statement.value().get(), 9,
                   row.timestamp.empty() ? nowTimestamp() : row.timestamp);
    if (sqlite3_step(statement.value().get()) != SQLITE_DONE) {
        return Result<void>::err(ErrorCode::INTERNAL_ERROR,
                                 std::string("Cannot record the migration: ") +
                                     sqlite3_errmsg(pImpl_->db()));
    }
    return Result<void>::success();
}

Result<DatabaseStatus> EvidenceDatabase::status() const {
    DatabaseStatus result;
    result.path = pImpl_->path();
    std::error_code ec;
    result.exists = fs::exists(result.path, ec);
    result.schemaVersion = schemaVersion();

    const auto countOf = [&](const char* table, int& destination) {
        auto statement = prepare(pImpl_->db(),
                                 std::string("SELECT COUNT(*) FROM ") + table + ";");
        if (statement.isError()) {
            return;
        }
        if (sqlite3_step(statement.value().get()) == SQLITE_ROW) {
            destination = static_cast<int>(columnInt(statement.value().get(), 0));
        }
    };
    countOf("evidence_records", result.evidenceCount);
    countOf("jobs", result.jobCount);
    countOf("evidence_artifacts", result.artifactCount);
    countOf("verification_results", result.verificationCount);
    countOf("evidence_migrations", result.migrationCount);

    {
        auto statement = prepare(pImpl_->db(), "PRAGMA journal_mode;");
        if (!statement.isError() &&
            sqlite3_step(statement.value().get()) == SQLITE_ROW) {
            result.journalMode = columnText(statement.value().get(), 0);
        }
    }
    if (result.exists) {
        result.sizeBytes = fs::file_size(result.path, ec);
        if (ec) {
            result.sizeBytes = 0;
        }
    }
    return Result<DatabaseStatus>::ok(result);
}

Result<ConsistencyReport> EvidenceDatabase::consistency(
    const std::function<Result<void>(const EvidenceArtifactRow&)>& verify) const {
    ConsistencyReport report;

    auto statement = prepare(
        pImpl_->db(),
        "SELECT artifact_id, evidence_id, job_id, artifact_type, path, file_size, "
        "sha256, COALESCE(format_version, ''), COALESCE(created_at, ''), "
        "COALESCE(signature_key_id, ''), signature_present FROM evidence_artifacts "
        "ORDER BY evidence_id, artifact_id;");
    if (statement.isError()) {
        return Result<ConsistencyReport>::err(statement.error());
    }
    while (sqlite3_step(statement.value().get()) == SQLITE_ROW) {
        EvidenceArtifactRow row;
        row.artifactId = columnInt(statement.value().get(), 0);
        row.evidenceId = columnText(statement.value().get(), 1);
        row.jobId = columnText(statement.value().get(), 2);
        row.artifactType = columnText(statement.value().get(), 3);
        row.path = columnText(statement.value().get(), 4);
        row.fileSize = static_cast<uint64_t>(columnInt(statement.value().get(), 5));
        row.sha256 = columnText(statement.value().get(), 6);
        row.formatVersion = columnText(statement.value().get(), 7);
        row.createdAt = columnText(statement.value().get(), 8);
        row.signatureKeyId = columnText(statement.value().get(), 9);
        row.signaturePresent = columnInt(statement.value().get(), 10) != 0;
        ++report.checked;
        const auto verified = verify(row);
        if (verified.isError()) {
            report.findings.push_back(
                {row.evidenceId, "artifact", verified.error().what()});
        }
    }

    {
        auto orphans = prepare(
            pImpl_->db(),
            "SELECT evidence_id FROM evidence_records WHERE evidence_id NOT IN "
            "(SELECT DISTINCT evidence_id FROM evidence_artifacts);");
        if (!orphans.isError()) {
            while (sqlite3_step(orphans.value().get()) == SQLITE_ROW) {
                report.findings.push_back(
                    {columnText(orphans.value().get(), 0), "missing-artifact-reference",
                     "The record names no artifact; the bundle path cannot be "
                     "verified."});
            }
        }
    }
    {
        auto unregistered = prepare(
            pImpl_->db(),
            "SELECT job_id FROM jobs WHERE job_id NOT IN "
            "(SELECT job_id FROM evidence_records);");
        if (!unregistered.isError()) {
            while (sqlite3_step(unregistered.value().get()) == SQLITE_ROW) {
                report.findings.push_back(
                    {"", "unregistered-job",
                     "Job " + columnText(unregistered.value().get(), 0) +
                         " has no evidence record."});
            }
        }
    }
    return Result<ConsistencyReport>::ok(std::move(report));
}

Result<void> EvidenceDatabase::backupTo(const std::string& directory,
                                        bool overwrite) {
    if (directory.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "A backup directory is required");
    }
    const fs::path root(directory);
    std::error_code ec;
    if (fs::exists(root, ec) && !directoryIsEmpty(root) && !overwrite) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "The backup directory " + directory + " is not empty",
            "Choose an empty directory, or use --force to write into it.");
    }
    if (!fs::exists(root, ec)) {
        fs::create_directories(root, ec);
        if (ec) {
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + directory + ": " +
                                         ec.message());
        }
        fs::permissions(root, fs::perms::owner_all,
                        fs::perm_options::replace, ec);
    }

    const fs::path backupDb = root / "ledgerase.db";
    if (fs::exists(backupDb, ec) && !overwrite) {
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "A database already exists at " +
                                     backupDb.string());
    }

    sqlite3* destination = nullptr;
    if (sqlite3_open_v2(backupDb.c_str(), &destination,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) !=
        SQLITE_OK) {
        const std::string message =
            destination != nullptr ? sqlite3_errmsg(destination) : "unknown error";
        if (destination != nullptr) {
            sqlite3_close(destination);
        }
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot create the backup database: " + message);
    }
    sqlite3_backup* backup =
        sqlite3_backup_init(destination, "main", pImpl_->db(), "main");
    if (backup == nullptr) {
        const std::string message = sqlite3_errmsg(destination);
        sqlite3_close(destination);
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot start the SQLite backup: " + message);
    }
    int rc = sqlite3_backup_step(backup, -1);
    (void)sqlite3_backup_finish(backup);
    if (rc != SQLITE_DONE) {
        sqlite3_close(destination);
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "The SQLite backup did not complete");
    }
    sqlite3_close(destination);
    (void)::chmod(backupDb.c_str(), S_IRUSR | S_IWUSR);

    std::vector<ConsistencyFinding> findings;
    nlohmann::json manifest;
    manifest["schema_version"] = kCurrentSchemaVersion;
    manifest["created_at"] = nowTimestamp();
    manifest["database"] = "ledgerase.db";
    manifest["artifacts"] = nlohmann::json::array();

    auto statement = prepare(
        pImpl_->db(),
        "SELECT artifact_id, evidence_id, artifact_type, path, file_size, sha256 "
        "FROM evidence_artifacts ORDER BY artifact_id;");
    if (statement.isError()) {
        return statement.error();
    }
    while (sqlite3_step(statement.value().get()) == SQLITE_ROW) {
        const std::string evidenceId = columnText(statement.value().get(), 1);
        const std::string artifactType = columnText(statement.value().get(), 2);
        const std::string source = columnText(statement.value().get(), 3);
        const std::string sha256 = columnText(statement.value().get(), 5);

        nlohmann::json entry;
        entry["evidence_id"] = evidenceId;
        entry["artifact_type"] = artifactType;
        entry["source_path"] = source;
        entry["sha256"] = sha256;

        std::error_code existsEc;
        if (!fs::exists(source, existsEc)) {
            entry["backed_up"] = false;
            findings.push_back({evidenceId, "missing-artifact",
                                "The artifact is missing from the evidence store: " +
                                    source});
            manifest["artifacts"].push_back(entry);
            continue;
        }

        const fs::path copied =
            root / "artifacts" /
            (std::to_string(columnInt(statement.value().get(), 0)) + "-" +
             fs::path(source).filename().string());
        auto copy = copyFileAtomic(source, copied.string(), overwrite);
        if (copy.isError()) {
            entry["backed_up"] = false;
            findings.push_back({evidenceId, "backup-copy", copy.error().what()});
            manifest["artifacts"].push_back(entry);
            continue;
        }
        auto digest = sha256OfFile(copied.string());
        if (digest.isError() || digest.value() != sha256) {
            entry["backed_up"] = false;
            findings.push_back(
                {evidenceId, "backup-hash",
                 "The backup copy of " + source + " does not match its recorded hash"});
            manifest["artifacts"].push_back(entry);
            continue;
        }
        entry["backed_up"] = true;
        entry["backup_path"] = fs::relative(copied, root, existsEc).string();
        manifest["artifacts"].push_back(entry);
    }

    manifest["complete"] = findings.empty();
    auto written = writeTextAtomic((root / "backup.json").string(),
                                   manifest.dump(2) + "\n", true);
    if (written.isError()) {
        return written;
    }

    if (!findings.empty()) {
        std::string detail;
        for (const auto& finding : findings) {
            if (!detail.empty()) {
                detail += "; ";
            }
            detail += finding.kind + ": " + finding.detail;
        }
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "The backup is incomplete: " + detail,
            "The database was copied, but a backup without its artifacts is not "
            "a complete evidence backup. Repair the evidence store and run the "
            "backup again.");
    }
    return Result<void>::success();
}

Result<void> EvidenceDatabase::restoreFrom(const std::string& directory,
                                           const std::string& targetPath,
                                           bool overwrite) {
    if (directory.empty() || targetPath.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "A backup directory and target path are required");
    }
    const fs::path root(directory);
    std::ifstream input((root / "backup.json").string());
    if (!input) {
        return Result<void>::err(ErrorCode::DEVICE_NOT_FOUND,
                                 "No backup manifest at " +
                                     (root / "backup.json").string());
    }
    nlohmann::json manifest = nlohmann::json::parse(input, nullptr, false);
    if (manifest.is_discarded() || !manifest.is_object()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "The backup manifest is malformed");
    }
    if (!manifest.value("complete", false)) {
        return Result<void>::err(
            ErrorCode::OPERATION_REJECTED,
            "The backup is marked incomplete",
            "A backup that did not capture every artifact is not restored as a "
            "complete evidence set.");
    }

    for (const nlohmann::json& entry : manifest.value("artifacts", nlohmann::json::array())) {
        if (!entry.value("backed_up", false)) {
            return Result<void>::err(ErrorCode::OPERATION_REJECTED,
                                     "The backup lists an artifact that was not copied");
        }
        const std::string relative = entry.value("backup_path", "");
        const std::string recorded = entry.value("sha256", "");
        if (relative.empty()) {
            return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                     "The backup manifest has an empty artifact path");
        }
        const fs::path copy = root / relative;
        auto digest = sha256OfFile(copy.string());
        if (digest.isError()) {
            return Result<void>::err(digest.error());
        }
        if (digest.value() != recorded) {
            return Result<void>::err(
                ErrorCode::OPERATION_REJECTED,
                "The backup artifact " + copy.string() +
                    " does not match the hash in the manifest");
        }
    }

    const fs::path sourceDb = root / manifest.value("database", "ledgerase.db");
    if (!fs::exists(sourceDb)) {
        return Result<void>::err(ErrorCode::DEVICE_NOT_FOUND,
                                 "The backup database is missing: " +
                                     sourceDb.string());
    }
    if (fs::exists(targetPath) && !overwrite) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "Refusing to overwrite the existing database " + targetPath,
            "Use --force to replace it.");
    }
    return copyFileAtomic(sourceDb.string(), targetPath, overwrite);
}

} // namespace ledgerase
