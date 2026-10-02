// File and folder erasure.
//
// A file eraser is not a smaller device sanitizer. It has a different question
// to answer and a smaller set of things it can actually answer:
//
//   * The target is a *file*, not a block device. The work is one open
//     descriptor, not a device, and the confirmation is the file's name rather
//     than a serial (a file has none).
//   * What can be wiped is the file's own blocks. Blocks freed by an earlier
//     delete of some *other* file, the inode table, the free-block bitmap and
//     the journal are all out of reach, and every one of them is recorded as a
//     limitation rather than implied to be clean.
//   * The check cannot be the carver. A signature carver cannot see a file with
//     no magic number, so "the carver found nothing" is not evidence. The check
//     here is content-based and does not depend on the file's format: several
//     distinctive chunks of the file's own bytes are recorded before the erase,
//     and the raw medium is searched for them afterwards.
//
// Everything is done through an open descriptor. A path is never re-resolved
// after the first stat(): the classic TOCTOU hole in a file shredder is that it
// checks one file and writes to whatever now has that name, and a symlink
// swapped in between the two gets followed. Here the file is opened once, and
// every subsequent operation is on that descriptor.

#ifndef LEDGERASE_ERASURE_HPP
#define LEDGERASE_ERASURE_HPP

#include "ledgerase/error.hpp"
#include "ledgerase/evidence.hpp"
#include "ledgerase/filesystem_capability.hpp"

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ledgerase {

// A content fingerprint recorded before the erase and looked for afterwards.
//
// This is the whole verification story, and it is deliberately not the carver.
// The carver finds files that identify themselves; a file with no magic number
// is invisible to it, so a carver-clean result after an erase proves nothing
// about a file that never had a signature. A chunk of the file's own bytes is
// found by those bytes and by nothing else.
struct ContentProbe {
    uint64_t offsetInFile = 0;
    uint32_t length = 0;
    std::string sha256;
    // A short, printable slice of the chunk, so a human reading a report can
    // see what was being looked for. Never the whole chunk, and never anything
    // from a key file.
    std::string sample;
};

enum class EraseState {
    DISCOVERING,
    REFUSED,
    ERASING,
    ERASED,
    FAILED,
    BLOCKED,
};

std::string eraseStateToString(EraseState state);

// How the overwrite pattern is generated. One vocabulary for both the device
// eraser and the file eraser, so "the same method" means one enum, not a
// file-only parallel type.
//
// The pattern is a function of (method, size, pass). Two of the three are
// inputs rather than constants precisely so the choice is recorded and
// reproducible, not so a verifier can be surprised.
enum class EraseMethod {
    // A constant 0x00 for every byte of every pass. This is the device eraser's
    // historical pattern (kOverwritePatternByte) and remains its default, so
    // device behaviour is unchanged. Cheap, reproducible, and trivially
    // recognisable - a property of a known-content wipe, not a weakness: this
    // tool is replacing a file, not hiding one.
    ZERO_FILL,
    // A deterministic pseudo-random stream seeded from the size and pass. Not a
    // PRNG seeded from the content (that would leak the first bytes into the
    // replacement) and not key-derived (an overwrite pattern is not a secret
    // once it is on the medium). Reproducible, so a test can assert it.
    RANDOM,
};

std::string eraseMethodToString(EraseMethod method);
EraseMethod eraseMethodFromString(const std::string& name);   // "" -> default

// One file's erasure, and everything that was checked about it.
struct FileEraseRecord {
    std::string path;
    uint64_t sizeBytes = 0;
    uint32_t linkCount = 1;
    // The filesystem's row, and the cells that decided whether the file could
    // be erased at all.
    FilesystemCapabilities filesystem;
    FilesystemRefusal refusal;

    uint32_t passesRequested = 1;
    uint32_t passesCompleted = 0;
    // The technique that produced the pattern, recorded because the pattern
    // itself is not in the evidence (it would be a second copy of what was
    // written) and a reader still needs to know which technique ran.
    EraseMethod method = EraseMethod::RANDOM;
    uint64_t bytesOverwritten = 0;
    // True when the content was read back and matched what was written.
    bool readBackVerified = false;
    // True when the directory entry was removed after a verified overwrite, so
    // the name no longer resolves. Separate from readBackVerified: the content
    // is unreadable through the filesystem either way, but "the file is gone"
    // and "its bytes were replaced" are different claims.
    bool removedFromDirectory = false;
    uint32_t readBackSectorsChecked = 0;
    uint64_t readBackCoverageBytes = 0;
    // True when a search of the raw medium found one of the pre-erase probes
    // after the erase. A finding, not a failure of the erase: the bytes may
    // have been copied into a journal, a log, or a copy the file was part of.
    bool residualContentFound = false;
    std::vector<std::string> residualLocations;

    std::vector<ContentProbe> probes;
    std::string sha256Before;
    // After the erase this is the digest of the pattern, not of the file, and
    // it is recorded under this name so nobody compares the two.
    std::string sha256After;

    EraseState state = EraseState::DISCOVERING;
    std::string detail;
    std::vector<std::string> limitations;
};

struct FolderEraseRecord {
    std::string path;
    // True when nothing was written: the --dry-run path. Carried in the record
    // so a dry run's own output cannot be mistaken for an erase that happened.
    bool dryRun = false;
    std::vector<std::string> entries;
    uint64_t totalBytes = 0;
    uint64_t filesErased = 0;
    uint64_t filesRefused = 0;
    uint64_t filesFailed = 0;
    // Files reached but not erased, with the reason. Never silently omitted: a
    // folder report that says "3 of 10 files erased" without saying which three
    // is not a report.
    std::vector<std::string> notErased;
    // The per-file records, one for every regular file reached. A folder
    // erasure is audited file by file, in the same format as a single-file
    // erasure, because a folder is not a fact an auditor can check on its own.
    std::vector<FileEraseRecord> records;
};

struct EraseOptions {
    // The overwrite technique. Defaults to RANDOM, which is what the file eraser
    // has always used; the device eraser passes ZERO_FILL explicitly.
    EraseMethod method = EraseMethod::RANDOM;

    // Folder scope.
    //
    // Recursion is off by default. A recursive run can reach files the operator
    // did not enumerate and has no mental model of, which is the difference
    // between "erase this folder" and "erase everything under this folder".
    bool recursive = false;
    // Follow a symlink whose target resolves outside the folder being erased.
    // Off by default: a symlink is a name, and following it out of the named
    // folder erases a file the operator did not name. Widening scope has to be
    // asked for.
    bool followSymlinks = false;
    // Glob patterns. An entry is in scope when it matches at least one
    // --include (if any are given) and matches no --exclude. Matched against the
    // entry's base name and against its path relative to the target folder, so
    // "*.log" and "cache/*" both behave as written. A single '*' does not cross
    // a '/'; "**" does.
    std::vector<std::string> includePatterns;
    std::vector<std::string> excludePatterns;

    // Overwrite passes. 1 is this tool's default and is a local choice, not a
    // NIST one: NIST SP 800-88 Rev. 2 §3.1.1 prescribes no pass count, recording
    // only that multi-pass overwrite was historical practice ("ranged from a
    // single pass to as high as 39") and that on "SSDs with overprovisioning,
    // such practices should be avoided". More passes are performed if asked for
    // and are recorded as requested and as completed, separately.
    uint32_t passes = 1;
    // Probes recorded before the erase and searched for afterwards. A count,
    // not a flag, because the verification is only as good as the number of
    // independent places it looks in.
    size_t probeCount = 6;
    // Each probe is this long. Long enough to be improbable by chance, short
    // enough to be found inside a block.
    size_t probeLength = 512;
    // Bound on the residual search, so a large medium does not turn the check
    // into an unbounded read. 0 means the whole medium.
    //
    // Owned by the eraser rather than passed to searchForProbes() as an
    // argument, because the object that performs the search should own the
    // limit it reports in the evidence. It was a field that was written to the
    // bundle and never read, with the CLI passing the same value separately -
    // so the record stated a bound the object did not hold.
    uint64_t searchLimitBytes = 0;
    // Simulated run: the pattern is computed and the checks run, but nothing
    // is written. Recorded as simulated, and never as erased.
    bool simulation = false;
    // Remove the directory entry after the overwrite and read-back, so the
    // file's name is gone as well as its content. This is what makes the
    // guarantee "the file is gone and unreadable through the filesystem" rather
    // than only "its bytes were replaced". The inode and its blocks stay on the
    // medium either way - that is the residue the residual search looks for.
    bool removeFile = true;
    // Refuse a file that is open in another process or mapped into a running
    // program, instead of overwriting it anyway. On by default. A batch run
    // that turned this off would be erasing files the system is using, and the
    // option exists so a caller can say it is doing that deliberately rather
    // than so the check can be skipped by accident.
    bool checkInUse = true;
};

class FileEraser {
public:
    explicit FileEraser(EraseOptions options = EraseOptions());
    ~FileEraser();

    FileEraser(const FileEraser&) = delete;
    FileEraser& operator=(const FileEraser&) = delete;

    // Erases one file. Refuses, rather than partially doing, when the
    // filesystem's row does not permit it.
    Result<FileEraseRecord> eraseFile(const std::string& path);

    // Erases a directory's regular files, one descriptor at a time.
    //
    // Recursion is opt-in. A non-recursive run touches only the entries directly
    // in the folder and records every subdirectory as not erased; a recursive
    // run descends when options_.recursive is set.
    //
    // Symlinks are a name, not a file, and the one they name may be outside the
    // folder entirely. The default is to skip a symlink whose target resolves
    // outside the folder being erased, and to report it; a symlink whose target
    // is inside the folder is followed by default, because there it names
    // something this run would erase anyway. options_.followSymlinks overrides
    // both and follows every symlink, which is a deliberate widening of scope
    // and is recorded as such.
    //
    // Device nodes, sockets and FIFOs inside the folder are refused with the
    // same reasoning: erasing a block device because it appeared in a directory
    // listing is exactly the accident this tool exists to prevent.
    Result<FolderEraseRecord> eraseFolder(const std::string& path);

    // Enumerates what eraseFolder() would touch, without writing anything.
    //
    // This is the --dry-run path and it is a separate function rather than a
    // flag on eraseFolder(), because "do not write" and "write" are different
    // code paths and a flag means the destructive path is the same code with one
    // branch disabled. Here there is no write at all: the function opens no file
    // for writing, takes no probe, and unlinks nothing.
    Result<FolderEraseRecord> planFolder(const std::string& path);

private:
    // The traversal behind both eraseFolder() and planFolder(). `writing` is the
    // only difference: true opens each file and unlinks it, false reports what
    // would happen and writes nothing. Both produce the same classification, so
    // a dry run describes the run that will actually happen.
    FolderEraseRecord collectFolder(const std::string& root,
                                    const std::string& dirPath,
                                    bool writing);

public:

    // A probe together with the bytes it was taken from.
    //
    // The bytes are held only for the duration of the search. They are not put
    // in the evidence record - a record containing the file's content is a copy
    // of the thing that was supposed to be erased - so the search needs them in
    // memory while it runs, and the record keeps only the digest.
    struct LiveProbe {
        ContentProbe record;
        std::vector<uint8_t> bytes;
    };

    // Records the content probes for a file without erasing anything. Used to
    // establish a baseline before an erasure, and by the tests.
    Result<std::vector<LiveProbe>> probeFileLive(const std::string& path) const;

    // The probes taken for the file most recently erased, with their bytes.
    //
    // They are held here rather than returned by eraseFile() because the bytes
    // are the content that was just erased: putting them in the returned
    // record would make the record a second copy of the secret, and putting
    // them in the evidence file would be the same mistake one level down. The
    // caller has to ask for them again, and asking is the reminder.
    Result<std::vector<LiveProbe>> liveProbesFor(const std::string& path) const;

    // Searches the medium for the probe content. Returns where it was found.
    //
    // The bound is `options_.searchLimitBytes`: 0 searches the whole medium,
    // which is the default and the only setting that can find a copy that has
    // been relocated. A bounded search is reported as a bounded search.
    //
    // Read-only by construction: the descriptor is opened O_RDONLY and there is
    // no code path here that opens anything for writing.
    Result<std::vector<std::string>> searchForProbes(
        const std::string& searchPath,
        const std::vector<LiveProbe>& probes) const;

    const EraseOptions& options() const { return options_; }

    // The pattern written over a file's content. Derived from the method, the
    // file's own size and a fixed seed, so the same file is always given the
    // same pattern and a second pass over the first pass's output is not a
    // no-op by accident.
    static std::string patternFor(EraseMethod method, uint64_t sizeBytes,
                                  uint32_t pass);

private:
    EraseOptions options_;
    // The probes for every file erased in this run, keyed by path. A folder of
    // twenty files needs all twenty sets available for the residual search, not
    // just the last one, so this is a map rather than a single slot. Cleared at
    // the start of eraseFolder so a second run in the same process does not
    // inherit the first one's content.
    mutable std::map<std::string, std::vector<LiveProbe>> probes_;
};

// The evidence record for a file or folder erasure.
//
// Same shape as the sanitization bundle and the same chain, so `verify-log`
// checks all three with one command. A different schema, because a file erasure
// makes different claims: it has no device, no verification report and no
// validation engine, and it has something the others do not - a content
// fingerprint recorded before the erase and searched for after it.
struct EraseEvidenceBundle {
    // Written under the new name; a "sanitizer.erase_bundle/1" written by an
    // earlier build is still read, for the reason in evidence.hpp.
    static constexpr const char* kSchema = "ledgerase.erase_bundle/1";
    static constexpr const char* kLegacySchemas[] = {"sanitizer.erase_bundle/1"};
    std::string schema = kSchema;

    std::string jobId;
    std::string generatedAt;
    std::string applicationVersion;

    std::string operatorName;
    std::string invokingUser;
    uint32_t invokingUid = 0;
    std::string effectiveUser;
    uint32_t effectiveUid = 0;
    bool elevated = false;

    std::string targetPath;
    std::string targetKind;      // "file" or "folder"
    std::string filesystemName;  // as the system reported it
    bool simulated = false;

    // The residual search is the only step that reports what is actually still
    // on the medium. A waiver is recorded here - as a fact with a reason - so a
    // reader of the evidence can tell a verified overwrite from an unverified
    // one without inferring it from an absent field.
    bool residualSearchSkipped = false;
    std::string residualSearchSkipReason;
    // The medium the search actually ran over, or would have. An empty string
    // means it did not run, or no medium could be found; the limitations say
    // which.
    std::string residualSearchTarget;

    EraseOptions options;
    std::vector<FileEraseRecord> files;
    // Present for a folder, empty for a single file.
    FolderEraseRecord folder;

    // What was refused, and why. A folder where three files could not be
    // erased is not a successful run, and the record says so here.
    uint64_t filesRefused = 0;
    uint64_t filesFailed = 0;

    std::vector<std::string> limitations;

    uint64_t chainLength = 0;
    std::string chainHead;
    std::vector<EvidenceRecord> eventChain;
    std::string canonicalHash;
};

void to_json(nlohmann::json& j, const ContentProbe& p);
void from_json(const nlohmann::json& j, ContentProbe& p);
void to_json(nlohmann::json& j, const FileEraseRecord& r);
void from_json(const nlohmann::json& j, FileEraseRecord& r);
void to_json(nlohmann::json& j, const FolderEraseRecord& r);
void from_json(const nlohmann::json& j, FolderEraseRecord& r);
void to_json(nlohmann::json& j, const EraseEvidenceBundle& b);
void from_json(const nlohmann::json& j, EraseEvidenceBundle& b);

class EraseEvidenceBuilder {
public:
    static Result<EraseEvidenceBundle> build(const EraseEvidenceBundle& inputs);
    static Result<std::string> canonicalJson(const EraseEvidenceBundle& bundle);
    static Result<std::string> canonicalHash(const EraseEvidenceBundle& bundle);
    static Result<std::string> canonicalHashOfDocument(
        const nlohmann::json& document);
    static std::string generateJobId();
};

class EraseEvidenceWriter {
public:
    static Result<void> write(const EraseEvidenceBundle& bundle,
                              const std::string& path,
                              bool overwrite = false);
    static Result<EraseEvidenceBundle> read(const std::string& path);
};

class EraseEvidenceVerifier {
public:
    static Result<EvidenceVerification> verifyStructure(const std::string& path);
};

} // namespace ledgerase

#endif // LEDGERASE_ERASURE_HPP
