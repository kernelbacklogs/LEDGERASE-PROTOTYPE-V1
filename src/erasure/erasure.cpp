// File and folder erasure. See include/ledgerase/erasure.hpp for the design.
//
// The three things this file is careful about:
//
//  1. One descriptor, opened once. A path is stat()ed to classify the target,
//     then opened, and then never named again. Every write, every read-back and
//     every digest is through that descriptor. A shredder that re-opens a path
//     after checking it can be made to erase a different file by swapping a
//     symlink in between, and that hole has been in every naive implementation
//     of "shred" since the 1990s.
//
//  2. The content check does not depend on the file's format. Probes are chunks
//     of the file's own bytes, found by those bytes. The carver is not used: it
//     finds files that identify themselves, and a file with no magic number is
//     invisible to it, so a carver-clean result says nothing about one.
//
//  3. The filesystem's row decides whether the file may be erased at all, and a
//     refusal is a refusal, not a partial success. See
//     src/filesystem/filesystem_capability.cpp and docs/FILESYSTEMS.md.

#include "ledgerase/erasure.hpp"
#include "ledgerase/platform/linux.hpp"
#include "ledgerase/target.hpp"

#include "../audit/evidence_document.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <functional>
#include <fcntl.h>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace ledgerase {

namespace {

constexpr size_t kIoBlock = 1u << 20;

// The overwrite pattern.
//
// Derived from the method, the file's size and the pass number, so it is not a
// constant: a pattern that is the same for every file makes an
// unknown-content overwrite easier to recognise and undo than it needs to be.
// It is *not* a PRNG seeded from the content, because the content is the thing
// being replaced and deriving from it leaks the first bytes into the
// replacement.
//
// Pseudo-random bytes, not a key-derived stream: a key would be a secret this
// tool would then have to protect, and an overwrite pattern is not a secret
// once it is on the medium.
std::string patternFor(EraseMethod method, uint64_t sizeBytes, uint32_t pass) {
    const uint64_t span = std::min<uint64_t>(sizeBytes, kIoBlock);
    if (method == EraseMethod::ZERO_FILL) {
        return std::string(static_cast<size_t>(span), '\0');
    }
    std::string pattern;
    pattern.reserve(static_cast<size_t>(span));
    // A fixed seed, mixed with the size and pass. Deterministic on purpose: the
    // same file and pass must always produce the same pattern, so a test can
    // assert it and an operator can reproduce it.
    uint64_t state = 0x9E3779B97F4A7C15ull ^ (sizeBytes * 1099511628211ull) ^
                    (static_cast<uint64_t>(pass) * 2654435761ull);
    for (uint64_t i = 0; i < span; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        pattern.push_back(static_cast<char>(state & 0xFF));
    }
    return pattern;
}

Result<std::string> digestOf(int fd, uint64_t sizeBytes) {
    Sha256Stream stream;
    if (::lseek(fd, 0, SEEK_SET) < 0) {
        return Result<std::string>::err(ErrorCode::IO_ERROR,
                                         std::string("Cannot rewind the file: ") +
                                             std::strerror(errno));
    }
    std::vector<uint8_t> buffer(kIoBlock);
    uint64_t remaining = sizeBytes;
    while (remaining > 0) {
        const size_t want = static_cast<size_t>(
            std::min<uint64_t>(remaining, buffer.size()));
        const ssize_t got = ::read(fd, buffer.data(), want);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return Result<std::string>::err(
                ErrorCode::IO_ERROR,
                std::string("Read failed while digesting: ") +
                    std::strerror(errno));
        }
        if (got == 0) {
            break;
        }
        stream.update(buffer.data(), static_cast<size_t>(got));
        remaining -= static_cast<uint64_t>(got);
    }
    return stream.finalHex();
}

std::string printableSample(const std::string& bytes) {
    std::string out;
    for (unsigned char byte : bytes) {
        if (out.size() >= 24) {
            break;
        }
        out.push_back((byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte)
                                                    : '.');
    }
    return out;
}

std::string formatTimestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm value{};
    gmtime_r(&now, &value);
    std::ostringstream out;
    out << std::put_time(&value, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

} // namespace

std::string eraseStateToString(EraseState state) {
    switch (state) {
        case EraseState::DISCOVERING: return "discovering";
        case EraseState::REFUSED: return "refused";
        case EraseState::ERASING: return "erasing";
        case EraseState::ERASED: return "erased";
        case EraseState::FAILED: return "failed";
        case EraseState::BLOCKED: return "blocked";
    }
    return "unknown";
}

FileEraser::FileEraser(EraseOptions options) : options_(options) {
    if (options_.passes < 1) {
        options_.passes = 1;
    }
    if (options_.passes > 15) {
        options_.passes = 15;
    }
    if (options_.probeCount < 1) {
        options_.probeCount = 1;
    }
    if (options_.probeLength < 64) {
        // Below this a probe is likely to occur by chance in unrelated data,
        // and a check that fires on a coincidence is worse than no check.
        options_.probeLength = 64;
    }
}

FileEraser::~FileEraser() = default;

std::string FileEraser::patternFor(EraseMethod method, uint64_t sizeBytes,
                                    uint32_t pass) {
    return ledgerase::patternFor(method, sizeBytes, pass);
}

std::string eraseMethodToString(EraseMethod method) {
    switch (method) {
        case EraseMethod::ZERO_FILL: return "zero-fill";
        case EraseMethod::RANDOM:    return "random";
    }
    return "random";
}

EraseMethod eraseMethodFromString(const std::string& name) {
    if (name == "zero" || name == "zero-fill" || name == "zerofill") {
        return EraseMethod::ZERO_FILL;
    }
    if (name == "random" || name == "rand") {
        return EraseMethod::RANDOM;
    }
    return EraseMethod::RANDOM;   // "" or unknown -> the default
}

namespace {

// Boyer-Moore-Horspool over one needle.
//
// Used rather than hashing a window at every offset: the probe bytes are held
// in memory for the duration of the search precisely so this can be done, and
// hashing every offset of a 64 MiB image means hashing 32 GiB.
std::vector<uint64_t> findAll(const std::vector<uint8_t>& haystack,
                              const std::vector<uint8_t>& needle) {
    std::vector<uint64_t> hits;
    if (needle.empty() || haystack.size() < needle.size()) {
        return hits;
    }
    // Horspool: for each byte value, how far it is safe to shift when it is the
    // one that mismatches. A byte that does not appear in the needle at all
    // gets the full needle length, which is the largest possible shift.
    std::vector<std::size_t> skip(256, needle.size());
    for (std::size_t i = 0; i + 1 < needle.size(); ++i) {
        skip[needle[i]] = needle.size() - 1 - i;
    }
    std::size_t at = 0;
    while (at + needle.size() <= haystack.size()) {
        // Compare from the end, and record *which* byte mismatched. An earlier
        // version used the shift itself as the match flag, initialised to
        // needle.size() - and a mismatch on a byte absent from the needle also
        // produces a shift of needle.size(). The two were indistinguishable, so
        // every such position was reported as a match: 59 false hits on a
        // 100 KiB region of unrelated data.
        std::size_t mismatchAt = needle.size();
        for (std::size_t k = needle.size(); k-- > 0;) {
            if (haystack[at + k] != needle[k]) {
                mismatchAt = k;
                break;
            }
        }
        if (mismatchAt == needle.size()) {
            hits.push_back(at);
            at += 1;
            continue;
        }
        at += skip[haystack[at + mismatchAt]];
    }
    return hits;
}

} // namespace

Result<std::vector<std::string>> FileEraser::searchForProbes(
    const std::string& searchPath,
    const std::vector<FileEraser::LiveProbe>& probes) const {
    std::vector<std::string> found;
    if (probes.empty()) {
        return Result<std::vector<std::string>>::ok(found);
    }

    // O_RDONLY and never O_RDWR: a search must not be able to modify what it is
    // searching, and the kernel enforces that here rather than this class
    // promising it.
    const int fd = ::open(searchPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return Result<std::vector<std::string>>::err(
            ErrorCode::IO_ERROR,
            "Cannot open for reading: " + searchPath + ": " + std::strerror(errno),
            "The residual search needs the medium to be readable. Nothing is "
            "written to it.");
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        ::close(fd);
        return Result<std::vector<std::string>>::err(
            ErrorCode::IO_ERROR, "Cannot read the search region's properties");
    }
    if (S_ISDIR(st.st_mode)) {
        ::close(fd);
        return Result<std::vector<std::string>>::err(
            ErrorCode::INVALID_ARGUMENT,
            "The search path is a directory: " + searchPath,
            "Search the file itself, or the block device it lives on. A "
            "directory is not a region of bytes.");
    }

    const uint64_t total = static_cast<uint64_t>(st.st_size);
    // The bound comes from this object's own options. Read here, not from the
    // caller, so the number written into the evidence file is the number that
    // was enforced.
    const uint64_t search =
        (options_.searchLimitBytes == 0 || options_.searchLimitBytes > total)
            ? total
            : options_.searchLimitBytes;

    // Overlap between reads by the longest needle, so a chunk that straddles a
    // read boundary is still seen whole. This is the same reason the carver's
    // chunks overlap, and the bug it fixes there - rescanning the overlap and
    // reporting every file twice - is avoided by advancing to the end of the
    // region already searched rather than by the window size.
    size_t longestNeedle = 0;
    for (const LiveProbe& probe : probes) {
        longestNeedle = std::max(longestNeedle, probe.bytes.size());
    }
    if (longestNeedle == 0) {
        ::close(fd);
        return Result<std::vector<std::string>>::ok(found);
    }

    // Read in windows of kIoBlock, each extended by the longest needle so a
    // chunk straddling a window boundary is still seen whole.
    const size_t stride = kIoBlock;
    std::vector<uint8_t> buffer(stride + longestNeedle);
    uint64_t at = 0;
    uint64_t lastReportedEnd = 0;
    constexpr std::size_t kMaxReports = 64;
    std::size_t reported = 0;
    while (at < search) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(
            search - at, buffer.size()));
        const ssize_t got = ::pread(fd, buffer.data(), want,
                                    static_cast<off_t>(at));
        if (got <= 0) {
            break;
        }
        const size_t gotUnsigned = static_cast<size_t>(got);
        // What this read covered, so the loop can tell whether another one adds
        // anything. Without it a region smaller than the window loops forever:
        // the first version clamped the offset back to
        // search - buffer.size(), which is negative for a small file, so the
        // offset went to 0 and spun. The test suite hung on a 200 KiB file.
        const uint64_t covered = at + gotUnsigned;
        for (const LiveProbe& probe : probes) {
            if (probe.bytes.size() > gotUnsigned) {
                continue;
            }
            for (const uint64_t hit :
                 findAll(std::vector<uint8_t>(buffer.begin(),
                                              buffer.begin() + gotUnsigned),
                         probe.bytes)) {
                const uint64_t absolute = at + hit;
                if (absolute >= search) {
                    continue;
                }
                // One report per contiguous run, so a probe that matched a
                // megabyte of repeated data does not produce a megabyte of
                // lines. A run cap as well: a 4 TB medium full of the same
                // kilobyte would otherwise produce millions of identical
                // findings, and a finding nobody can read is not evidence.
                //
                // Worth stating plainly: a probe of N bytes can match unrelated
                // data that happens to repeat. The probe length is a floor
                // (see the constructor) and the default of 512 is chosen to be
                // long enough that accidental repetition is improbable - but
                // "improbable" is not "impossible", and a reported hit is a
                // prompt to look, not a conclusion.
                if (absolute < lastReportedEnd || reported >= kMaxReports) {
                    continue;
                }
                ++reported;
                found.push_back("byte offset " + std::to_string(absolute) +
                                " in " + searchPath + " matches the probe taken "
                                "from file offset " +
                                std::to_string(probe.record.offsetInFile) +
                                " (sha256 " + probe.record.sha256.substr(0, 16) +
                                "...)");
                lastReportedEnd = absolute + probe.bytes.size();
            }
        }
        if (covered >= search) {
            break;
        }
        // One window forward. A step that does not advance is an exit, not a
        // retry.
        uint64_t next = at + stride;
        if (next >= search) {
            next = covered;
        }
        if (next <= at) {
            break;
        }
        at = next;
    }
    if (reported >= kMaxReports) {
        found.push_back("reporting stopped at " + std::to_string(kMaxReports) +
                        " locations; there are more, and the count is bounded "
                        "so a pathological region does not produce an unreadable "
                        "record");
    }
    ::close(fd);
    return Result<std::vector<std::string>>::ok(std::move(found));
}

Result<std::vector<FileEraser::LiveProbe>> FileEraser::liveProbesFor(
    const std::string& path) const {
    const auto held = probes_.find(path);
    if (held == probes_.end() || held->second.empty()) {
        return Result<std::vector<LiveProbe>>::err(
            ErrorCode::INVALID_ARGUMENT,
            "No pre-erase probes are held for " + path,
            "Call eraseFile() for this path first. The probe bytes exist only "
            "for the duration of the run and are not read back from the file, "
            "which no longer holds the content.");
    }
    return Result<std::vector<LiveProbe>>::ok(held->second);
}

Result<std::vector<FileEraser::LiveProbe>> FileEraser::probeFileLive(
    const std::string& path) const {
    std::vector<LiveProbe> live;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return Result<std::vector<FileEraser::LiveProbe>>::err(
            ErrorCode::IO_ERROR,
            "Cannot open for reading: " + path + ": " + std::strerror(errno));
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return Result<std::vector<FileEraser::LiveProbe>>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Not a regular file: " + path,
            "A content fingerprint needs a regular file with a length.");
    }
    const uint64_t size = static_cast<uint64_t>(st.st_size);
    if (size == 0) {
        ::close(fd);
        return Result<std::vector<FileEraser::LiveProbe>>::ok(std::move(live));
    }

    const uint64_t length = std::min<uint64_t>(options_.probeLength, size);
    // Spread the probes across the file. A prefix-only fingerprint would miss a
    // file whose middle was copied somewhere, which is the case that matters.
    for (size_t i = 0; i < options_.probeCount; ++i) {
        uint64_t offset = 0;
        if (options_.probeCount > 1) {
            offset = (size - length) * static_cast<uint64_t>(i) /
                     static_cast<uint64_t>(options_.probeCount - 1);
        }
        LiveProbe probe;
        probe.bytes.resize(static_cast<size_t>(length));
        if (::pread(fd, probe.bytes.data(), probe.bytes.size(),
                    static_cast<off_t>(offset)) !=
            static_cast<ssize_t>(probe.bytes.size())) {
            continue;
        }
        probe.record.offsetInFile = offset;
        probe.record.length = static_cast<uint32_t>(length);
        const auto hashed = sha256HexBytes(probe.bytes.data(), probe.bytes.size());
        if (hashed.isError()) {
            ::close(fd);
            return Result<std::vector<FileEraser::LiveProbe>>::err(hashed.error());
        }
        probe.record.sha256 = hashed.value();
        probe.record.sample = printableSample(std::string(
            reinterpret_cast<const char*>(probe.bytes.data()),
            probe.bytes.size()));
        live.push_back(std::move(probe));
    }
    ::close(fd);
    return Result<std::vector<FileEraser::LiveProbe>>::ok(std::move(live));
}

Result<FileEraseRecord> FileEraser::eraseFile(const std::string& path) {
    FileEraseRecord record;
    record.path = path;
    record.passesRequested = options_.passes;
    record.method = options_.method;

    // Classify from a stat() of the *path*, following symlinks, so a symlink to
    // a file is treated as that file. The decision to refuse a symlink to a
    // device is made below from the opened descriptor, not from the path.
    const TargetProperties properties = statTarget(path);
    if (!properties.exists) {
        record.state = EraseState::FAILED;
        record.detail = "The path does not exist or cannot be read: " + path;
        return Result<FileEraseRecord>::err(
            ErrorCode::INVALID_ARGUMENT, record.detail,
            "Check the path. Nothing was opened and nothing was written.");
    }

    record.filesystem = detectFilesystem(path);
    record.refusal = evaluateErasePermission(record.filesystem);
    // Permission is not gated on the filesystem: the matrix describes residue,
    // and residue is disclosed, not enforced against. A permitted run on a
    // filesystem that leaves residue carries the note so the operator reads
    // exactly what a file-level erase does and does not reach there.
    if (!record.refusal.residueNote.empty()) {
        record.limitations.push_back(record.refusal.residueNote);
    }

    // O_NOFOLLOW: a symlink is a name, not the file. If the operator named a
    // symlink, say so rather than erasing whatever it points at, which may be
    // outside the directory they thought they were in.
    const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        record.state = EraseState::FAILED;
        record.detail = "Cannot open for writing: " + path + ": " +
                        std::strerror(errno);
        record.limitations.push_back(
            "Nothing was written. A symbolic link is not erased by this tool: "
            "its name is not the file, and the file it names may be outside the "
            "folder the operator had in mind.");
        return Result<FileEraseRecord>::ok(record);
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        ::close(fd);
        record.state = EraseState::FAILED;
        record.detail = "Cannot read the opened file's properties: " + path;
        return Result<FileEraseRecord>::ok(record);
    }

    if (!S_ISREG(st.st_mode)) {
        ::close(fd);
        record.state = EraseState::REFUSED;
        record.detail =
            "Not a regular file. Erasing a device node, FIFO or socket because "
            "it appeared in a path is the accident this tool exists to prevent.";
        record.limitations.push_back(record.detail);
        return Result<FileEraseRecord>::ok(record);
    }

    record.sizeBytes = static_cast<uint64_t>(st.st_size);
    record.linkCount = static_cast<uint32_t>(st.st_nlink);

    // -- Safety, decided from the opened file -------------------------------
    //
    // These run on the descriptor, not on the path, so a check cannot be
    // satisfied by a different file appearing at the same name between the
    // check and the write. They are refusals, not warnings, and each one says
    // what to do instead.
    {
        // A read-only filesystem cannot be written to at all. Without this the
        // failure surfaces as an EROFS on the first pwrite, which in a
        // multi-file run means one entry fails for a reason that applies to all
        // of them.
        if (platform::linux::isOnReadOnlyMount(path)) {
            ::close(fd);
            record.state = EraseState::REFUSED;
            record.detail =
                "The filesystem holding this file is mounted read-only, so it "
                "cannot be overwritten. Nothing was written.";
            record.limitations.push_back(record.detail);
            return Result<FileEraseRecord>::ok(record);
        }

        // Ownership and write permission. The descriptor is already open
        // O_RDWR, so the write is permitted by the time this runs; the check is
        // here to produce a refusal an operator can act on rather than a
        // partial write, and to catch the case where a privileged run would
        // succeed and silently exceed what the operator's own account allows.
        if (st.st_uid != ::geteuid() && ::geteuid() != 0) {
            ::close(fd);
            record.state = EraseState::REFUSED;
            record.detail =
                "The file is owned by uid " + std::to_string(st.st_uid) +
                " and this process runs as uid " +
                std::to_string(static_cast<uint32_t>(::geteuid())) +
                ". Refused rather than performed with privilege the operator did "
                "not name.";
            record.limitations.push_back(record.detail);
            return Result<FileEraseRecord>::ok(record);
        }
    }

    // A file that is open elsewhere, or mapped into a running process, is
    // refused. Not force-closed, not written anyway: the process holding it
    // would keep its pages, and the write would either be lost or would change a
    // program while it is running.
    if (options_.checkInUse) {
        const platform::linux::FileUse use = platform::linux::findFileUse(
            static_cast<uint64_t>(st.st_dev),
            static_cast<uint64_t>(st.st_ino),
            path);
        if (use.mappedAsExecutable) {
            ::close(fd);
            record.state = EraseState::BLOCKED;
            record.detail =
                "The file is mapped into a running process"
                + (use.mappedByCommand.empty()
                       ? std::string()
                       : " (" + use.mappedByCommand + ", pid " +
                             std::to_string(use.pid) + ")") +
                ". Erasing it would change a running program. Close it first, or "
                "erase it from a bootable environment.";
            record.limitations.push_back(record.detail);
            return Result<FileEraseRecord>::ok(record);
        }
        if (use.openByAnyProcess) {
            ::close(fd);
            record.state = EraseState::BLOCKED;
            record.detail =
                "The file is open in another process"
                + (use.command.empty()
                       ? std::string()
                       : " (" + use.command + ", pid " + std::to_string(use.pid) +
                             ")") +
                ". Refused rather than overwritten: a process holding it open "
                "keeps its pages, so the erase would not remove the content from "
                "that process and would not be what the record says it is.";
            record.limitations.push_back(record.detail);
            return Result<FileEraseRecord>::ok(record);
        }
        if (!use.scanCompleted) {
            // The check could not run. That is not a pass, and it must not be
            // reported as one: the file may well be open and this build simply
            // could not look.
            record.limitations.push_back(
                "The open-file check could not read /proc, so it could not "
                "establish whether this file is in use. The file was not treated "
                "as free on the strength of a check that did not run.");
        }
    }

    if (record.linkCount > 1) {
        // Erasing this content destroys every other name for it. Refused, not
        // warned about: the operator asked to erase one path.
        ::close(fd);
        record.state = EraseState::BLOCKED;
        record.detail =
            "The file has " + std::to_string(record.linkCount) +
            " hard links. Erasing its content would destroy the content behind "
            "every one of them, and the operator named one path.";
        record.limitations.push_back(
            record.detail +
            " Break the links with `ln` and `unlink` if that is what is "
            "intended, or erase the device instead.");
        return Result<FileEraseRecord>::ok(record);
    }

    if (record.sizeBytes == 0) {
        // An empty file has no content to overwrite. Recorded as erased, with
        // the reason, rather than as a pass over zero bytes that proves nothing.
        // The name is still removed, so "the file is gone" holds for it too.
        if (options_.removeFile && !options_.simulation &&
            ::unlink(path.c_str()) == 0) {
            record.removedFromDirectory = true;
        }
        ::close(fd);
        record.state = EraseState::ERASED;
        record.detail =
            "The file is empty, so there was no content to overwrite. Recorded "
            "as erased for the content question only" +
            std::string(record.removedFromDirectory
                            ? " and its name was removed."
                            : "; the name was left in place.") +
            " See the limitations.";
        record.limitations.push_back(
            "An empty file has no content. 'Erased' here means the content "
            "question is vacuous, not that anything was written.");
        return Result<FileEraseRecord>::ok(record);
    }

    // -- Before: fingerprint and digest -------------------------------------
    const auto liveProbes = probeFileLive(path);
    if (liveProbes.isError()) {
        ::close(fd);
        record.state = EraseState::FAILED;
        record.detail = liveProbes.error().what();
        return Result<FileEraseRecord>::ok(record);
    }
    for (const LiveProbe& probe : liveProbes.value()) {
        record.probes.push_back(probe.record);
    }
    probes_[path] = liveProbes.value();
    const auto beforeDigest = digestOf(fd, record.sizeBytes);
    if (beforeDigest.isError()) {
        ::close(fd);
        record.state = EraseState::FAILED;
        record.detail = beforeDigest.error().what();
        return Result<FileEraseRecord>::ok(record);
    }
    record.sha256Before = beforeDigest.value();

    if (options_.simulation) {
        ::close(fd);
        record.state = EraseState::ERASED;
        record.detail =
            "SIMULATED: the pattern and the checks were computed and nothing "
            "was written.";
        record.limitations.push_back(
            "This was a simulated run. No byte of the file was changed.");
        return Result<FileEraseRecord>::ok(record);
    }

    // -- Erase --------------------------------------------------------------
    record.state = EraseState::ERASING;
    std::string lastPattern;
    for (uint32_t pass = 0; pass < options_.passes; ++pass) {
        const std::string pattern =
            patternFor(options_.method, record.sizeBytes, pass);
        lastPattern = pattern;
        if (::lseek(fd, 0, SEEK_SET) < 0) {
            ::close(fd);
            record.state = EraseState::FAILED;
            record.detail = std::string("Cannot rewind the file: ") +
                            std::strerror(errno);
            return Result<FileEraseRecord>::ok(record);
        }
        uint64_t written = 0;
        while (written < record.sizeBytes) {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(
                record.sizeBytes - written, pattern.size()));
            size_t position = 0;
            while (position < want) {
                const ssize_t put = ::pwrite(fd, pattern.data() + position,
                                             want - position,
                                             static_cast<off_t>(written + position));
                if (put < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    ::close(fd);
                    record.state = EraseState::FAILED;
                    record.detail = std::string("Write failed at offset ") +
                                    std::to_string(written + position) + ": " +
                                    std::strerror(errno) +
                                    ". The file may be partly overwritten, which "
                                    "is recorded rather than reported as erased.";
                    return Result<FileEraseRecord>::ok(record);
                }
                position += static_cast<size_t>(put);
            }
            written += want;
        }
        record.passesCompleted = pass + 1;
    }

    // Flush. Without this the writes may still be in the page cache when the
    // process exits, and a certificate saying "erased" would be describing an
    // intention.
    if (::fsync(fd) != 0) {
        ::close(fd);
        record.state = EraseState::FAILED;
        record.detail = std::string("Failed to flush the file: ") +
                        std::strerror(errno) +
                        ". The overwrite may not have reached the medium.";
        return Result<FileEraseRecord>::ok(record);
    }

    // -- Read back ----------------------------------------------------------
    {
        if (::lseek(fd, 0, SEEK_SET) == 0) {
            std::vector<uint8_t> buffer(kIoBlock);
            uint64_t at = 0;
            bool allMatch = true;
            const size_t blockSize = 512;
            while (at < record.sizeBytes && allMatch) {
                const size_t want = static_cast<size_t>(
                    std::min<uint64_t>(record.sizeBytes - at, buffer.size()));
                const ssize_t got = ::read(fd, buffer.data(), want);
                if (got <= 0) {
                    allMatch = false;
                    break;
                }
                for (size_t i = 0; i < static_cast<size_t>(got); ++i) {
                    const size_t expected = static_cast<size_t>(i % lastPattern.size());
                    if (buffer[i] != static_cast<uint8_t>(lastPattern[expected])) {
                        allMatch = false;
                        break;
                    }
                }
                at += static_cast<uint64_t>(got);
            }
            if (allMatch) {
                record.readBackVerified = true;
                record.readBackCoverageBytes = record.sizeBytes;
                record.readBackSectorsChecked = static_cast<uint32_t>(
                    (record.sizeBytes + blockSize - 1) / blockSize);
            }
        }
    }

    const auto afterDigest = digestOf(fd, record.sizeBytes);
    if (afterDigest.ok()) {
        record.sha256After = afterDigest.value();
    }

    // Remove the name, but only after the read-back has confirmed the overwrite.
    // Unlinking first would destroy the operator's ability to inspect a file
    // whose overwrite did not verify, and the cost of a failed read-back is a
    // name that is still there - not a file that is gone and unexplained.
    if (options_.removeFile && record.readBackVerified && !options_.simulation) {
        if (::unlink(path.c_str()) == 0) {
            record.removedFromDirectory = true;
        } else {
            // The content is already replaced, so this is not a failure of the
            // erase's guarantee - the content is unreadable through the
            // filesystem whether or not the name still resolves. It is recorded
            // as its own fact, because "erased" and "the name is gone" are two
            // different claims.
            record.detail +=
                " The content was replaced, but the directory entry could not "
                "be removed (" + std::string(std::strerror(errno)) +
                "), so the name still resolves to a file of pattern bytes.";
            record.limitations.push_back(
                "The file's content was overwritten and verified, but its "
                "directory entry was not removed, so the name still resolves. "
                "The content question is settled; the name is a separate one.");
        }
    }

    ::close(fd);

    // Commit the containing filesystem's journal, so the transaction that wrote
    // the pattern is not left pending. This does not zero journal blocks, and
    // the limitation says so.
    {
        const int dirFd = ::open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirFd >= 0) {
            (void)::syncfs(dirFd);
            ::close(dirFd);
        }
    }

    record.bytesOverwritten = record.sizeBytes * record.passesCompleted;
    record.state = record.readBackVerified ? EraseState::ERASED : EraseState::FAILED;
    record.detail =
        record.readBackVerified
            ? "Overwrote " + std::to_string(record.passesCompleted) +
                  " pass(es) and read the whole file back; every byte holds the "
                  "pattern." +
                  (record.removedFromDirectory
                       ? " The directory entry was removed, so the file is gone "
                         "and unreadable through the filesystem."
                       : " The name was left in place; the content is "
                         "unreadable through the filesystem but the entry "
                         "remains.")
            : "The overwrite completed but the read-back did not match. The "
              "file is not recorded as erased and was not removed.";

    record.limitations.push_back(
        "Only this file's own blocks were written. Blocks freed by an earlier "
        "delete of another file, the inode table, the free-block map and the "
        "journal are not reachable from one open file. See docs/RESIDUE.md.");
    record.limitations.push_back(
        "syncfs was called so the journal commits, but already-committed "
        "journal blocks are not zeroed and this tool does not reach them.");
    record.limitations.push_back(
        "The file's name, its inode's extent map and its size are still on the "
        "medium. A file-level erase does not remove a filesystem's records of "
        "the file having existed.");

    return Result<FileEraseRecord>::ok(record);
}

namespace {

// Glob matching for --include / --exclude.
//
// Written by hand rather than through std::filesystem or fnmatch for two
// reasons. fnmatch treats a bare "*" as matching "/", so "--exclude *" would
// silently exclude a whole tree, which is not what a person writing "erase
// everything but this" means. And the matching has to be done on the path
// *relative to the target folder*, not on the absolute path, so that a pattern
// written for the folder behaves the same wherever the folder is mounted.
//
// Semantics:
//   '*'   any run of characters except '/'
//   '?'   one character, not '/'
//   '**/' zero or more whole directories. "**/*.txt" matches "a.txt" as well as
//          "sub/deep/e.txt", because that is what an operator means by it; the
//          strict reading, which requires at least one directory, made the
//          pattern silently not match the top-level files it was named for.
//   '**'  at the end, any run including '/'
// A leading '/' in a pattern is stripped by the caller before matching, so a
// pattern is always written relative to the folder.
//
// Recursive rather than iterative. The "**/" case has to try both "skip the
// token" and "consume a directory", and the iterative form needed a second
// backtrack slot and got the zero-directory case wrong. The inputs are short -
// an operator-supplied pattern against a path under a folder - so the recursion
// is not a risk, and the version that is easy to read is the one to keep.
bool globMatch(const std::string& pattern, const std::string& text) {
    const std::function<bool(std::size_t, std::size_t)> match =
        [&](std::size_t p, std::size_t t) -> bool {
        while (p < pattern.size()) {
            const char c = pattern[p];
            if (c == '*') {
                if (p + 1 < pattern.size() && pattern[p + 1] == '*') {
                    // A run of '*'. It is the globstar only when it is followed
                    // by '/' or ends the pattern; otherwise it is just a '*' and
                    // is handled below, so "**x" does not match everything.
                    std::size_t run = p;
                    while (run < pattern.size() && pattern[run] == '*') ++run;
                    if (run == pattern.size()) {
                        return true;   // trailing "**": the rest is consumed
                    }
                    if (pattern[run] == '/') {
                        if (match(run + 1, t)) {
                            return true;   // zero directories
                        }
                        for (std::size_t k = t; k < text.size(); ++k) {
                            if (text[k] == '/' && match(run + 1, k + 1)) {
                                return true;
                            }
                        }
                        return false;
                    }
                    p = run - 1;   // fall through to the single-'*' case
                    continue;
                }
                // Single '*': any run that does not cross a '/'.
                const std::size_t next = p + 1;
                for (std::size_t k = t;; ++k) {
                    if (match(next, k)) return true;
                    if (k >= text.size() || text[k] == '/') return false;
                }
            }
            if (c == '?') {
                if (t >= text.size() || text[t] == '/') return false;
                ++p;
                ++t;
                continue;
            }
            if (t >= text.size() || text[t] != c) return false;
            ++p;
            ++t;
        }
        return t == text.size();
    };
    return match(0, 0);
}

// True when an --exclude pattern names this entry.
bool isExcluded(const EraseOptions& options, const std::string& base,
                const std::string& relative) {
    for (const std::string& pattern : options.excludePatterns) {
        std::string p = pattern;
        if (!p.empty() && p.front() == '/') p.erase(0, 1);
        if (globMatch(p, relative) || globMatch(p, base)) return true;
    }
    return false;
}

// True when an --include pattern names this entry. With no --include patterns
// every entry is included.
bool isIncluded(const EraseOptions& options, const std::string& base,
                const std::string& relative) {
    if (options.includePatterns.empty()) return true;
    for (const std::string& pattern : options.includePatterns) {
        std::string p = pattern;
        if (!p.empty() && p.front() == '/') p.erase(0, 1);
        if (globMatch(p, relative) || globMatch(p, base)) return true;
    }
    return false;
}

// In scope for a *file*: excluded by nothing, included by something if any
// --include patterns were given.
bool inScope(const EraseOptions& options, const std::string& base,
             const std::string& relative) {
    if (isExcluded(options, base, relative)) return false;
    return isIncluded(options, base, relative);
}

// Where a symlink points, resolved. Empty when it does not resolve, which is a
// broken link and is reported as such rather than followed.
std::string resolveSymlink(const std::string& path) {
    std::error_code ec;
    const std::filesystem::path resolved = std::filesystem::weakly_canonical(
        std::filesystem::path(path), ec);
    if (ec) return {};
    return resolved.string();
}

} // namespace

Result<FolderEraseRecord> FileEraser::planFolder(const std::string& path) {
    FolderEraseRecord record;
    record.path = path;
    record.dryRun = true;

    const TargetProperties properties = statTarget(path);
    if (!properties.exists || !properties.isDirectory) {
        return Result<FolderEraseRecord>::err(
            ErrorCode::INVALID_ARGUMENT, "Not a directory: " + path,
            "The path must be a directory. Naming a single file uses "
            "'erase-file'.");
    }

    probes_.clear();
    std::vector<std::string> names;
    DIR* dir = ::opendir(path.c_str());
    if (dir == nullptr) {
        return Result<FolderEraseRecord>::err(
            ErrorCode::IO_ERROR,
            "Cannot read the directory: " + path + ": " + std::strerror(errno));
    }
    while (const struct dirent* entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        names.push_back(name);
    }
    ::closedir(dir);
    std::sort(names.begin(), names.end());
    record.entries = names;

    // The traversal, shared with eraseFolder(). `writing` is false here, so the
    // only difference is that no file is opened for writing and nothing is
    // unlinked; the classification is identical, which is the point: a dry run
    // that classified differently from the real run would be worse than no dry
    // run at all.
    FolderEraseRecord planned = collectFolder(path, path, false);
    planned.dryRun = true;
    planned.path = path;
    return Result<FolderEraseRecord>::ok(std::move(planned));
}

FolderEraseRecord FileEraser::collectFolder(const std::string& root,
                                            const std::string& dirPath,
                                            bool writing) {
    FolderEraseRecord record;
    record.path = dirPath;
    if (dirPath == root) record.path = root;

    std::vector<std::string> names;
    DIR* dir = ::opendir(dirPath.c_str());
    if (dir == nullptr) {
        record.notErased.push_back(dirPath + ": cannot be read: " +
                                   std::strerror(errno));
        ++record.filesFailed;
        return record;
    }
    while (const struct dirent* entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        names.push_back(name);
    }
    ::closedir(dir);
    std::sort(names.begin(), names.end());
    // The entries of *this* directory, so the record says what was looked at.
    // Only the root's list is the interesting one - a nested record has its own
    // and merging them would double-count - which is why this is set here rather
    // than accumulated up the recursion.
    record.entries = (dirPath == root) ? names : record.entries;

    // `display` is the path under the folder, not the bare entry name. In a
    // recursive run a bare name is ambiguous - three levels can each hold a
    // "c.txt" - and a record that says "c.txt: excluded" when the file is
    // "sub/c.txt" is a record naming a path that does not exist.
    const auto refuse = [&record](const std::string& display,
                                  const std::string& why) {
        FileEraseRecord refused;
        refused.path = display;
        refused.state = EraseState::REFUSED;
        refused.detail = why;
        refused.limitations.push_back(why);
        record.records.push_back(refused);
        record.notErased.push_back(display + ": " + why);
        ++record.filesRefused;
    };

    for (const std::string& name : names) {
        const std::string child = dirPath + "/" + name;
        // lstat, not stat: a symlink is classified as a symlink, so the decision
        // to follow it is made from what it *is*, not from what it points at.
        const TargetProperties childProperties = lstatTarget(child);

        // The path under the folder the operator named, which is what the glob
        // patterns are matched against. Computed from `root` rather than
        // accumulated, so a nested call cannot build a longer path than the one
        // that exists.
        const std::string relative =
            (dirPath == root) ? name : child.substr(root.size() + 1);
        if (!childProperties.exists) {
            FileEraseRecord failed;
            failed.path = name;
            failed.state = EraseState::FAILED;
            failed.detail = "vanished before it was reached";
            record.records.push_back(failed);
            record.notErased.push_back(name + ": vanished before it was reached");
            ++record.filesFailed;
            continue;
        }

        // A subdirectory. Recursion is opt-in, and the decision is recorded
        // either way so the record says what happened to every entry.
        if (childProperties.isDirectory) {
            if (!options_.recursive) {
                refuse(relative,
                       "a subdirectory. Folder erasure is not recursive unless "
                       "--recursive is given; name the subdirectory to erase it.");
                continue;
            }
            // Only --exclude applies to a directory. An --include pattern names
            // files, and applying it to a directory stops the descent before it
            // can reach any file: "--include *.txt -r" found the top-level .txt
            // files and silently skipped every subdirectory, because "sub" does
            // not match "*.txt". The include filter belongs on the files.
            if (isExcluded(options_, name, relative)) {
                refuse(relative,
                       "excluded by an --exclude pattern, and it is a directory, "
                       "so nothing under it was reached.");
                continue;
            }
            const FolderEraseRecord nested = collectFolder(root, child, writing);
            for (const FileEraseRecord& r : nested.records) {
                record.records.push_back(r);
            }
            for (const std::string& reason : nested.notErased) {
                // Not re-prefixed. The nested call was given the same `root`, so
                // its paths are already relative to the folder the operator
                // named. Prefixing again produced "sub/sub/deep/e.txt" and made
                // a name in the record that no path in the tree has.
                record.notErased.push_back(reason);
            }
            record.totalBytes += nested.totalBytes;
            record.filesErased += nested.filesErased;
            record.filesRefused += nested.filesRefused;
            record.filesFailed += nested.filesFailed;
            continue;
        }

        // A symlink. The one this tool exists to prevent is a symlink out of the
        // folder, so that case is skipped and named rather than followed.
        if (childProperties.isSymlink) {
            const std::string target = resolveSymlink(child);
            if (target.empty()) {
                refuse(relative,
                       "a broken symbolic link. It resolves to nothing, so there "
                       "is no file to erase and no target to report.");
                continue;
            }
            const bool insideFolder =
                target == root ||
                (target.size() > root.size() &&
                 target.compare(0, root.size(), root) == 0 &&
                 target[root.size()] == '/');
            if (!insideFolder && !options_.followSymlinks) {
                refuse(relative,
                       "a symbolic link pointing outside the folder being erased ("
                           + target +
                       "). Not followed and not erased: the name is not a file, "
                       "and the file it names is not inside the folder that was "
                       "asked for. --follow-symlinks overrides this.");
                continue;
            }
            if (!inScope(options_, name, relative)) {
                refuse(relative, "excluded by the --include/--exclude patterns.");
                continue;
            }
            if (!writing) {
                if (insideFolder) {
                    // The target is inside the folder, so it is already listed
                    // on its own. Listing the link as a file to erase would
                    // double-count it, and an earlier version did exactly that:
                    // the count said 2 and three paths were printed.
                    record.notErased.push_back(
                        name + ": a symbolic link to " + target +
                        ", which is inside the folder being erased and is "
                        "already in scope, so it adds nothing to erase");
                    continue;
                }
                // Outside the folder, and --follow-symlinks was given, so this
                // really is a file the run would reach. It is listed as one, and
                // it is listed as outside the folder, because the operator
                // widened the scope deliberately and should see what that
                // reaches. Calling it "inside" here was the bug: the same
                // message was used for both cases, so --follow-symlinks
                // reported an out-of-folder target as being in the folder.
                const TargetProperties targetProperties = lstatTarget(target);
                FileEraseRecord planned;
                planned.path = name + " -> " + target;
                planned.state = EraseState::ERASED;
                planned.sizeBytes = targetProperties.exists
                                        ? targetProperties.sizeBytes
                                        : 0;
                planned.detail =
                    "OUTSIDE THE FOLDER: " + target +
                    ". Reached only because --follow-symlinks was given, which "
                    "widens the erase beyond the named folder.";
                record.records.push_back(planned);
                record.totalBytes += planned.sizeBytes;
                ++record.filesErased;
                continue;
            }
            const auto erased = eraseFile(target);
            if (erased.isError()) {
                record.notErased.push_back(name + ": " + erased.error().what());
                ++record.filesFailed;
                continue;
            }
            FileEraseRecord r = erased.value();
            r.path = name + " -> " + target;
            record.totalBytes += r.sizeBytes;
            record.records.push_back(r);
            if (r.state == EraseState::ERASED) {
                ++record.filesErased;
            } else {
                record.notErased.push_back(name + ": " + r.detail);
                ++record.filesFailed;
            }
            continue;
        }

        if (!childProperties.isRegularFile) {
            refuse(relative,
                   "not a regular file (device node, FIFO or socket). Refused: "
                   "erasing a device because it appeared in a listing is the "
                   "accident this tool exists to prevent.");
            continue;
        }

        if (!inScope(options_, name, relative)) {
            refuse(relative, "excluded by the --include/--exclude patterns.");
            continue;
        }

        if (!writing) {
            // The dry run reports the file and its size and stops. It does not
            // open the file for writing, take a probe, or unlink anything.
            FileEraseRecord planned;
            planned.path = relative;
            planned.state = EraseState::ERASED;
            planned.sizeBytes = childProperties.sizeBytes;
            planned.linkCount = childProperties.linkCount;
            planned.detail = "would be overwritten and removed (dry run)";
            record.records.push_back(planned);
            record.totalBytes += childProperties.sizeBytes;
            ++record.filesErased;
            continue;
        }

        const auto erased = eraseFile(child);
        if (erased.isError()) {
            record.notErased.push_back(name + ": " + erased.error().what());
            ++record.filesFailed;
            continue;
        }
        const FileEraseRecord& fileRecord = erased.value();
        record.totalBytes += fileRecord.sizeBytes;
        record.records.push_back(fileRecord);
        switch (fileRecord.state) {
            case EraseState::ERASED:
                ++record.filesErased;
                break;
            case EraseState::FAILED:
                record.notErased.push_back(name + ": " + fileRecord.detail);
                ++record.filesFailed;
                break;
            default:
                record.notErased.push_back(name + ": " +
                                           eraseStateToString(fileRecord.state) +
                                           " - " + fileRecord.detail);
                ++record.filesRefused;
                break;
        }
    }
    return record;
}

Result<FolderEraseRecord> FileEraser::eraseFolder(const std::string& path) {
    const TargetProperties properties = statTarget(path);
    if (!properties.exists || !properties.isDirectory) {
        return Result<FolderEraseRecord>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Not a directory: " + path,
            "The path must be a directory. Erasing a single file names the file "
            "directly.");
    }
    // This run's probes only. A second erase in the same process must not be
    // able to search for the previous run's content.
    probes_.clear();
    FolderEraseRecord record = collectFolder(path, path, true);
    record.path = path;
    return Result<FolderEraseRecord>::ok(std::move(record));
}

void to_json(nlohmann::json& j, const ContentProbe& p) {
    j = {{"offset_in_file", p.offsetInFile},
         {"length", p.length},
         {"sha256", p.sha256},
         {"sample", p.sample}};
}

void from_json(const nlohmann::json& j, ContentProbe& p) {
    if (j.contains("offset_in_file")) j.at("offset_in_file").get_to(p.offsetInFile);
    if (j.contains("length")) j.at("length").get_to(p.length);
    if (j.contains("sha256")) j.at("sha256").get_to(p.sha256);
    if (j.contains("sample")) j.at("sample").get_to(p.sample);
}

void to_json(nlohmann::json& j, const FileEraseRecord& r) {
    j = {{"path", r.path},
         {"size_bytes", r.sizeBytes},
         {"link_count", r.linkCount},
         {"filesystem", r.filesystem.reportedName},
         {"state", eraseStateToString(r.state)},
         {"detail", r.detail},
         {"method", eraseMethodToString(r.method)},
         {"passes_requested", r.passesRequested},
         {"passes_completed", r.passesCompleted},
         {"bytes_overwritten", r.bytesOverwritten},
         {"read_back_verified", r.readBackVerified},
         {"removed_from_directory", r.removedFromDirectory},
         {"read_back_sectors_checked", r.readBackSectorsChecked},
         {"read_back_coverage_bytes", r.readBackCoverageBytes},
         {"residual_content_found", r.residualContentFound},
         {"residual_locations", r.residualLocations},
         {"sha256_before", r.sha256Before},
         {"sha256_after_pattern", r.sha256After},
         {"probes", r.probes},
         {"limitations", r.limitations}};
    if (r.refusal.refused) {
        j["refusal"] = {{"filesystem", r.refusal.filesystem},
                        {"level", supportLevelToString(r.refusal.level)}};
    }
    // The residue a permitted run still leaves, recorded whether or not the
    // erase was refused. A reader checking the evidence must be able to see
    // what the filesystem keeps, not only that something was overwritten.
    if (!r.refusal.residue.empty() || !r.refusal.residueNote.empty()) {
        j["residue"] = {{"filesystem", r.refusal.filesystem},
                        {"level", supportLevelToString(r.refusal.level)},
                        {"what_remains", r.refusal.residue},
                        {"note", r.refusal.residueNote}};
    }
}

void from_json(const nlohmann::json& j, FileEraseRecord& r) {
    if (j.contains("path")) j.at("path").get_to(r.path);
    if (j.contains("size_bytes")) j.at("size_bytes").get_to(r.sizeBytes);
    if (j.contains("link_count")) j.at("link_count").get_to(r.linkCount);
    if (j.contains("filesystem")) r.filesystem.reportedName = j.at("filesystem").get<std::string>();
    if (j.contains("detail")) j.at("detail").get_to(r.detail);
    if (j.contains("method")) r.method = eraseMethodFromString(j.at("method").get<std::string>());
    if (j.contains("passes_requested")) j.at("passes_requested").get_to(r.passesRequested);
    if (j.contains("passes_completed")) j.at("passes_completed").get_to(r.passesCompleted);
    if (j.contains("bytes_overwritten")) j.at("bytes_overwritten").get_to(r.bytesOverwritten);
    if (j.contains("read_back_verified")) j.at("read_back_verified").get_to(r.readBackVerified);
    if (j.contains("read_back_sectors_checked")) j.at("read_back_sectors_checked").get_to(r.readBackSectorsChecked);
    if (j.contains("read_back_coverage_bytes")) j.at("read_back_coverage_bytes").get_to(r.readBackCoverageBytes);
    if (j.contains("residual_content_found")) j.at("residual_content_found").get_to(r.residualContentFound);
    if (j.contains("residual_locations")) j.at("residual_locations").get_to(r.residualLocations);
    if (j.contains("sha256_before")) j.at("sha256_before").get_to(r.sha256Before);
    if (j.contains("sha256_after_pattern")) j.at("sha256_after_pattern").get_to(r.sha256After);
    if (j.contains("probes")) j.at("probes").get_to(r.probes);
    if (j.contains("limitations")) j.at("limitations").get_to(r.limitations);
    if (j.contains("state")) {
        const std::string state = j.at("state").get<std::string>();
        for (EraseState candidate : {EraseState::DISCOVERING, EraseState::REFUSED,
                                    EraseState::ERASING, EraseState::ERASED,
                                    EraseState::FAILED, EraseState::BLOCKED}) {
            if (eraseStateToString(candidate) == state) {
                r.state = candidate;
            }
        }
    }
}

void to_json(nlohmann::json& j, const FolderEraseRecord& r) {
    j = {{"path", r.path},
         {"dry_run", r.dryRun},
         {"entries", r.entries},
         {"total_bytes", r.totalBytes},
         {"files_erased", r.filesErased},
         {"files_refused", r.filesRefused},
         {"files_failed", r.filesFailed},
         {"not_erased", r.notErased},
         {"records", r.records}};
}

void from_json(const nlohmann::json& j, FolderEraseRecord& r) {
    if (j.contains("path")) j.at("path").get_to(r.path);
    if (j.contains("dry_run")) j.at("dry_run").get_to(r.dryRun);
    if (j.contains("entries")) j.at("entries").get_to(r.entries);
    if (j.contains("total_bytes")) j.at("total_bytes").get_to(r.totalBytes);
    if (j.contains("files_erased")) j.at("files_erased").get_to(r.filesErased);
    if (j.contains("files_refused")) j.at("files_refused").get_to(r.filesRefused);
    if (j.contains("files_failed")) j.at("files_failed").get_to(r.filesFailed);
    if (j.contains("not_erased")) j.at("not_erased").get_to(r.notErased);
    if (j.contains("records")) j.at("records").get_to(r.records);
}

void to_json(nlohmann::json& j, const EraseOptions& o) {
    j = {{"method", eraseMethodToString(o.method)},
         {"recursive", o.recursive},
         {"follow_symlinks", o.followSymlinks},
         {"include_patterns", o.includePatterns},
         {"exclude_patterns", o.excludePatterns},
         {"passes", o.passes},
         {"probe_count", o.probeCount},
         {"probe_length", o.probeLength},
         {"search_limit_bytes", o.searchLimitBytes},
         {"remove_file", o.removeFile},
         {"check_in_use", o.checkInUse},
         {"simulation", o.simulation}};
}

void from_json(const nlohmann::json& j, EraseOptions& o) {
    if (j.contains("method")) o.method = eraseMethodFromString(j.at("method").get<std::string>());
    if (j.contains("recursive")) j.at("recursive").get_to(o.recursive);
    if (j.contains("follow_symlinks")) j.at("follow_symlinks").get_to(o.followSymlinks);
    if (j.contains("include_patterns")) j.at("include_patterns").get_to(o.includePatterns);
    if (j.contains("exclude_patterns")) j.at("exclude_patterns").get_to(o.excludePatterns);
    if (j.contains("passes")) j.at("passes").get_to(o.passes);
    if (j.contains("probe_count")) j.at("probe_count").get_to(o.probeCount);
    if (j.contains("probe_length")) j.at("probe_length").get_to(o.probeLength);
    if (j.contains("search_limit_bytes")) j.at("search_limit_bytes").get_to(o.searchLimitBytes);
    if (j.contains("remove_file")) j.at("remove_file").get_to(o.removeFile);
    if (j.contains("check_in_use")) j.at("check_in_use").get_to(o.checkInUse);
    if (j.contains("simulation")) j.at("simulation").get_to(o.simulation);
}

void to_json(nlohmann::json& j, const EraseEvidenceBundle& b) {
    j = {
        {"schema", b.schema},
        {"job_id", b.jobId},
        {"generated_at", b.generatedAt},
        {"application_version", b.applicationVersion},
        {"operator", b.operatorName},
        {"operator_invoking_user", b.invokingUser},
        {"operator_invoking_uid", b.invokingUid},
        {"operator_effective_user", b.effectiveUser},
        {"operator_effective_uid", b.effectiveUid},
        {"operator_elevated", b.elevated},
        {"target", {{"path", b.targetPath}, {"kind", b.targetKind},
                    {"filesystem", b.filesystemName}, {"simulated", b.simulated}}},
        {"residual_search", {{"skipped", b.residualSearchSkipped},
                             {"skip_reason", b.residualSearchSkipReason},
                             {"target", b.residualSearchTarget}}},
        {"options", b.options},
        {"files", b.files},
        {"folder", b.folder},
        {"summary", {{"files_refused", b.filesRefused},
                     {"files_failed", b.filesFailed}}},
        {"limitations", b.limitations},
        {"integrity", {{"chain_length", b.chainLength},
                       {"chain_head", b.chainHead},
                       {"event_chain", b.eventChain}}},
        {"canonical_hash", b.canonicalHash},
    };
}

void from_json(const nlohmann::json& j, EraseEvidenceBundle& b) {
    if (j.contains("schema")) j.at("schema").get_to(b.schema);
    if (j.contains("job_id")) j.at("job_id").get_to(b.jobId);
    if (j.contains("generated_at")) j.at("generated_at").get_to(b.generatedAt);
    if (j.contains("application_version")) j.at("application_version").get_to(b.applicationVersion);
    if (j.contains("operator")) j.at("operator").get_to(b.operatorName);
    if (j.contains("operator_invoking_user")) j.at("operator_invoking_user").get_to(b.invokingUser);
    if (j.contains("operator_invoking_uid")) j.at("operator_invoking_uid").get_to(b.invokingUid);
    if (j.contains("operator_effective_user")) j.at("operator_effective_user").get_to(b.effectiveUser);
    if (j.contains("operator_effective_uid")) j.at("operator_effective_uid").get_to(b.effectiveUid);
    if (j.contains("operator_elevated")) j.at("operator_elevated").get_to(b.elevated);
    if (j.contains("target")) {
        const auto& t = j.at("target");
        if (t.contains("path")) t.at("path").get_to(b.targetPath);
        if (t.contains("kind")) t.at("kind").get_to(b.targetKind);
        if (t.contains("filesystem")) t.at("filesystem").get_to(b.filesystemName);
        if (t.contains("simulated")) t.at("simulated").get_to(b.simulated);
    }
    if (j.contains("residual_search")) {
        const auto& r = j.at("residual_search");
        if (r.contains("skipped")) r.at("skipped").get_to(b.residualSearchSkipped);
        if (r.contains("skip_reason")) r.at("skip_reason").get_to(b.residualSearchSkipReason);
        if (r.contains("target")) r.at("target").get_to(b.residualSearchTarget);
    }
    if (j.contains("options")) j.at("options").get_to(b.options);
    if (j.contains("files")) j.at("files").get_to(b.files);
    if (j.contains("folder")) j.at("folder").get_to(b.folder);
    if (j.contains("summary")) {
        const auto& s = j.at("summary");
        if (s.contains("files_refused")) s.at("files_refused").get_to(b.filesRefused);
        if (s.contains("files_failed")) s.at("files_failed").get_to(b.filesFailed);
    }
    if (j.contains("limitations")) j.at("limitations").get_to(b.limitations);
    if (j.contains("canonical_hash")) j.at("canonical_hash").get_to(b.canonicalHash);
    if (j.contains("integrity")) {
        const auto& i = j.at("integrity");
        if (i.contains("chain_length")) i.at("chain_length").get_to(b.chainLength);
        if (i.contains("chain_head")) i.at("chain_head").get_to(b.chainHead);
        if (i.contains("event_chain")) i.at("event_chain").get_to(b.eventChain);
    }
}

std::string EraseEvidenceBuilder::generateJobId() {
    static thread_local std::mt19937 engine(std::random_device{}());
    std::uniform_int_distribution<int> dist(1000, 9999);
    const std::time_t seconds = std::time(nullptr);
    std::tm value{};
    gmtime_r(&seconds, &value);
    std::ostringstream out;
    out << "ERASE-" << std::put_time(&value, "%Y%m%dT%H%M%SZ") << "-" << dist(engine);
    return out.str();
}

Result<EraseEvidenceBundle> EraseEvidenceBuilder::build(
    const EraseEvidenceBundle& inputs) {
    EraseEvidenceBundle bundle = inputs;
    bundle.generatedAt = formatTimestamp();

    bundle.filesRefused = 0;
    bundle.filesFailed = 0;
    for (const FileEraseRecord& file : bundle.files) {
        if (file.state == EraseState::REFUSED ||
            file.state == EraseState::BLOCKED) {
            ++bundle.filesRefused;
        } else if (file.state == EraseState::FAILED) {
            ++bundle.filesFailed;
        }
    }

    EvidenceJournal journal;
    const auto append = [&journal, &bundle](const char* type,
                                            nlohmann::json payload) -> Result<void> {
        const auto appended = journal.append(type, bundle.jobId, std::move(payload));
        if (appended.isError()) {
            return Result<void>::err(appended.error());
        }
        return Result<void>::success();
    };

    // The job-level record type. Named "file_erase" rather than a generic
    // "erase" so a reader scanning a mixed evidence directory can tell a
    // file-level job from a device sanitization without reading the payload,
    // and so the per-file results below have an unambiguous parent.
    auto opened = append("file_erase",
                         {{"record_type", "file_erase"},
                          {"target_path", bundle.targetPath},
                          {"target_kind", bundle.targetKind},
                          {"filesystem", bundle.filesystemName},
                          {"simulated", bundle.simulated},
                          // The scope, recorded so a recursive run can be told
                          // from a single-level one after the fact.
                          {"recursive", bundle.options.recursive},
                          {"follow_symlinks", bundle.options.followSymlinks},
                          {"include_patterns", bundle.options.includePatterns},
                          {"exclude_patterns", bundle.options.excludePatterns},
                          {"residual_search", {{"skipped", bundle.residualSearchSkipped},
                                               {"skip_reason", bundle.residualSearchSkipReason},
                                               {"target", bundle.residualSearchTarget}}},
                          {"tool", {{"application_version", bundle.applicationVersion}}},
                          {"options", bundle.options}});
    if (opened.isError()) {
        return Result<EraseEvidenceBundle>::err(opened.error());
    }

    for (const FileEraseRecord& file : bundle.files) {
        nlohmann::json payload = {
            {"path", file.path},
            {"size_bytes", file.sizeBytes},
            {"filesystem", file.filesystem.reportedName},
            {"state", eraseStateToString(file.state)},
            {"method", eraseMethodToString(file.method)},
            {"passes_requested", file.passesRequested},
            {"passes_completed", file.passesCompleted},
            {"bytes_overwritten", file.bytesOverwritten},
            {"read_back_verified", file.readBackVerified},
            {"removed_from_directory", file.removedFromDirectory},
            {"sha256_before", file.sha256Before},
            {"sha256_after_pattern", file.sha256After},
            {"residual_content_found", file.residualContentFound},
            {"residual_locations", file.residualLocations},
        };
        // One record per probe, so the chain commits to every digest the report
        // relies on rather than to a summary count.
        nlohmann::json probeList = nlohmann::json::array();
        for (const ContentProbe& probe : file.probes) {
            probeList.push_back(probe);
        }
        payload["probes"] = probeList;
        if (file.refusal.refused) {
            payload["refused"] = true;
        }
        if (!file.refusal.residueNote.empty()) {
            payload["residue_note"] = file.refusal.residueNote;
        }
        auto appended = append("erase_file_result", std::move(payload));
        if (appended.isError()) {
            return Result<EraseEvidenceBundle>::err(appended.error());
        }
    }

    auto closed = append("erase_job_closed",
                         {{"files", bundle.files.size()},
                          {"files_refused", bundle.filesRefused},
                          {"files_failed", bundle.filesFailed}});
    if (closed.isError()) {
        return Result<EraseEvidenceBundle>::err(closed.error());
    }

    bundle.eventChain = journal.records();
    bundle.chainLength = journal.count();
    bundle.chainHead = journal.head();

    auto hash = canonicalHash(bundle);
    if (hash.isError()) {
        return Result<EraseEvidenceBundle>::err(hash.error());
    }
    bundle.canonicalHash = hash.value();
    return bundle;
}

Result<std::string> EraseEvidenceBuilder::canonicalJson(
    const EraseEvidenceBundle& bundle) {
    nlohmann::json j = bundle;
    j.erase("canonical_hash");
    return j.dump();
}

Result<std::string> EraseEvidenceBuilder::canonicalHash(
    const EraseEvidenceBundle& bundle) {
    const auto canonical = canonicalJson(bundle);
    if (canonical.isError()) {
        return Result<std::string>::err(canonical.error());
    }
    return sha256HexBytes(
        reinterpret_cast<const uint8_t*>(canonical.value().data()),
        canonical.value().size());
}

Result<std::string> EraseEvidenceBuilder::canonicalHashOfDocument(
    const nlohmann::json& document) {
    nlohmann::json copy = document;
    copy.erase("canonical_hash");
    const std::string dumped = copy.dump();
    return sha256HexBytes(reinterpret_cast<const uint8_t*>(dumped.data()),
                          dumped.size());
}

Result<void> EraseEvidenceWriter::write(const EraseEvidenceBundle& bundle,
                                        const std::string& path,
                                        bool overwrite) {
    EraseEvidenceBundle document = bundle;
    auto hash = EraseEvidenceBuilder::canonicalHash(document);
    if (hash.isError()) {
        return Result<void>::err(hash.error());
    }
    document.canonicalHash = hash.value();
    std::string payload = nlohmann::json(document).dump(2);
    payload.push_back('\n');
    return detail::writeEvidenceDocument(path, payload, overwrite);
}

Result<EraseEvidenceBundle> EraseEvidenceWriter::read(const std::string& path) {
    auto document = detail::readEvidenceDocument(path);
    if (document.isError()) {
        return Result<EraseEvidenceBundle>::err(document.error());
    }
    EraseEvidenceBundle bundle;
    try {
        document.value().get_to(bundle);
    } catch (const std::exception& e) {
        return Result<EraseEvidenceBundle>::err(
            ErrorCode::INVALID_ARGUMENT,
            std::string("Erase evidence file is malformed: ") + e.what());
    }
    return bundle;
}

Result<EvidenceVerification> EraseEvidenceVerifier::verifyStructure(
    const std::string& path) {
    auto document = detail::readEvidenceDocument(path);
    if (document.isError()) {
        return Result<EvidenceVerification>::err(document.error());
    }
    EraseEvidenceBundle bundle;
    try {
        document.value().get_to(bundle);
    } catch (const std::exception& e) {
        return Result<EvidenceVerification>::err(
            ErrorCode::INVALID_ARGUMENT,
            std::string("Erase evidence file is malformed: ") + e.what());
    }

    EvidenceVerification report;
    report.schemaRecognised = (bundle.schema == EraseEvidenceBundle::kSchema);
    if (!report.schemaRecognised) {
        report.findings.push_back("Unrecognised schema: " + bundle.schema);
        return report;
    }
    const auto recomputed =
        EraseEvidenceBuilder::canonicalHashOfDocument(document.value());
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
    report.findings.push_back(
        chain.intact ? "Event chain is intact (" +
                           std::to_string(chain.recordsChecked) + " records)"
                     : "Event chain FAILED: " + chain.failureReason);
    report.signaturePresent = false;
    report.findings.push_back(
        "No signature present. An erase record is unsigned, so integrity here "
        "rests on the hash alone.");
    report.limitations.add(LimitationId::VERIFYLOG_SCOPE);
    return report;
}

} // namespace ledgerase
