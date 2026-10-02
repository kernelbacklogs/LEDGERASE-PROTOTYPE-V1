// Signature-based file carving.
//
// The carver reads a source read-only and searches it for file headers whose
// format records its own length. For each candidate it derives the length from
// the format's own rules, extracts the bytes, and scores how sure it is.
//
// Two things this deliberately does not do:
//
//  * It never writes to the source. A recovery source is evidence, and
//    evidence that has been modified is not evidence.
//  * It does not load the source into memory. A 4 TB device is scanned in
//    bounded chunks with an overlap, so peak memory is a configuration value
//    rather than a function of the medium.
//
// The platform-specific part is FileCarveSource and nothing else, so the
// scanning logic is portable as-is.

#ifndef LEDGERASE_CARVING_HPP
#define LEDGERASE_CARVING_HPP

#include "ledgerase/error.hpp"
#include "ledgerase/target.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ledgerase {

enum class FileCategory {
    IMAGE,
    DOCUMENT,
    ARCHIVE,
    AUDIO_VIDEO,
    EXECUTABLE,
    DATABASE,
    TEXT,
    UNKNOWN,
};

std::string fileCategoryToString(FileCategory category);

// How the length of a candidate file is established.
enum class LengthRule {
    // Search forward for the format's trailer.
    ToFooter,
    // Read a length field inside the header, at a known offset and width.
    FromHeaderField,
    // No terminator. Bounded by the signature's ceiling or by the next
    // accepted candidate, whichever comes first.
    ToNextCandidate,
};

struct FileSignature {
    const char* name;
    const char* extension;
    FileCategory category;
    // Bytes that must appear at headerOffset within the file. Matched exactly.
    std::vector<uint8_t> header;
    size_t headerOffset = 0;
    // Trailer bytes, for LengthRule::ToFooter. Matched at (length - footerSize).
    std::vector<uint8_t> footer;
    LengthRule lengthRule = LengthRule::ToFooter;

    // For LengthRule::FromHeaderField: offset of the length field, its width
    // in bytes, and its byte order.
    size_t sizeFieldOffset = 0;
    uint8_t sizeFieldWidth = 0;
    bool sizeFieldBigEndian = false;
    // Added to the field value. Some formats record the payload length rather
    // than the total file length.
    int64_t sizeFieldAdjustment = 0;

    // A length beyond this is treated as a false header match. Generous
    // ceilings are deliberate: a wrong guess here silently truncates a real
    // file, and a high ceiling only costs a little scanning.
    uint64_t maxSize = 1ull << 30;         // 1 GiB
    uint64_t minSize = 32;
    // Files with no terminator cannot be confirmed, so they are extracted as
    // uncertain even when the header is unambiguous.
    bool footerRequired = false;
    // Secondary bytes at a fixed offset, used to reject coincidental matches
    // of a short magic number.
    size_t verifyOffset = 0;
    std::vector<uint8_t> verifyBytes;
    // A signature that must appear inside the first N bytes of the header,
    // used by formats whose magic is weak.
    bool containerHint = false;
    // Walks the candidate's internal structure and reports where the file
    // really ends.
    //
    // This exists because of a measured failure. On a fragmented PNG the
    // header and the trailer are both genuine and belong to the same file, so
    // every length rule the carver had said "this is the file" - and it was
    // wrong: the bytes between the two belong to whatever the allocator put
    // there. The result scored HIGH confidence, which is the worst possible
    // answer, because it is indistinguishable from a clean recovery unless the
    // structure is actually walked.
    //
    // Returns false and sets `why` when the structure does not hold. `endAt`
    // receives the true end offset when it does, which can be earlier than the
    // search-based answer.
    using Validator = bool (*)(const uint8_t* data, size_t length, size_t* endAt,
                              std::string* why);
    Validator validator = nullptr;
};

const std::vector<FileSignature>& carvingSignatures();

// Looks at a byte range and names what it most likely contains, independent of
// which signature matched. Used to catch a DOCX being reported as a plain ZIP.
struct Classification {
    FileCategory category = FileCategory::UNKNOWN;
    std::string label;        // "OOXML word processing", "PNG image", ...
    std::string extension;    // recommended extension for the recovered file
    bool agreesWithSignature = false;
};

Classification classifyContent(const uint8_t* data, size_t length);

enum class Confidence {
    HIGH,        // header, a length field or a confirmed trailer, and content
                 // classification all agree
    MEDIUM,      // header plus a length source, but one is missing
    LOW,         // header only; length inferred
    VERY_LOW,    // weak magic, or the candidate was truncated by the source end
};

std::string confidenceToString(Confidence confidence);

struct RecoveredFile {
    uint64_t offset = 0;          // byte offset in the source
    uint64_t length = 0;          // extracted length in bytes
    std::string signatureName;
    std::string extension;
    FileCategory category = FileCategory::UNKNOWN;
    Confidence confidence = Confidence::LOW;
    double score = 0.0;           // 0.0 - 1.0, for ranking
    std::string sha256;           // of the extracted bytes
    // Every score adjustment, so a score can be argued with rather than
    // trusted. A carver that cannot say why it is sure is not evidence.
    std::vector<std::string> reasons;
    // Set when the candidate ran to the end of the source, which usually means
    // the file was truncated rather than recovered whole.
    bool truncated = false;
    // Set when the length had to be guessed because the format has no
    // terminator. Fragmented or interleaved files also land here.
    bool lengthInferred = false;
    // False when the format has a structure walker and the walk failed: the
    // header and the trailer are real but the bytes between them are not this
    // file's. Such a candidate is a fragmented or interleaved file, and it is
    // kept in the report rather than dropped, because "the file is here but
    // scattered" and "the file is gone" are different findings.
    bool structureValid = true;

    std::string describe() const;
};

// ---------------------------------------------------------------------------
// Source integrity and output containment
//
// A recovery source is evidence. Two rules follow from that, and neither can
// be left to the operator remembering them.
// ---------------------------------------------------------------------------

// SHA-256 of a whole file, read O_RDONLY and streamed.
//
// Taken twice around a scan: if the two differ, the source changed while it was
// being read, and every offset and length in the report then describes a
// mixture of two different states of the medium.
Result<std::string> sha256OfFile(const std::string& path);

// Refuses an output directory that sits on the source.
//
// The reason is not tidiness. Recovering files into the same medium being
// recovered overwrites the very bytes the scan is reading, so the result is
// both wrong and self-defeating, and on a block device it also destroys the
// evidence. Two checks, because "same device" has two meanings:
//
//  * for a file source, same filesystem - compared by st_dev, which is exact;
//  * for a block device source, any filesystem mounted on it or on one of its
//    partitions - a block device node has its own st_dev, so comparing numbers
//    would never fire.
//
// The directory itself must exist. A caller that names a non-existent path gets
// an error rather than a silent pass, because "the output is somewhere safe" is
// not a question with a default answer.
Result<void> requireOutputSeparateFromSource(const std::string& sourcePath,
                                              const std::string& outputDirectory);

struct CarveOptions {
    // Peak buffer is chunkSize + overlap. Overlap must exceed the largest
    // header we care about, so a file starting near a chunk boundary is still
    // seen whole.
    size_t chunkSize = 8u * 1024 * 1024;
    size_t overlap = 2u * 1024 * 1024;
    // Stop after this many candidates have been examined, so a signature that
    // matches every block cannot turn into an unbounded scan.
    size_t maxCandidates = 100000;
    // Refuse to emit more than this in total, so a pathological image cannot
    // fill the filesystem.
    uint64_t maxTotalOutputBytes = 8ull * 1024 * 1024 * 1024;
    // Ceiling on any length that was inferred rather than measured.
    //
    // A format with no terminator is resolved to the next accepted candidate,
    // or to its own ceiling, or to the end of the medium - and the last of
    // those is nonsense. A trailing gzip on a 96 MiB image resolved to tens of
    // megabytes of certainty-free output. An inferred length is never reported
    // as longer than this, and the result is marked truncated, which is the
    // honest description of it.
    uint64_t maxInferredLength = 16ull * 1024 * 1024;
    // Ignore candidates whose score falls below this.
    double minimumScore = 0.0;
    // Only these categories, when non-empty.
    std::vector<FileCategory> categoryFilter;
};

struct CarveReport {
    uint64_t sourceSize = 0;
    size_t candidatesExamined = 0;
    std::vector<RecoveredFile> files;
    // Candidates rejected for a reason worth recording, so a low recovery count
    // is explainable.
    std::vector<std::string> notes;
};

// A read-only, randomly-addressable byte source.
class CarveSource {
public:
    virtual ~CarveSource() = default;
    virtual Result<uint64_t> size() const = 0;
    // Reads up to length bytes at offset. Returns the count read; a short read
    // is normal at the end of the source.
    virtual Result<size_t> readAt(uint64_t offset, void* buffer,
                                  size_t length) const = 0;
};

// POSIX file-backed source. Opens O_RDONLY and never requests write access,
// so the kernel enforces the read-only property rather than this class
// promising it.
class FileCarveSource : public CarveSource {
public:
    explicit FileCarveSource(std::string path);
    ~FileCarveSource() override;

    FileCarveSource(const FileCarveSource&) = delete;
    FileCarveSource& operator=(const FileCarveSource&) = delete;

    Result<uint64_t> size() const override;
    Result<size_t> readAt(uint64_t offset, void* buffer,
                          size_t length) const override;

    const std::string& path() const { return path_; }

private:
    std::string path_;
    int fd_ = -1;
    uint64_t size_ = 0;
};

class Carver {
public:
    explicit Carver(CarveOptions options = CarveOptions());

    // Scans the whole source. Does not write anything anywhere: the report is
    // the output, and extraction is a separate, explicit step.
    Result<CarveReport> scan(const CarveSource& source) const;

    // Extracts one recovered file to a path. Refuses to write outside
    // `outputDirectory` and refuses to follow a symlink at the destination.
    Result<uint64_t> extract(const CarveSource& source,
                             const RecoveredFile& file,
                             const std::string& outputDirectory,
                             std::string& writtenPath) const;

    // Suggests a destination name that cannot collide: prefix, offset, size.
    static std::string suggestName(const RecoveredFile& file);

    // How many more bytes may be written, given what has already been.
    //
    // The cap used to be applied by the caller, which meant the Carver held a
    // limit it never checked and a second copy had to be kept in step. The
    // object that carries the limit is the object that enforces it.
    //
    // Returns the remaining budget, and sets `allowed` to false when nothing
    // more may be written - including when a single remaining candidate is
    // larger than what is left, so the cap is a hard bound and not a rounding.
    uint64_t extractionBudgetRemaining(uint64_t alreadyWritten,
                                      bool& allowed) const;

    const CarveOptions& options() const { return options_; }

private:
    CarveOptions options_;
};

} // namespace ledgerase

#endif // LEDGERASE_CARVING_HPP
