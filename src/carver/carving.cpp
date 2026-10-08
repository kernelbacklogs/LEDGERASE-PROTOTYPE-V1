#include "ledgerase/carving.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include "ledgerase/evidence.hpp"
#include "platform/linux/linux.hpp"

namespace ledgerase {

namespace {

std::vector<uint8_t> bytesOf(std::initializer_list<int> values) {
    std::vector<uint8_t> out;
    out.reserve(values.size());
    for (const int value : values) {
        out.push_back(static_cast<uint8_t>(value));
    }
    return out;
}

// CRC-32 as PNG and gzip use it: the reflected 0xEDB88320 polynomial, with the
// usual pre/post inversion. Written out rather than pulled from zlib because
// the build takes no compression library, and a carver that has to link zlib to
// check a 4-byte field is a dependency nobody should accept in an erasure tool.
uint32_t crc32Of(const uint8_t* data, size_t length) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value & 1) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
            }
            table[i] = value;
        }
        built = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

uint32_t readBigEndian32(const uint8_t* at) {
    return (static_cast<uint32_t>(at[0]) << 24) |
           (static_cast<uint32_t>(at[1]) << 16) |
           (static_cast<uint32_t>(at[2]) << 8) | static_cast<uint32_t>(at[3]);
}

// Walks a PNG's chunk list.
//
// PNG is self-delimiting: after the 8-byte signature every chunk carries its own
// big-endian length and a CRC-32 over its type and data. Walking that list is
// the only way to know where the file ends, and it is also the only way to tell
// a real file from a chimera.
//
// The chimera is the case this exists for. A fragmented file's first and last
// blocks are genuine, so a search for the IEND marker finds a real one and the
// length rule reports the file as recovered - at high confidence, since nothing
// in the header or the trailer is wrong. What is wrong is everything between.
// The measured result on a fragmented PNG before this check: a 304 623-byte
// "recovery" of a 120 303-byte file, scored HIGH. After it, the walk hits
// filler bytes where a chunk length should be and the candidate is reported as
// what it is.
bool validatePng(const uint8_t* data, size_t length, size_t* endAt,
                 std::string* why) {
    if (data == nullptr || length < 8) {
        *why = "fewer bytes than a PNG signature";
        return false;
    }
    size_t at = 8;
    bool sawHeader = false;
    bool sawEnd = false;
    while (at + 12 <= length) {
        const uint32_t chunkLength = readBigEndian32(data + at);
        if (chunkLength > length) {
            *why = "a chunk claims " + std::to_string(chunkLength) +
                   " bytes, more than the whole candidate";
            return false;
        }
        const uint8_t* type = data + at + 4;
        const size_t total = 12u + chunkLength;
        if (at + total > length) {
            *why = "a chunk runs past the end of the candidate";
            return false;
        }
        const uint32_t stored = readBigEndian32(data + at + 8 + chunkLength);
        const uint32_t computed = crc32Of(type, 4 + chunkLength);
        if (stored != computed) {
            *why = "the chunk at offset " + std::to_string(at) +
                   " has a CRC that does not match its contents";
            return false;
        }
        if (std::memcmp(type, "IHDR", 4) == 0) {
            sawHeader = true;
        }
        at += total;
        if (std::memcmp(type, "IEND", 4) == 0) {
            if (chunkLength != 0) {
                *why = "IEND is not empty";
                return false;
            }
            sawEnd = true;
            break;
        }
    }
    if (!sawHeader) {
        *why = "no IHDR chunk, so this is not a PNG file structure";
        return false;
    }
    if (!sawEnd) {
        *why = "the chunk list does not reach an IEND";
        return false;
    }
    *endAt = at;
    return true;
}

const FileSignature kJpeg{
    "jpeg", "jpg", FileCategory::IMAGE,
    bytesOf({0xFF, 0xD8, 0xFF}), 0,
    bytesOf({0xFF, 0xD9}), LengthRule::ToFooter,
    0, 0, false, 0, 64ull * 1024 * 1024, 128, true, 0, {}, false};

const FileSignature kPng{
    "png", "png", FileCategory::IMAGE,
    bytesOf({0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}), 0,
    bytesOf({0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}),
    LengthRule::ToFooter,
    0, 0, false, 0, 64ull * 1024 * 1024, 67, true, 0, {}, false,
    &validatePng};

const FileSignature kGif{
    "gif", "gif", FileCategory::IMAGE,
    bytesOf({'G', 'I', 'F', '8', '9', 'a'}), 0,
    bytesOf({0x3B}), LengthRule::ToFooter,
    0, 0, false, 0, 128ull * 1024 * 1024, 26, true, 0, {}, false};

const FileSignature kBmp{
    "bmp", "bmp", FileCategory::IMAGE,
    bytesOf({'B', 'M'}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 256ull * 1024 * 1024, 14, false, 0, {}, false};

const FileSignature kTiff{
    "tiff", "tif", FileCategory::IMAGE,
    bytesOf({'I', 'I', 0x2A, 0x00}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 256ull * 1024 * 1024, 8, false, 0, {}, false};

const FileSignature kWebp{
    "webp", "webp", FileCategory::IMAGE,
    bytesOf({'R', 'I', 'F', 'F'}), 0,
    {}, LengthRule::FromHeaderField,
    4, 4, false, 8, 64ull * 1024 * 1024, 12, false,
    8, bytesOf({'W', 'E', 'B', 'P'}), false};

const FileSignature kIco{
    "ico", "ico", FileCategory::IMAGE,
    bytesOf({0x00, 0x00, 0x01, 0x00}), 0,
    {}, LengthRule::FromHeaderField,
    0, 0, false, 0, 64ull * 1024 * 1024, 22, false, 0, {}, false};

const FileSignature kPdf{
    "pdf", "pdf", FileCategory::DOCUMENT,
    bytesOf({'%', 'P', 'D', 'F', '-'}), 0,
    bytesOf({'%', '%', 'E', 'O', 'F'}), LengthRule::ToFooter,
    0, 0, false, 0, 64ull * 1024 * 1024, 32, true, 0, {}, false};

const FileSignature kZip{
    "zip", "zip", FileCategory::ARCHIVE,
    bytesOf({'P', 'K', 0x03, 0x04}), 0,
    bytesOf({'P', 'K', 0x05, 0x06}), LengthRule::ToFooter,
    0, 0, false, 0, 4ull * 1024 * 1024 * 1024, 22, true, 0, {}, false};

// gzip's last four bytes are ISIZE, the length of the *uncompressed* data. That
// is not the file length, and using it as one truncates every member whose
// compression ratio is not exactly 1. The compressed length is only obtainable
// by walking the deflate stream, which is structure-aware work, so the length is
// inferred here and the result is reported as uncertain rather than guessed at
// confidently.
const FileSignature kGzip{
    "gzip", "gz", FileCategory::ARCHIVE,
    bytesOf({0x1F, 0x8B, 0x08}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 256ull * 1024 * 1024, 18, false, 0, {}, false};

const FileSignature kBzip2{
    "bzip2", "bz2", FileCategory::ARCHIVE,
    bytesOf({'B', 'Z', 'h'}), 0,
    bytesOf({0x17, 0x72, 0x45, 0x38, 0x50, 0x90}), LengthRule::ToFooter,
    0, 0, false, 0, 64ull * 1024 * 1024, 14, true, 0, {}, false};

const FileSignature kXz{
    "xz", "xz", FileCategory::ARCHIVE,
    bytesOf({0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}), 0,
    bytesOf({'Y', 'Z'}), LengthRule::ToFooter,
    0, 0, false, 0, 64ull * 1024 * 1024, 32, true, 0, {}, false};

const FileSignature kSevenZip{
    "7zip", "7z", FileCategory::ARCHIVE,
    bytesOf({0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}), 0,
    bytesOf({0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1D}), LengthRule::ToFooter,
    0, 0, false, 0, 256ull * 1024 * 1024, 32, true, 0, {}, false};

// TAR has no magic at offset 0. "ustar" sits at 257, and the file size is an
// octal field at 124, so the length is exact rather than searched for.
const FileSignature kTar{
    "tar", "tar", FileCategory::ARCHIVE,
    bytesOf({'u', 's', 't', 'a', 'r'}), 257,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 8ull * 1024 * 1024 * 1024, 512, false, 0, {}, false};

const FileSignature kRar{
    "rar", "rar", FileCategory::ARCHIVE,
    bytesOf({'R', 'a', 'r', '!'}), 0,
    bytesOf({0x7B, 0x3D, 0xC4}), LengthRule::ToFooter,
    0, 0, false, 0, 256ull * 1024 * 1024, 7, true, 0, {}, false};

const FileSignature kElf{
    "elf", "elf", FileCategory::EXECUTABLE,
    bytesOf({0x7F, 'E', 'L', 'F'}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 256ull * 1024 * 1024, 64, false, 4, bytesOf({1, 0, 0, 0}),
    false};

const FileSignature kPe{
    "pe", "exe", FileCategory::EXECUTABLE,
    bytesOf({'M', 'Z'}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 256ull * 1024 * 1024, 64, false, 0, {}, false};

const FileSignature kSqlite{
    "sqlite", "sqlite", FileCategory::DATABASE,
    bytesOf({'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't',
             ' ', '3', 0x00}),
    0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 4ull * 1024 * 1024 * 1024, 512, false, 0, {}, false};

const FileSignature kOle2{
    "ole2", "doc", FileCategory::DOCUMENT,
    bytesOf({0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 512ull * 1024 * 1024, 512, false, 0, {}, false};

// ISO base media (MP4 and friends). "ftyp" is at offset 4 and every box after
// it carries its own length, so the real length is a structure walk rather than
// a search. The generic rule here is deliberately ToNextCandidate with a
// modest ceiling: reporting a precise length for a format this carver has not
// walked would be a guess dressed as a measurement.
const FileSignature kIsoBmff{
    "iso-bmff", "mp4", FileCategory::AUDIO_VIDEO,
    bytesOf({'f', 't', 'y', 'p'}), 4,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 4ull * 1024 * 1024 * 1024, 32, false, 0, {}, false};

const FileSignature kRiff{
    "riff", "wav", FileCategory::AUDIO_VIDEO,
    bytesOf({'R', 'I', 'F', 'F'}), 0,
    {}, LengthRule::FromHeaderField,
    4, 4, false, 8, 2ull * 1024 * 1024 * 1024, 12, false,
    8, bytesOf({'W', 'A', 'V', 'E'}), false};

const FileSignature kOgg{
    "ogg", "ogg", FileCategory::AUDIO_VIDEO,
    bytesOf({'O', 'g', 'g', 'S'}), 0,
    {}, LengthRule::ToNextCandidate,
    0, 0, false, 0, 512ull * 1024 * 1024, 27, false, 0, {}, false};

// A file-start table: for each possible first byte, which signatures could
// begin there.
//
// Without it the scan compares every one of ~23 signatures at every byte
// position, which on a zero-filled medium is 200-odd million memcmp calls per
// chunk doing nothing. Nearly every byte of a disk is not a file header's first
// byte, so one lookup rejects almost all positions before any comparison.
struct StartTable {
    // For each first byte, a bitmask of the signatures that could start there.
    //
    // This has to identify *which* signatures, not merely say "maybe". A
    // boolean gate looks like an optimisation and is not one when any
    // signature's first byte is common: an ICO header begins 0x00 0x00 0x01
    // 0x00, so on a zero-filled medium every byte looked plausible and the scan
    // fell through to all twenty-three signatures at every offset.
    //
    // A bitmask rather than a list, because a std::vector per byte is a
    // 24-byte header plus a heap pointer, and this is looked up once per byte
    // of medium. One 4-byte word per possible first byte keeps it in cache.
    uint32_t mask[256] = {};
    // Signatures whose header is not at offset 0, looked up at their own
    // offset, so they are handled separately.
    std::vector<uint16_t> offsetSignatures;

    explicit StartTable(const std::vector<FileSignature>& signatures) {
        for (size_t i = 0; i < signatures.size() && i < 32; ++i) {
            const FileSignature& signature = signatures[i];
            if (signature.header.empty()) {
                continue;
            }
            if (signature.headerOffset != 0) {
                offsetSignatures.push_back(static_cast<uint16_t>(i));
                continue;
            }
            mask[signature.header[0]] |= (1u << i);
        }
    }
};

const StartTable& startTable() {
    static const StartTable table(carvingSignatures());
    return table;
}

// Plain substring search over bytes. Used to look for a name inside a
// container, where a match is weak evidence rather than a format check.
bool containsBytes(const uint8_t* haystack, size_t haystackLength,
                   const char* needle, size_t needleLength) {
    if (needleLength == 0 || haystackLength < needleLength) {
        return false;
    }
    for (size_t i = 0; i + needleLength <= haystackLength; ++i) {
        if (std::memcmp(haystack + i, needle, needleLength) == 0) {
            return true;
        }
    }
    return false;
}

bool startsWith(const uint8_t* data, size_t length,
                const std::vector<uint8_t>& prefix, size_t offset) {
    if (data == nullptr || prefix.empty()) {
        return false;
    }
    if (offset + prefix.size() > length) {
        return false;
    }
    return std::memcmp(data + offset, prefix.data(), prefix.size()) == 0;
}

uint64_t readSizeField(const uint8_t* data, const FileSignature& signature) {
    const size_t at = signature.sizeFieldOffset;
    const size_t width = signature.sizeFieldWidth;
    if (data == nullptr || width == 0) {
        return 0;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        const uint8_t byte = signature.sizeFieldBigEndian
                                 ? data[at + i]
                                 : data[at + width - 1 - i];
        value = (value << 8) | byte;
    }
    return value;
}

// Finds where a trailer-terminated format ends.
//
// The first trailer found is not always the end of the file. A real PDF from a
// distribution ends with "%%EOF" followed by a newline, so taking the first
// match truncates the last byte and the recovered hash will not match. A
// trailer may also appear inside an embedded stream.
//
// So: find the first match, then look for a later one within a small window and
// prefer it. A trailer much further away than that is more likely to be inside
// the file than to be its real end, so the search is bounded.
uint64_t findFooter(const CarveSource& source, uint64_t start,
                    const FileSignature& signature, uint64_t sourceSize,
                    bool& found) {
    found = false;
    if (signature.footer.empty()) {
        return 0;
    }

    // The search is bounded by the format's own ceiling, not by the end of the
    // medium. Without this a candidate whose trailer is absent costs a scan of
    // everything after it: on a 512 MiB image with a hundred-odd weak matches
    // that was tens of gigabytes of reads, and it was the whole of the scan
    // time. Bounding at the ceiling is also more correct - a file longer than
    // its format's ceiling is not that format's file.
    const uint64_t searchLimit =
        (signature.maxSize > 0 && start + signature.maxSize < sourceSize)
            ? start + signature.maxSize
            : sourceSize;
    // The window bounds both memory and the number of reads. At 1 MiB a
    // trailer search over a 24 MiB medium issued two dozen pread calls per
    // candidate, and the suite spent most of its time in the kernel. 8 MiB
    // keeps peak memory bounded while cutting that by eight.
    const size_t window = 8u << 20;
    const size_t needle = signature.footer.size();
    std::vector<uint8_t> buffer(window + needle);

    // Bytes after a trailer that are still plausibly part of the file. A
    // trailing newline or a few padding bytes is normal; a kilobyte is not.
    constexpr uint64_t kTrailerTolerance = 64;

    uint64_t firstMatch = 0;
    bool haveFirst = false;

    for (uint64_t at = start; at < searchLimit; at += window) {
        const uint64_t remaining = searchLimit - at;
        const size_t want = static_cast<size_t>(
            std::min<uint64_t>(remaining, window + needle));
        const auto read = source.readAt(at, buffer.data(), want);
        if (read.isError() || read.value() < needle) {
            break;
        }
        const size_t got = read.value();
        for (size_t i = 0; i + needle <= got; ++i) {
            if (std::memcmp(buffer.data() + i, signature.footer.data(), needle) !=
                0) {
                continue;
            }
            const uint64_t end = at + i + needle;
            if (!haveFirst) {
                firstMatch = end;
                haveFirst = true;
                found = true;
                continue;
            }
            // A later trailer close behind the first is the real end.
            if (end - firstMatch <= kTrailerTolerance) {
                return end;
            }
            // Far away: a trailer inside the file, so stop at the first.
            return firstMatch;
        }
        if (got < want) {
            break;
        }
    }
    return firstMatch;
}

// Extends a trailer-terminated file over the padding that follows its marker.
//
// A PDF produced by a distribution ends with "%%EOF" and then a newline, so a
// carver that stops at the marker returns every byte except the last one and the
// recovered hash will not match the original.
//
// Only whitespace is absorbed, and only a few bytes of it. NUL is deliberately
// NOT absorbed: a medium is largely zero-filled, and treating trailing zeroes as
// padding made every recovered file run on to the next 4 KiB boundary. Formats
// that legitimately end in NUL (BMP, ICO) are common, so absorbing them would
// corrupt those too.
uint64_t extendOverTrailingPadding(const CarveSource& source, uint64_t end,
                                   uint64_t sourceSize) {
    constexpr uint64_t kMaxPadding = 8;
    constexpr size_t kChunk = 256;
    uint8_t buffer[kChunk];

    uint64_t at = end;
    uint64_t absorbed = 0;
    while (at < sourceSize && absorbed < kMaxPadding) {
        const size_t want = static_cast<size_t>(
            std::min<uint64_t>(sourceSize - at, kChunk));
        const auto read = source.readAt(at, buffer, want);
        if (read.isError() || read.value() == 0) {
            break;
        }
        size_t run = 0;
        for (; run < read.value(); ++run) {
            const uint8_t byte = buffer[run];
            const bool isPadding =
                byte == 0x0A || byte == 0x0D || byte == 0x20 || byte == 0x09;
            if (!isPadding) {
                break;
            }
        }
        at += run;
        absorbed += run;
        if (run < read.value()) {
            break;
        }
    }
    return at;
}

} // namespace

std::string fileCategoryToString(FileCategory category) {
    switch (category) {
        case FileCategory::IMAGE:
            return "image";
        case FileCategory::DOCUMENT:
            return "document";
        case FileCategory::ARCHIVE:
            return "archive";
        case FileCategory::AUDIO_VIDEO:
            return "audio/video";
        case FileCategory::EXECUTABLE:
            return "executable";
        case FileCategory::DATABASE:
            return "database";
        case FileCategory::TEXT:
            return "text";
        case FileCategory::UNKNOWN:
        default:
            return "unknown";
    }
}

std::string confidenceToString(Confidence confidence) {
    switch (confidence) {
        case Confidence::HIGH:
            return "high";
        case Confidence::MEDIUM:
            return "medium";
        case Confidence::LOW:
            return "low";
        case Confidence::VERY_LOW:
            return "very low";
        default:
            return "unknown";
    }
}

std::string RecoveredFile::describe() const {
    std::ostringstream out;
    out << signatureName << " at offset " << offset << ", " << length
        << " bytes, " << confidenceToString(confidence) << " confidence ("
        << fileCategoryToString(category) << ")";
    if (truncated) {
        out << ", truncated at the end of the source";
    }
    if (lengthInferred) {
        out << ", length inferred";
    }
    return out.str();
}

const std::vector<FileSignature>& carvingSignatures() {
    static const std::vector<FileSignature> table = {
        kJpeg,    kPng,     kGif,     kBmp,     kTiff,   kWebp,
        kIco,     kPdf,     kZip,     kGzip,    kBzip2,  kXz,
        kSevenZip, kTar,    kRar,     kElf,     kPe,     kSqlite,
        kOle2,    kIsoBmff, kRiff,    kOgg,
    };
    return table;
}

Classification classifyContent(const uint8_t* data, size_t length) {
    Classification result;
    if (data == nullptr || length < 4) {
        // Not an error: there is too little to go on. Saying so is better than
        // an empty label in the reason text, which reads as a tool that lost
        // track of what it was doing.
        result = {FileCategory::UNKNOWN, "not enough bytes to classify", "bin",
                  false};
        return result;
    }

    if (startsWith(data, length, bytesOf({0x89, 'P', 'N', 'G', 0x0D, 0x0A,
                                          0x1A, 0x0A}),
                   0)) {
        result = {FileCategory::IMAGE, "PNG image", "png", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({0xFF, 0xD8, 0xFF}), 0)) {
        result = {FileCategory::IMAGE, "JPEG image", "jpg", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'G', 'I', 'F', '8'}), 0)) {
        result = {FileCategory::IMAGE, "GIF image", "gif", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'B', 'M'}), 0)) {
        result = {FileCategory::IMAGE, "BMP image", "bmp", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'%', 'P', 'D', 'F'}), 0)) {
        result = {FileCategory::DOCUMENT, "PDF document", "pdf", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({0x1F, 0x8B, 0x08}), 0)) {
        result = {FileCategory::ARCHIVE, "gzip stream", "gz", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'B', 'Z', 'h'}), 0)) {
        result = {FileCategory::ARCHIVE, "bzip2 stream", "bz2", true};
        return result;
    }
    if (startsWith(data, length,
                   bytesOf({0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}), 0)) {
        result = {FileCategory::ARCHIVE, "xz stream", "xz", true};
        return result;
    }
    if (startsWith(data, length,
                   bytesOf({0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}), 0)) {
        result = {FileCategory::ARCHIVE, "7-zip archive", "7z", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'R', 'a', 'r', '!'}), 0)) {
        result = {FileCategory::ARCHIVE, "RAR archive", "rar", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({0x7F, 'E', 'L', 'F'}), 0)) {
        result = {FileCategory::EXECUTABLE, "ELF executable", "elf", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'S', 'Q', 'L', 'i', 't', 'e',
                                          ' ', 'f', 'o', 'r', 'm', 'a', 't'}),
                   0)) {
        result = {FileCategory::DATABASE, "SQLite database", "sqlite", true};
        return result;
    }
    if (startsWith(data, length,
                   bytesOf({0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}),
                   0)) {
        result = {FileCategory::DOCUMENT,
                  "OLE2 compound document (legacy Office)", "doc", true};
        return result;
    }

    if (startsWith(data, length, bytesOf({'P', 'K', 0x03, 0x04}), 0)) {
        // A ZIP is a container. Naming the inner application is the difference
        // between "recovered a zip" and "recovered a Word document", and the
        // caller would otherwise have to open every archive.
        static const char* kOoxml[] = {
            "word/document.xml",     "xl/workbook.xml",
            "ppt/presentation.xml",  "docProps/app.xml",
        };
        static const char* kOoxmlExtensions[] = {"docx", "xlsx", "pptx", "docx"};
        const size_t window = std::min<size_t>(length, 65536);
        for (size_t i = 0; i < std::size(kOoxml); ++i) {
            if (window > std::strlen(kOoxml[i]) &&
                containsBytes(data, window, kOoxml[i], std::strlen(kOoxml[i]))) {
                result = {FileCategory::DOCUMENT, "OOXML document",
                          kOoxmlExtensions[i], true};
                return result;
            }
        }
        result = {FileCategory::ARCHIVE, "ZIP archive", "zip", true};
        return result;
    }

    if (startsWith(data, length, bytesOf({'R', 'I', 'F', 'F'}), 0)) {
        if (length >= 12 && std::memcmp(data + 8, "WEBP", 4) == 0) {
            result = {FileCategory::IMAGE, "WebP image", "webp", true};
            return result;
        }
        if (length >= 12 && std::memcmp(data + 8, "WAVE", 4) == 0) {
            result = {FileCategory::AUDIO_VIDEO, "WAVE audio", "wav", true};
            return result;
        }
        result = {FileCategory::AUDIO_VIDEO, "RIFF container", "bin", false};
        return result;
    }

    if (startsWith(data, length, bytesOf({'f', 't', 'y', 'p'}), 4)) {
        result = {FileCategory::AUDIO_VIDEO, "ISO base media", "mp4", true};
        return result;
    }
    if (startsWith(data, length, bytesOf({'O', 'g', 'g', 'S'}), 0)) {
        result = {FileCategory::AUDIO_VIDEO, "Ogg stream", "ogg", true};
        return result;
    }

    // Plain text is worth reporting rather than discarding, but only when the
    // bytes are overwhelmingly printable, so a random string of zeroes is not
    // offered as a text file.
    if (length >= 32) {
        size_t printable = 0;
        const size_t sample = std::min<size_t>(length, 4096);
        for (size_t i = 0; i < sample; ++i) {
            const uint8_t byte = data[i];
            if (byte == '\n' || byte == '\r' || byte == '\t' ||
                (byte >= 0x20 && byte < 0x7F) || byte >= 0xC0) {
                ++printable;
            }
        }
        if (printable * 100 >= sample * 95) {
            result = {FileCategory::TEXT, "plain text", "txt", true};
        }
    }

    result = {FileCategory::UNKNOWN, "unrecognised", "bin", false};
    return result;
}

FileCarveSource::FileCarveSource(std::string path) : path_(std::move(path)) {
    // O_RDONLY only. The read-only property of a recovery source is enforced
    // by the kernel, not promised by this class.
    fd_ = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
        return;
    }
    struct stat st {};
    if (::fstat(fd_, &st) == 0) {
        size_ = static_cast<uint64_t>(st.st_size);
    }
}

FileCarveSource::~FileCarveSource() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

Result<uint64_t> FileCarveSource::size() const {
    if (fd_ < 0) {
        return Result<uint64_t>::err(
            ErrorCode::IO_ERROR, "Cannot open for reading: " + path_,
            "A recovery source must be readable. The file is never opened for "
            "writing.");
    }
    return Result<uint64_t>::ok(size_);
}

Result<size_t> FileCarveSource::readAt(uint64_t offset, void* buffer,
                                       size_t length) const {
    if (fd_ < 0) {
        return Result<size_t>::err(ErrorCode::IO_ERROR,
                                   "Source is not open: " + path_);
    }
    auto* out = static_cast<uint8_t*>(buffer);
    size_t total = 0;
    while (total < length) {
        const ssize_t got =
            ::pread(fd_, out + total, length - total,
                    static_cast<off_t>(offset + total));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return Result<size_t>::err(
                ErrorCode::IO_ERROR,
                "Read failed at offset " + std::to_string(offset) + ": " +
                    std::strerror(errno));
        }
        if (got == 0) {
            break;
        }
        total += static_cast<size_t>(got);
    }
    return Result<size_t>::ok(total);
}

Carver::Carver(CarveOptions options) : options_(std::move(options)) {
    if (options_.chunkSize < (1u << 20)) {
        options_.chunkSize = 1u << 20;
    }
    // The overlap has to exceed the largest header a signature looks at, or a
    // file beginning near a chunk boundary is split across two buffers and its
    // header is never seen whole.
    const size_t largestHeader = 512;
    if (options_.overlap < largestHeader) {
        options_.overlap = largestHeader * 2;
    }
    if (options_.overlap >= options_.chunkSize) {
        options_.overlap = options_.chunkSize / 2;
    }
}

uint64_t Carver::extractionBudgetRemaining(uint64_t alreadyWritten,
                                           bool& allowed) const {
    if (alreadyWritten >= options_.maxTotalOutputBytes) {
        allowed = false;
        return 0;
    }
    allowed = true;
    return options_.maxTotalOutputBytes - alreadyWritten;
}

std::string Carver::suggestName(const RecoveredFile& file) {
    std::ostringstream name;
    const std::string extension = file.extension.empty() ? "bin" : file.extension;
    name << "carved_" << std::hex << file.offset << std::dec << "_"
         << file.length << "B." << extension;
    return name.str();
}

Result<uint64_t> Carver::extract(const CarveSource& source,
                                 const RecoveredFile& file,
                                 const std::string& outputDirectory,
                                 std::string& writtenPath) const {
    const auto sourceSize = source.size();
    if (sourceSize.isError()) {
        return Result<uint64_t>::err(sourceSize.error());
    }
    if (file.length == 0 || file.offset >= sourceSize.value()) {
        return Result<uint64_t>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Refusing to extract: the candidate lies outside the source",
            "The recorded offset and length do not describe a region of the "
            "source that exists.");
    }

    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec) {
        return Result<uint64_t>::err(
            ErrorCode::IO_ERROR,
            "Cannot create the output directory: " + outputDirectory);
    }

    const std::string destination = outputDirectory + "/" + suggestName(file);

    // O_EXCL so an existing file is never overwritten: a recovery run must be
    // additive, and silently clobbering an earlier recovery would be its own
    // kind of data loss.
    const int out = ::open(destination.c_str(),
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0) {
        return Result<uint64_t>::err(
            ErrorCode::IO_ERROR,
            "Cannot create " + destination + ": " + std::strerror(errno),
            "A file of that name already exists. Recovery output is never "
            "overwritten.");
    }

    uint64_t written = 0;
    const size_t block = 1u << 20;
    std::vector<uint8_t> buffer(block);
    while (written < file.length) {
        const size_t want = static_cast<size_t>(
            std::min<uint64_t>(file.length - written, block));
        const auto read =
            source.readAt(file.offset + written, buffer.data(), want);
        if (read.isError() || read.value() == 0) {
            ::close(out);
            return Result<uint64_t>::err(
                ErrorCode::IO_ERROR,
                "Read failed while extracting " + destination);
        }
        size_t position = 0;
        while (position < read.value()) {
            const ssize_t put = ::write(out, buffer.data() + position,
                                        read.value() - position);
            if (put < 0) {
                if (errno == EINTR) {
                    continue;
                }
                ::close(out);
                return Result<uint64_t>::err(
                    ErrorCode::IO_ERROR,
                    std::string("Write failed: ") + std::strerror(errno));
            }
            position += static_cast<size_t>(put);
        }
        written += read.value();
    }
    ::fsync(out);
    ::close(out);

    writtenPath = destination;
    return Result<uint64_t>::ok(written);
}

Result<CarveReport> Carver::scan(const CarveSource& source) const {
    const auto sourceSize = source.size();
    if (sourceSize.isError()) {
        return Result<CarveReport>::err(sourceSize.error());
    }
    const uint64_t total = sourceSize.value();

    CarveReport report;
    report.sourceSize = total;

    if (total == 0) {
        report.notes.push_back("The source is empty.");
        return Result<CarveReport>::ok(std::move(report));
    }

    const std::vector<FileSignature>& table = carvingSignatures();
    const StartTable& starts = startTable();
    std::vector<uint8_t> buffer(options_.chunkSize + options_.overlap);

    // Offsets of accepted candidates, so a format with no terminator can be cut
    // off at the next file rather than running to the end of the medium.
    std::vector<uint64_t> accepted;
    // Reused per byte position so the candidate list costs no allocation.
    std::vector<const FileSignature*> candidates;
    candidates.reserve(8);

    for (uint64_t base = 0; base < total; base += options_.chunkSize) {
        const uint64_t remaining = total - base;
        const size_t want = static_cast<size_t>(
            std::min<uint64_t>(remaining, options_.chunkSize + options_.overlap));

        const auto read = source.readAt(base, buffer.data(), want);
        if (read.isError()) {
            return Result<CarveReport>::err(read.error());
        }
        const size_t got = read.value();
        if (got == 0) {
            break;
        }

        // The overlap exists so a file whose header straddles a chunk boundary
        // is seen whole. It must therefore be *skipped* at the start of every
        // chunk after the first: the previous chunk already scanned those bytes,
        // and rescanning them reported the same file twice, at two identical
        // offsets with two identical digests.
        const size_t scanFrom = (base == 0) ? 0 : options_.overlap;
        if (scanFrom >= got) {
            continue;
        }

        for (size_t i = scanFrom; i < got; ++i) {
            if (report.candidatesExamined >= options_.maxCandidates) {
                report.notes.push_back(
                    "Stopped after examining the candidate limit of " +
                    std::to_string(options_.maxCandidates) +
                    ". Raise CarveOptions::maxCandidates to continue; the "
                    "remainder of the source was not scanned.");
                return Result<CarveReport>::ok(std::move(report));
            }

            const uint8_t* at = buffer.data() + i;
            const size_t available = got - i;
            const uint64_t absolute = base + i;

            // Skip to just past this byte on any match so a header inside
            // another candidate's body is not examined again.
            bool matchedAny = false;

            // One word narrows twenty-three signatures to the one or two that
            // can start with this byte, so a position that cannot begin a file
            // costs a single table read and a zero test.
            uint32_t bits = starts.mask[at[0]];
            for (const uint16_t index : starts.offsetSignatures) {
                const FileSignature& signature = table[index];
                if (signature.headerOffset < available &&
                    at[signature.headerOffset] == signature.header[0]) {
                    bits |= (1u << index);
                }
            }
            if (bits == 0) {
                continue;
            }
            candidates.clear();
            while (bits != 0) {
                const unsigned index =
                    static_cast<unsigned>(__builtin_ctz(bits));
                bits &= bits - 1;
                candidates.push_back(&table[index]);
            }

            for (const FileSignature* signaturePointer : candidates) {
                const FileSignature& signature = *signaturePointer;
                if (!options_.categoryFilter.empty() &&
                    std::find(options_.categoryFilter.begin(),
                              options_.categoryFilter.end(),
                              signature.category) ==
                        options_.categoryFilter.end()) {
                    continue;
                }
                if (!startsWith(at, available, signature.header,
                                signature.headerOffset)) {
                    continue;
                }
                if (!signature.verifyBytes.empty() &&
                    !startsWith(at, available, signature.verifyBytes,
                                signature.verifyOffset)) {
                    continue;
                }

                matchedAny = true;
                ++report.candidatesExamined;

                RecoveredFile recovered;
                recovered.offset = absolute;
                recovered.signatureName = signature.name;
                recovered.extension = signature.extension;
                recovered.category = signature.category;

                double score = 0.60;
                recovered.reasons.push_back(
                    "header matched " + std::string(signature.name) +
                    " at the expected offset");
                if (!signature.verifyBytes.empty()) {
                    score += 0.10;
                    recovered.reasons.push_back(
                        "the secondary marker at offset " +
                        std::to_string(signature.verifyOffset) +
                        " also matched, so this is not a coincidental prefix");
                }

                uint64_t length = 0;
                bool lengthFromField = false;
                bool footerFound = false;
                uint64_t footerEnd = 0;

                if (absolute + signature.headerOffset >= total) {
                    // The header is cut off by the end of the source.
                    continue;
                }

                if (signature.lengthRule == LengthRule::FromHeaderField) {
                    // The field has to be inside the bytes already read.
                    const size_t needed = signature.sizeFieldOffset +
                                          signature.sizeFieldWidth;
                    if (available < needed) {
                        continue;
                    }
                    const uint64_t field =
                        readSizeField(at, signature);
                    if (field == 0) {
                        continue;
                    }
                    length = field + static_cast<uint64_t>(
                                           signature.sizeFieldAdjustment);
                    lengthFromField = true;
                } else if (signature.lengthRule == LengthRule::ToFooter) {
                    footerEnd = findFooter(source, absolute + signature.headerOffset +
                                                      signature.header.size(),
                                           signature, total, footerFound);
                    if (!footerFound) {
                        continue;
                    }
                    if (footerEnd < total) {
                        footerEnd = extendOverTrailingPadding(source, footerEnd,
                                                               total);
                    }
                    length = footerEnd - absolute;
                } else {
                    // ToNextCandidate: bounded by the ceiling for now and
                    // tightened once the whole scan is known.
                    length = 0;   // resolved after the pass
                }

                // Structural validation, where the format has one.
                //
                // Run before the length is used, so a candidate whose internal
                // structure does not hold cannot be reported as a recovery on
                // the strength of a header and a trailer that are both real
                // but belong to different files. The walk needs the candidate's
                // bytes, so the length computed above is used as the window -
                // which is exactly the point: if the walk fails, the length was
                // wrong.
                bool structureOk = true;
                std::string structureWhy;
                if (signature.validator != nullptr && length > 0 &&
                    absolute + length <= total) {
                    std::vector<uint8_t> window(
                        static_cast<size_t>(length));
                    if (source.readAt(absolute, window.data(), window.size())
                            .ok()) {
                        size_t walkedEnd = 0;
                        structureOk =
                            signature.validator(window.data(), window.size(),
                                                &walkedEnd, &structureWhy);
                        if (structureOk && walkedEnd > 0 &&
                            walkedEnd < window.size()) {
                            // The walk found a shorter file than the search
                            // did. Trust the walk: it is reading the format's
                            // own length fields.
                            recovered.reasons.push_back(
                                "the format's own structure ends the file at " +
                                std::to_string(absolute + walkedEnd) +
                                ", before the trailer search did");
                            length = walkedEnd;
                        }
                    } else {
                        structureOk = false;
                        structureWhy = "the candidate's bytes could not be read";
                    }
                }

                if (signature.lengthRule != LengthRule::ToNextCandidate) {
                    if (!structureOk) {
                        // Reported, not dropped. A file that is there but
                        // interleaved with other data is a finding: it is
                        // evidence that the medium still holds recoverable
                        // content, and its absence from the report would read
                        // as "nothing there".
                        recovered.structureValid = false;
                        recovered.reasons.push_back(
                            "the file's internal structure does not hold (" +
                            structureWhy +
                            "), so the bytes between the header and the trailer "
                            "are not this file's: it is fragmented or "
                            "interleaved, and the length is not a measurement");
                        report.notes.push_back(
                            std::string(signature.name) + " candidate at offset " +
                            std::to_string(absolute) +
                            " is not a whole file: " + structureWhy);
                        // The trailer does not end this file, so it must not be
                        // counted as a length measurement either.
                        footerFound = false;
                        length = 0;   // fall through to the inferred bound
                    }
                    if (length < signature.minSize && length != 0) {
                        report.notes.push_back(
                            "Rejected a " + std::string(signature.name) +
                            " candidate at offset " + std::to_string(absolute) +
                            ": derived length " + std::to_string(length) +
                            " is below the format minimum.");
                        continue;
                    }
                    if (length > signature.maxSize) {
                        report.notes.push_back(
                            "Rejected a " + std::string(signature.name) +
                            " candidate at offset " + std::to_string(absolute) +
                            ": derived length " + std::to_string(length) +
                            " exceeds the format ceiling of " +
                            std::to_string(signature.maxSize) + " bytes.");
                        continue;
                    }
                    if (absolute + length > total) {
                        recovered.truncated = true;
                        length = total - absolute;
                    }
                }

                // Classify the actual content rather than trusting the
                // signature alone.
                size_t head = 0;
                std::vector<uint8_t> headBuffer(std::min<size_t>(65536,
                                                                std::max<uint64_t>(length, 1)));
                if (source.readAt(absolute, headBuffer.data(),
                                  headBuffer.size())
                        .ok()) {
                    head = headBuffer.size();
                }
                const Classification classification =
                    classifyContent(headBuffer.data(), head);
                if (classification.agreesWithSignature) {
                    score += 0.15;
                    recovered.reasons.push_back(
                        "content classification (" + classification.label +
                        ") agrees with the signature");
                } else if (classification.label == "not enough bytes to classify") {
                    // No support either way, and no penalty: a candidate with an
                    // inferred length may be one sector long.
                    recovered.reasons.push_back(
                        "too few bytes to classify the content independently");
                } else {
                    recovered.reasons.push_back(
                        "content classification (" + classification.label +
                        ") does not add support");
                }

                if (lengthFromField) {
                    score += 0.15;
                    recovered.reasons.push_back(
                        "the length came from the format's own header field, "
                        "not from a search");
                    recovered.length = length;
                } else if (footerFound && signature.footerRequired) {
                    score += 0.20;
                    recovered.reasons.push_back(
                        "the format's trailer was found and the file ends there");
                    recovered.length = length;
                } else if (footerFound) {
                    score += 0.10;
                    recovered.reasons.push_back(
                        "the format's trailer was found");
                    recovered.length = length;
                } else {
                    score -= 0.15;
                    recovered.lengthInferred = true;
                    recovered.reasons.push_back(
                        "the format has no trailer, so the length is a bound "
                        "rather than a measurement");
                }

                if (recovered.truncated) {
                    score -= 0.20;
                    recovered.reasons.push_back(
                        "the candidate reached the end of the source, which "
                        "usually means the file was truncated");
                }

                recovered.score = std::max(0.0, std::min(1.0, score));
                if (recovered.score < options_.minimumScore) {
                    continue;
                }

                if (recovered.score >= 0.95) {
                    recovered.confidence = Confidence::HIGH;
                } else if (recovered.score >= 0.75) {
                    recovered.confidence = Confidence::MEDIUM;
                } else if (recovered.score >= 0.55) {
                    recovered.confidence = Confidence::LOW;
                } else {
                    recovered.confidence = Confidence::VERY_LOW;
                }
                if (recovered.confidence == Confidence::HIGH &&
                    recovered.lengthInferred) {
                    // An unterminated format cannot be confirmed by a length,
                    // so it never claims high confidence however well its
                    // header matched.
                    recovered.confidence = Confidence::MEDIUM;
                    recovered.reasons.push_back(
                        "confidence capped below high because the length is "
                        "inferred");
                }
                if (!recovered.structureValid) {
                    // The hard cap, and the one that matters.
                    //
                    // A candidate whose format has a structure walker and whose
                    // walk failed is not a file. Before this check the
                    // fragmented PNGs came back at HIGH with a plausible length
                    // and a digest that matched nothing, which is the most
                    // damaging way this tool can be wrong: it looks like a
                    // recovery. VERY_LOW is a ranking floor, and the reason
                    // string above says what actually happened.
                    recovered.confidence = Confidence::VERY_LOW;
                    recovered.score = std::min(recovered.score, 0.30);
                    recovered.reasons.push_back(
                        "confidence forced to the floor: the recovered bytes are "
                        "not a whole file of this format");
                }

                if (recovered.length == 0) {
                    recovered.lengthInferred = true;
                    // Filled in during the resolve pass below.
                }

                report.files.push_back(recovered);
                accepted.push_back(absolute);
                i += std::max<size_t>(
                    1, static_cast<size_t>(recovered.length == 0
                                                ? 1
                                                : recovered.length) -
                           1);
            }

            if (!matchedAny) {
                continue;
            }
        }
    }

    // Resolve the formats with no terminator now that every accepted offset is
    // known: each runs to the next candidate, or to its ceiling.
    for (RecoveredFile& file : report.files) {
        if (file.length != 0) {
            continue;
        }
        const FileSignature* signature = nullptr;
        for (const FileSignature& candidate : table) {
            if (file.signatureName == candidate.name) {
                signature = &candidate;
                break;
            }
        }
        if (signature == nullptr) {
            continue;
        }
        uint64_t next = total;
        for (const uint64_t offset : accepted) {
            if (offset > file.offset) {
                next = std::min(next, offset);
                break;
            }
        }
        uint64_t end = next;
        if (end - file.offset > signature->maxSize) {
            end = file.offset + signature->maxSize;
        }
        file.length = end - file.offset;
        if (file.offset + file.length >= total) {
            file.truncated = true;
        }
        if (file.length > options_.maxInferredLength) {
            // This is the single rule that stops a weak magic from producing
            // hundreds of megabytes of confident nonsense. It replaces an
            // earlier per-format "weak magic" filter, which had to be a list and
            // which still dropped a genuine 20 KiB gzip because its *inferred*
            // span was large.
            file.length = options_.maxInferredLength;
            file.truncated = true;
            file.reasons.push_back(
                "length capped at " +
                std::to_string(options_.maxInferredLength / (1024 * 1024)) +
                " MiB: the format has no terminator, so the length is a bound "
                "and not a measurement");
        }
    }

    // Apply the output budget now, once every length is known. It has to happen
    // here and not at accept time: a format with no terminator has length 0
    // until the resolve pass above, and a weak magic such as "MZ" resolves to
    // its ceiling - a quarter of a gigabyte for one false positive. A scan of a
    // 256 MiB medium reported 259 MB of recovered files before this check
    // existed.
    if (!report.files.empty()) {
        uint64_t budget = 0;
        std::vector<RecoveredFile> withinBudget;
        withinBudget.reserve(report.files.size());
        for (const RecoveredFile& file : report.files) {
            if (budget + file.length > options_.maxTotalOutputBytes) {
                report.notes.push_back(
                    "Dropped a candidate at offset " + std::to_string(file.offset) +
                    " (" + std::to_string(file.length) +
                    " bytes): including it would exceed the " +
                    std::to_string(options_.maxTotalOutputBytes) +
                    " byte output budget, already committed to " +
                    std::to_string(budget) + " bytes.");
                continue;
            }
            budget += file.length;
            withinBudget.push_back(file);
        }
        if (withinBudget.size() != report.files.size()) {
            report.notes.push_back(
                std::to_string(report.files.size() - withinBudget.size()) +
                " candidate(s) were dropped on the output budget. Raise "
                "CarveOptions::maxTotalOutputBytes to keep them.");
            report.files = std::move(withinBudget);
        }
    }

    // Hash each accepted candidate so a recovery can be compared against a
    // known original by content rather than by name. Hashed in blocks: a
    // recovered file can be hundreds of megabytes and is never held whole.
    std::vector<uint8_t> hashBlock(1u << 20);
    for (RecoveredFile& file : report.files) {
        if (file.length == 0) {
            continue;
        }
        Sha256Stream digest;
        uint64_t done = 0;
        bool failed = false;
        while (done < file.length) {
            const size_t want = static_cast<size_t>(
                std::min<uint64_t>(file.length - done, hashBlock.size()));
            const auto read =
                source.readAt(file.offset + done, hashBlock.data(), want);
            if (read.isError() || read.value() == 0) {
                failed = true;
                break;
            }
            digest.update(hashBlock.data(), read.value());
            done += read.value();
        }
        if (failed) {
            file.reasons.push_back(
                "the recovered content could not be read in full, so it was "
                "not hashed");
            continue;
        }
        const auto hex = digest.finalHex();
        if (hex.isError()) {
            file.reasons.push_back(std::string("hashing failed: ") + hex.error().what());
            continue;
        }
        file.sha256 = hex.value();
    }

    // Strongest first, so a reader sees the best-supported recovery at the top.
    std::sort(report.files.begin(), report.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.score != b.score) {
                      return a.score > b.score;
                  }
                  return a.offset < b.offset;
              });

    return Result<CarveReport>::ok(std::move(report));
}

// ---------------------------------------------------------------------------
// Source integrity and output containment
// ---------------------------------------------------------------------------

Result<std::string> sha256OfFile(const std::string& path) {
    // O_RDONLY, and never reopened for writing. The same rule the carver holds
    // the source to applies to the code that measures it.
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return Result<std::string>::err(
            ErrorCode::IO_ERROR,
            "Cannot open for reading: " + path + ": " + std::strerror(errno),
            "The digest is taken by reading the file. It is never opened for "
            "writing.");
    }

    Sha256Stream stream;
    std::vector<uint8_t> buffer(1u << 20);
    for (;;) {
        const ssize_t got = ::read(fd, buffer.data(), buffer.size());
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            ::close(fd);
            return Result<std::string>::err(
                ErrorCode::IO_ERROR,
                "Read failed while hashing " + path + ": " +
                    std::strerror(saved));
        }
        if (got == 0) {
            break;
        }
        stream.update(buffer.data(), static_cast<size_t>(got));
    }
    ::close(fd);
    return stream.finalHex();
}

namespace {

// True when `directory` is inside `mountPoint` on a path-component boundary.
// "/mnt/data" is inside "/mnt/data" and inside "/mnt", but not inside
// "/mnt/d".
bool isInsideDirectory(const std::string& directory, const std::string& mountPoint) {
    if (mountPoint == "/") {
        return true;
    }
    if (directory.size() < mountPoint.size()) {
        return false;
    }
    if (directory.compare(0, mountPoint.size(), mountPoint) != 0) {
        return false;
    }
    return directory.size() == mountPoint.size() ||
           directory[mountPoint.size()] == '/';
}

} // namespace

Result<void> requireOutputSeparateFromSource(const std::string& sourcePath,
                                              const std::string& outputDirectory) {
    if (outputDirectory.empty()) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "No output directory was given",
            "Callers must state where recovered files go before this check can "
            "say anything about it.");
    }

    struct stat sourceStat {};
    if (::stat(sourcePath.c_str(), &sourceStat) != 0) {
        return Result<void>::err(
            ErrorCode::IO_ERROR,
            "Cannot read the source's properties: " + sourcePath + ": " +
                std::strerror(errno));
    }

    struct stat outputStat {};
    if (::stat(outputDirectory.c_str(), &outputStat) != 0) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "The output directory does not exist: " + outputDirectory,
            "Create it first, or choose a different --output-dir. This check "
            "compares the device the output sits on with the device being "
            "recovered, so the directory has to exist to be compared.");
    }
    if (!S_ISDIR(outputStat.st_mode)) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "The output path is not a directory: " + outputDirectory);
    }

    // A file source: the filesystem it lives on, compared by st_dev. That is
    // exact - two different filesystems cannot share a st_dev, and one
    // filesystem has one st_dev however many directories it holds.
    if (!S_ISBLK(sourceStat.st_mode)) {
        if (sourceStat.st_dev == outputStat.st_dev) {
            return Result<void>::err(
                ErrorCode::INVALID_ARGUMENT,
                "Refusing to write recovered files into the source's own "
                "filesystem: " + outputDirectory,
                "Recovered files are written over the bytes being recovered, so "
                "the result would be wrong and the source would no longer be "
                "the evidence it was. Choose an --output-dir on a different "
                "filesystem, such as a removable disk.");
        }
        return Result<void>::success();
    }

    // A block device source. Its st_dev is the device node's own, which is not
    // the st_dev of any filesystem mounted on it, so the numbers cannot be
    // compared directly. What has to be established is whether the output
    // directory sits on a filesystem backed by this disk or by one of its
    // partitions - getMountPoints() matches the device and its partitions, so
    // a mount on /dev/sda2 is caught when the source is /dev/sda.
    const std::vector<std::string> mountPoints =
        platform::linux::getMountPoints(sourcePath);
    for (const std::string& mountPoint : mountPoints) {
        if (isInsideDirectory(outputDirectory, mountPoint)) {
            return Result<void>::err(
                ErrorCode::INVALID_ARGUMENT,
                "Refusing to write recovered files onto the device being "
                "recovered: " + outputDirectory + " is on " + mountPoint +
                    ", which is mounted from " + sourcePath,
                "Writing to the source would overwrite the bytes being "
                "recovered and destroy the evidence. Mount another filesystem, "
                "or point --output-dir somewhere else.");
        }
    }
    return Result<void>::success();
}

} // namespace ledgerase
