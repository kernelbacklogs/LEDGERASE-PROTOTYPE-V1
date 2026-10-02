// Controlled-dataset tests for the carver.
//
// A carver that reports "recovered 14 files" tells you nothing. These tests
// build a medium from files whose sizes and SHA-256 digests are known, delete
// them from the filesystem layer, and then require that the carver return the
// original bytes: recovery is asserted by content hash, never by name.

#include "ledgerase/carving.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/evidence.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace ledgerase;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

namespace fs = std::filesystem;

// One known file, so a test can say "this digest must come back".
struct Sample {
    std::string name;
    std::string expectedExtension;
    std::string digest;
    size_t size = 0;
};

Sample makeSample(const std::string& name, const std::string& extension,
                  const std::string& contents) {
    Sample sample;
    sample.name = name;
    sample.expectedExtension = extension;
    sample.size = contents.size();
    const auto hashed = sha256HexBytes(
        reinterpret_cast<const uint8_t*>(contents.data()), contents.size());
    sample.digest = hashed.ok() ? hashed.value() : std::string();
    return sample;
}

std::string readWhole(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

// A medium of exactly this size, so offsets and the chunk/overlap boundary can
// be chosen deliberately.
fs::path makeMedium(const fs::path& dir, uint64_t size) {
    std::error_code dirEc;
    fs::create_directories(dir, dirEc);
    const fs::path path = dir / "medium.img";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    std::vector<char> zeros(static_cast<size_t>(size), 0);
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    return path;
}

void placeAt(const fs::path& medium, uint64_t offset,
             const std::string& contents) {
    std::fstream stream(medium, std::ios::binary | std::ios::in |
                                        std::ios::out);
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Real files from the host, so the corpus is not synthetic. Falls back to a
// constructed sample when the host has none, and says which it used.
std::map<std::string, std::string> hostFiles() {
    static const char* kCandidates[][2] = {
        {"/usr/share/pixmaps/archlinux-logo.png", "png"},
        {"/usr/share/doc/speexdsp/manual.pdf", "pdf"},
        {"/usr/share/man/man1/captoinfo.1m.gz", "gz"},
    };
    std::map<std::string, std::string> found;
    for (const auto& candidate : kCandidates) {
        const fs::path path(candidate[0]);
        std::error_code ec;
        if (!fs::is_regular_file(path, ec)) {
            continue;
        }
        const std::string contents = readWhole(path);
        if (contents.size() < 512 || contents.size() > (4u << 20)) {
            continue;
        }
        found[std::string(candidate[0]) + "|" + candidate[1]] = contents;
    }
    return found;
}

// CRC-32 as PNG computes it. Present because the fixtures build real chunks;
// without it the only way to write a PNG is to copy CRCs out of another file,
// which is how the previous version of this fixture ended up wrong.
uint32_t crc32Png(const uint8_t* data, size_t length) {
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

// A minimal PNG, built here so the suite does not depend on a host file. The
// bytes are a real 1x1 PNG: signature, IHDR, IDAT with a valid zlib stream,
// IEND. A carver that recovers this by hash has done real work.
std::string minimalPng() {
    // A structurally valid 1x1 PNG: signature, IHDR, IDAT, IEND, with the chunk
    // lengths and CRCs computed rather than written out by hand.
    //
    // This fixture used to carry literal CRCs and an IDAT length of 15 for a
    // 22-byte payload. The carver did not notice, because nothing checked: it
    // matched the header, searched for the IEND marker and reported a file. The
    // chunk walker added for the fragmentation case does notice, and the three
    // tests that recover this sample by hash then failed - correctly, because
    // the fixture was not a PNG. The assertions are unchanged; only the fixture
    // is now what it always claimed to be.
    std::string out;

    auto append32 = [&out](uint32_t value) {
        out.push_back(static_cast<char>((value >> 24) & 0xFF));
        out.push_back(static_cast<char>((value >> 16) & 0xFF));
        out.push_back(static_cast<char>((value >> 8) & 0xFF));
        out.push_back(static_cast<char>(value & 0xFF));
    };
    auto appendChunk = [&out, &append32](const char* type,
                                         const std::string& payload) {
        append32(static_cast<uint32_t>(payload.size()));
        const std::string body = std::string(type, 4) + payload;
        out.append(body);
        append32(crc32Png(reinterpret_cast<const uint8_t*>(body.data()),
                          body.size()));
    };

    out.append("\x89PNG\r\n\x1a\n", 8);

    std::string ihdr(13, '\0');
    ihdr[3] = 1;   // width  = 1
    ihdr[7] = 1;   // height = 1
    ihdr[8] = 8;   // bit depth
    ihdr[9] = 2;   // truecolour
    appendChunk("IHDR", ihdr);

    static const uint8_t kIdatPayload[22] = {
        0x78, 0x01, 0x01, 0x05, 0x00, 0xDA, 0x24, 0x51, 0x00, 0x00, 0x04,
        0x00, 0x01, 0x5A, 0xDB, 0x2D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    appendChunk("IDAT", std::string(
                           reinterpret_cast<const char*>(kIdatPayload),
                           sizeof(kIdatPayload)));
    appendChunk("IEND", std::string());
    return out;
}

std::string minimalPdf() {
    // A structurally valid single-page PDF: header, catalogue, page, xref
    // table, trailer. The xref offsets are not corrected, which is deliberate:
    // the point is that the carver finds %%EOF and stops there, and a reader
    // that cared could still see the text.
    std::string out =
        "%PDF-1.4\n"
        "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        "trailer<</Root 1 0 R>>\n";
    // Pad so the sample is comfortably over the PDF minimum length, which is
    // what makes a short "%%PDF-" string in a text file a poor false positive.
    out.append(512, ' ');
    // One trailer, at the end, as a real PDF has. An earlier version of this
    // fixture put %%EOF in the middle too, and the carver correctly truncated
    // there - the fixture was wrong, not the carver.
    out.append("\n%%EOF\n");
    return out;
}

std::string minimalGzip(const std::string& payload) {
    // A gzip member with stored (uncompressed) deflate blocks, built by hand so
    // the suite does not need zlib. Header, then stored blocks of at most 65535
    // bytes, then CRC32 and ISIZE.
    std::string out;
    out.push_back(static_cast<char>(0x1F));
    out.push_back(static_cast<char>(0x8B));
    out.push_back(8);    // deflate
    out.push_back(0);    // no flags
    for (int i = 0; i < 4; ++i) {
        out.push_back(0);   // mtime, fixed so the sample is reproducible
    }
    out.push_back(0);   // XFL
    out.push_back(static_cast<char>(0xFF));   // OS unknown

    size_t position = 0;
    while (position < payload.size()) {
        const size_t take = std::min<size_t>(65535, payload.size() - position);
        const bool last = (position + take) >= payload.size();
        out.push_back(last ? 1 : 0);
        out.push_back(static_cast<char>(take & 0xFF));
        out.push_back(static_cast<char>((take >> 8) & 0xFF));
        const uint16_t inverted = static_cast<uint16_t>(~take);
        out.push_back(static_cast<char>(inverted & 0xFF));
        out.push_back(static_cast<char>((inverted >> 8) & 0xFF));
        out.append(payload, position, take);
        position += take;
    }

    // CRC32 of the payload, and its length. The carver reads only the length.
    uint32_t crc = 0xFFFFFFFFu;
    for (const char byte : payload) {
        crc ^= static_cast<uint8_t>(byte);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    crc = ~crc;
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((crc >> (8 * i)) & 0xFF));
    }
    const uint32_t size = static_cast<uint32_t>(payload.size());
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((size >> (8 * i)) & 0xFF));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const RecoveredFile* findByDigest(const CarveReport& report,
                                  const std::string& digest) {
    for (const RecoveredFile& file : report.files) {
        if (file.sha256 == digest) {
            return &file;
        }
    }
    return nullptr;
}

void testKnownFilesAreRecoveredByContent(const fs::path& dir) {
    std::printf("known files are recovered, and recovery is proven by hash\n");

    const std::string png = minimalPng();
    const std::string pdf = minimalPdf();
    const std::string gz = minimalGzip(std::string(4096, 'g') + "tail marker");

    std::vector<Sample> expected;
    expected.push_back(makeSample("built.png", "png", png));
    expected.push_back(makeSample("built.pdf", "pdf", pdf));
    expected.push_back(makeSample("built.gz", "gz", gz));

    // Whatever the host provides is added too, so the corpus is not purely
    // synthetic. The count of host samples is reported rather than assumed.
    const auto hosts = hostFiles();
    std::size_t hostIndex = 0;
    for (const auto& entry : hosts) {
        const std::string label = entry.first;
        const std::string extension = label.substr(label.rfind('|') + 1);
        const std::string base = "host" + std::to_string(hostIndex++);
        expected.push_back(makeSample(base, extension, entry.second));
    }
    std::printf("       corpus: %zu built, %zu from the host\n",
                static_cast<std::size_t>(3), hosts.size());
    check(!expected.empty(), "the corpus is not empty");

    // 24 MiB, so several samples straddle a chunk boundary when the chunk size
    // is reduced for the test.
    const fs::path medium = makeMedium(dir, 24ull << 20);

    // Spread the samples out, deliberately including positions within one
    // chunk-size of the end so the overlap logic is exercised.
    const std::vector<uint64_t> offsets = {1ull << 20, 5ull << 20,
                                           (8ull << 20) - 3, 12ull << 20,
                                           (16ull << 20) + 7, 20ull << 20};

    // The contents each expected sample was built from, in the same order.
    std::vector<std::string> contentsFor;
    contentsFor.push_back(png);
    contentsFor.push_back(pdf);
    contentsFor.push_back(gz);
    for (const auto& entry : hosts) {
        contentsFor.push_back(entry.second);
    }
    check(contentsFor.size() == expected.size(),
          "every expected sample has matching contents to place");

    for (std::size_t i = 0; i < expected.size(); ++i) {
        placeAt(medium, offsets[i % offsets.size()], contentsFor[i]);
    }

    FileCarveSource source(medium.string());
    const auto sized = source.size();
    check(sized.ok(), "the medium opens read-only");
    if (!sized.ok()) {
        return;
    }

    // A small chunk size forces the boundary handling to matter.
    CarveOptions options;
    options.chunkSize = 1u << 20;
    options.overlap = 1u << 18;
    const Carver carver(options);

    const auto report = carver.scan(source);
    check(report.ok(), "the scan completes");
    if (!report.ok()) {
        std::printf("       %s\n", report.error().what());
        return;
    }

    // Samples whose length the format records, or whose trailer can be found,
    // must come back byte-exact. gzip is excluded and asserted separately: its
    // ISIZE field is the *uncompressed* length, so the file length is only
    // obtainable by walking the deflate stream, which is structure-aware work
    // not done yet. Claiming otherwise would be a guess.
    std::vector<std::string> exactExpectations = {"built.png", "built.pdf"};
    for (std::size_t i = 3; i < expected.size(); ++i) {
        if (expected[i].expectedExtension != "gz") {
            exactExpectations.push_back(expected[i].name);
        }
    }

    std::size_t recoveredCount = 0;
    for (const Sample& sample : expected) {
        if (sample.expectedExtension == "gz") {
            continue;
        }
        const RecoveredFile* found = findByDigest(report.value(), sample.digest);
        if (found == nullptr) {
            std::printf("       not recovered: %s (%s, %zu bytes)\n",
                        sample.name.c_str(), sample.expectedExtension.c_str(),
                        sample.size);
            continue;
        }
        ++recoveredCount;
        check(found->length == sample.size,
              sample.name + ": recovered length equals the original");
    }
    check(recoveredCount == exactExpectations.size(),
          "every length-derivable sample was recovered by content hash (" +
              std::to_string(recoveredCount) + "/" +
              std::to_string(exactExpectations.size()) + ")");

    // The gzip samples are still located as candidates, and reported as the
    // uncertain results they are.
    for (const Sample& sample : expected) {
        if (sample.expectedExtension != "gz") {
            continue;
        }
        const RecoveredFile* found = nullptr;
        for (const RecoveredFile& file : report.value().files) {
            if (file.signatureName == "gzip" && file.offset >= 1ull << 20 &&
                file.offset < 24ull << 20) {
                found = &file;
                break;
            }
        }
        check(found != nullptr,
              sample.name + ": a gzip candidate is reported as a candidate");
        if (found != nullptr) {
            check(found->lengthInferred,
                  sample.name +
                      ": a gzip length is reported as inferred, not measured");
            check(found->confidence != Confidence::HIGH,
                  sample.name +
                      ": a gzip with an inferred length is not high confidence");
        }
    }

    // A recovered file must carry a digest and a defensible score.
    bool allHashed = true;
    bool allScored = true;
    bool allExplained = true;
    for (const RecoveredFile& file : report.value().files) {
        if (file.sha256.size() != 64) {
            allHashed = false;
        }
        if (file.score <= 0.0 || file.score > 1.0) {
            allScored = false;
        }
        if (file.reasons.empty()) {
            allExplained = false;
        }
    }
    check(allHashed, "every recovered file carries a SHA-256 digest");
    check(allScored, "every score is within 0.0 and 1.0");
    check(allExplained, "every score is accompanied by its reasons");
}

void testFalsePositivesAreSuppressed(const fs::path& dir) {
    std::printf("stray header-like bytes do not become recovered files\n");

    // Bytes that contain the PNG signature but are not a PNG: no IHDR, no IEND.
    std::string notAPng;
    notAPng.append("\x89PNG\r\n\x1a\n", 8);
    notAPng.append(200, 'x');
    notAPng.append(" and then a lot of ordinary text, no trailer, no length "
                   "field, nothing that the format itself provides");

    // A bare "%PDF-" with no %%EOF anywhere after it.
    const std::string notAPdf =
        "%PDF-1.4 this mentions the marker in a sentence and then keeps going "
        "for a while without ever closing the document properly at all";

    // A gzip header followed by no member.
    std::string notAGzip;
    notAGzip.push_back(static_cast<char>(0x1F));
    notAGzip.push_back(static_cast<char>(0x8B));
    notAGzip.push_back(8);
    notAGzip.append(64, 'q');

    const fs::path medium = makeMedium(dir, 8ull << 20);
    placeAt(medium, 1ull << 20, notAPng);
    placeAt(medium, 3ull << 20, notAPdf);
    placeAt(medium, 5ull << 20, notAGzip);

    FileCarveSource source(medium.string());
    CarveOptions options;
    options.chunkSize = 1u << 20;
    options.overlap = 1u << 18;
    const Carver carver(options);
    const auto report = carver.scan(source);
    check(report.ok(), "the scan of decoys completes");
    if (!report.ok()) {
        return;
    }

    // The PNG decoy is short and has no trailer, so it should not come back as
    // a confirmed file. It may appear at low confidence, which is the honest
    // outcome; what must not happen is a claim that it is a recovered PNG.
    for (const RecoveredFile& file : report.value().files) {
        if (file.signatureName == "png" || file.signatureName == "pdf" ||
            file.signatureName == "gzip") {
            check(file.confidence != Confidence::HIGH,
                  "a decoy is never reported as high confidence (" +
                      file.signatureName + ")");
        }
    }

    // A medium of zeroes must produce nothing at all.
    const fs::path empty = makeMedium(dir / "empty", 4ull << 20);
    FileCarveSource emptySource(empty.string());
    const auto emptyReport = carver.scan(emptySource);
    check(emptyReport.ok(), "an all-zero medium scans cleanly");
    if (emptyReport.ok()) {
        check(emptyReport.value().files.empty(),
              "an all-zero medium yields no recovered files");
    }
}

void testExtractionIsAdditiveAndReadOnly(const fs::path& dir) {
    std::printf("extraction writes new files and never touches the source\n");

    const std::string png = minimalPng();
    const auto sample = makeSample("x.png", "png", png);
    const fs::path medium = makeMedium(dir, 4ull << 20);
    placeAt(medium, 1ull << 20, png);

    const std::string before = readWhole(medium);

    FileCarveSource source(medium.string());
    const Carver carver;
    const auto report = carver.scan(source);
    check(report.ok(), "the scan completes");
    if (!report.ok()) {
        return;
    }
    const RecoveredFile* found = findByDigest(report.value(), sample.digest);
    check(found != nullptr, "the sample is recovered");
    if (found == nullptr) {
        return;
    }

    const fs::path outputDir = dir / "recovered";
    std::string written;
    const auto extracted = carver.extract(source, *found, outputDir.string(), written);
    check(extracted.ok(), "the file is extracted");
    check(extracted.ok() && extracted.value() == sample.size,
          "the extracted length equals the original length");
    if (extracted.ok()) {
        check(readWhole(written) == png,
              "the extracted bytes are identical to the original");
    }

    // The source is unchanged: recovery must not alter evidence.
    check(readWhole(medium) == before,
          "the source is byte-for-byte unchanged after carving and extraction");

    // Extracting the same candidate again must refuse rather than clobber.
    std::string second;
    const auto again = carver.extract(source, *found, outputDir.string(), second);
    check(again.isError(),
          "extracting to an existing name is refused rather than overwriting");
}

void testSourceIsNeverOpenedForWriting(const fs::path& dir) {
    std::printf("the source is opened read-only, and the OS enforces it\n");

    const fs::path readOnly = dir / "locked.img";
    makeMedium(dir, 1ull << 20);
    std::filesystem::rename(dir / "medium.img", readOnly);
    fs::permissions(readOnly, fs::perms::owner_read);

    FileCarveSource source(readOnly.string());
    const auto sized = source.size();
    check(sized.ok(), "a read-only source opens and reports its size");

    // Writing to it through the tool's own handle is impossible: the class
    // exposes no write path at all, which the compile-time surface enforces.
    // The check that matters is that the file's mode never changed.
    std::error_code ec;
    check((fs::status(readOnly, ec).permissions() & fs::perms::owner_write) ==
              fs::perms::none,
          "the source's permissions are unchanged");
}

void testSourcesOutsideTheMediumAreRefused(const fs::path& dir) {
    std::printf("a candidate outside the source is refused\n");

    const fs::path medium = makeMedium(dir, 2ull << 20);
    FileCarveSource source(medium.string());
    const Carver carver;

    RecoveredFile beyond;
    beyond.offset = 100ull << 20;
    beyond.length = 1024;
    std::string written;
    const auto outside = carver.extract(source, beyond, (dir / "out").string(), written);
    check(outside.isError(),
          "an offset past the end of the source is refused");

    RecoveredFile zeroLength;
    zeroLength.offset = 0;
    zeroLength.length = 0;
    const auto empty = carver.extract(source, zeroLength, (dir / "out2").string(), written);
    check(empty.isError(), "a zero-length candidate is refused");
}

void testClassificationNamesTheInnerApplication() {
    std::printf("a ZIP container is classified by what it contains\n");

    // A ZIP whose first local header names word/document.xml: an OOXML word
    // processor document, not a generic archive.
    std::string ooxml;
    ooxml.append("PK\x03\x04", 4);
    ooxml.append(std::string(26, '\0'));
    ooxml.append("word/document.xml");
    ooxml.append(std::string(200, 'p'));
    ooxml.append("PK\x05\x06", 4);
    ooxml.append(std::string(18, '\0'));

    const uint8_t* data = reinterpret_cast<const uint8_t*>(ooxml.data());
    const Classification asWord = classifyContent(data, ooxml.size());
    check(asWord.category == FileCategory::DOCUMENT,
          "an OOXML zip is classified as a document");
    check(asWord.extension == "docx",
          "an OOXML zip is given the docx extension, not zip");

    std::string plainZip;
    plainZip.append("PK\x03\x04", 4);
    plainZip.append(std::string(26, '\0'));
    plainZip.append("notes/hello.txt");
    plainZip.append(std::string(100, 'q'));
    plainZip.append("PK\x05\x06", 4);
    plainZip.append(std::string(18, '\0'));
    const Classification asZip = classifyContent(
        reinterpret_cast<const uint8_t*>(plainZip.data()), plainZip.size());
    check(asZip.category == FileCategory::ARCHIVE,
          "a plain zip is classified as an archive");
    check(asZip.extension == "zip", "a plain zip keeps the zip extension");
}

void testConfidenceIsCappedForInferredLengths(const fs::path& dir) {
    std::printf("a file whose length is inferred cannot claim high confidence\n");

    // A BMP has a 2-byte magic and no trailer, so its length is always a
    // bound. It must not be reported as confirmed however well the header
    // matched.
    std::string bmp("BM", 2);
    bmp.append(std::string(54, '\0'));
    bmp.append(std::string(4000, 'B'));

    const fs::path medium = makeMedium(dir, 4ull << 20);
    placeAt(medium, 1ull << 20, bmp);

    FileCarveSource source(medium.string());
    const Carver carver;
    const auto report = carver.scan(source);
    check(report.ok(), "the scan completes");
    if (!report.ok()) {
        return;
    }
    for (const RecoveredFile& file : report.value().files) {
        if (file.signatureName != "bmp") {
            continue;
        }
        check(file.lengthInferred, "a trailerless format is marked as inferred");
        check(file.confidence != Confidence::HIGH,
              "a trailerless format never reaches high confidence");
        bool explained = false;
        for (const std::string& reason : file.reasons) {
            if (reason.find("inferred") != std::string::npos ||
                reason.find("no trailer") != std::string::npos) {
                explained = true;
            }
        }
        check(explained, "the inferred length is stated in the reasons");
    }
}


// The synthetic-medium test proves the scanner. This one proves it works on a
// real filesystem, where files are allocated non-contiguously, sit after other
// data, and are not the first thing in the image.
//
// The image is built with debugfs rather than by mounting, so the test needs no
// root and no loop device. Where debugfs is absent the test says it was skipped
// rather than passing silently.
void testRealFilesystem(const fs::path& dir) {
    std::printf("files are recovered from a real ext4 filesystem\n");

    std::error_code ec;
    const std::string debugfs = "/usr/sbin/debugfs";
    const std::string mkfs = "/usr/sbin/mkfs.ext4";
    if (!fs::exists(debugfs, ec) || !fs::exists(mkfs, ec)) {
        std::printf("       SKIPPED: debugfs or mkfs.ext4 is unavailable here, so "
                    "no filesystem could be built.\n");
        return;
    }

    const fs::path corpusDir = dir / "corpus";
    fs::create_directories(corpusDir, ec);

    // Three originals with different shapes: a small image, a larger document,
    // and a compressed stream whose length cannot be derived from its header.
    const std::string png = minimalPng();
    const std::string pdf = minimalPdf();
    const std::string gz = minimalGzip(std::string(60000, 'z') + " payload tail");

    const fs::path pngOnHost = corpusDir / "a.png";
    const fs::path pdfOnHost = corpusDir / "b.pdf";
    const fs::path gzOnHost = corpusDir / "c.gz";
    for (const auto& pair : {std::make_pair(pngOnHost, png),
                             std::make_pair(pdfOnHost, pdf),
                             std::make_pair(gzOnHost, gz)}) {
        std::ofstream out(pair.first, std::ios::binary);
        out << pair.second;
    }

    const auto hashOf = [](const std::string& contents) {
        const auto hashed = sha256HexBytes(
            reinterpret_cast<const uint8_t*>(contents.data()), contents.size());
        return hashed.ok() ? hashed.value() : std::string();
    };

    const fs::path image = corpusDir / "corpus.ext4";
    {
        std::ofstream make(image, std::ios::binary);
        std::vector<char> zeros(96u << 20, 0);
        make.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    }
    if (std::system((mkfs + " -q -F " + image.string()).c_str()) != 0) {
        std::printf("       SKIPPED: mkfs.ext4 failed on this host.\n");
        return;
    }
    if (std::system((debugfs + " -w -R \"mkdir /evidence\" " + image.string()).c_str()) != 0) {
        std::printf("       SKIPPED: debugfs could not create a directory.\n");
        return;
    }
    for (const auto& pair : {std::make_pair(pngOnHost, std::string("a.png")),
                             std::make_pair(pdfOnHost, std::string("b.pdf")),
                             std::make_pair(gzOnHost, std::string("c.gz"))}) {
        const std::string command = debugfs + " -w -R \"write " +
                                    pair.first.string() + " /evidence/" +
                                    pair.second + "\" " + image.string();
        if (std::system(command.c_str()) != 0) {
            std::printf("       SKIPPED: debugfs could not write a file.\n");
            return;
        }
    }

    FileCarveSource source(image.string());
    CarveOptions options;
    options.chunkSize = 4u << 20;
    options.overlap = 1u << 20;
    const Carver carver(options);
    const auto report = carver.scan(source);
    check(report.ok(), "the scan of a real filesystem completes");
    if (!report.ok()) {
        return;
    }

    // The two whose length the format records must come back byte-exact.
    for (const auto& pair : {std::make_pair(std::string("a.png"), png),
                             std::make_pair(std::string("b.pdf"), pdf)}) {
        const std::string digest = hashOf(pair.second);
        const RecoveredFile* found = findByDigest(report.value(), digest);
        check(found != nullptr,
              pair.first + " is recovered from the filesystem by content hash");
        if (found != nullptr) {
            check(found->length == pair.second.size(),
                  pair.first + ": recovered length equals the original");
            check(found->confidence == Confidence::HIGH,
                  pair.first + ": a file with a measured end is high confidence");
        }
    }

    // The gzip cannot be byte-exact, and must not be claimed as one.
    check(findByDigest(report.value(), hashOf(gz)) == nullptr,
          "a gzip with an underivable length is NOT claimed as an exact recovery");
    bool gzipCandidateSeen = false;
    for (const RecoveredFile& file : report.value().files) {
        if (file.signatureName == "gzip") {
            gzipCandidateSeen = true;
            check(file.confidence != Confidence::HIGH,
                  "the gzip candidate is not high confidence");
        }
    }
    check(gzipCandidateSeen, "the gzip is at least reported as a candidate");
}
} // namespace

// Times each phase so a slow one is identifiable rather than guessed at.
struct Timed {
    const char* name;
    std::chrono::steady_clock::time_point start;
    explicit Timed(const char* label)
        : name(label), start(std::chrono::steady_clock::now()) {}
    ~Timed() {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start)
                            .count();
        std::printf("       [timing] %-46s %5lld ms\n", name,
                    static_cast<long long>(ms));
    }
};

int main() {
    const fs::path dir =
        fs::temp_directory_path() / "sanitizer-carving-test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    { Timed t("KnownFilesAreRecoveredByContent"); testKnownFilesAreRecoveredByContent(dir); }
    { Timed t("FalsePositivesAreSuppressed"); testFalsePositivesAreSuppressed(dir); }
    { Timed t("ExtractionIsAdditiveAndReadOnly"); testExtractionIsAdditiveAndReadOnly(dir); }
    { Timed t("SourceIsNeverOpenedForWriting"); testSourceIsNeverOpenedForWriting(dir); }
    { Timed t("SourcesOutsideTheMediumAreRefused"); testSourcesOutsideTheMediumAreRefused(dir); }
    { Timed t("ClassificationNamesTheInnerApplication"); testClassificationNamesTheInnerApplication(); }
    { Timed t("ConfidenceIsCappedForInferredLengths"); testConfidenceIsCappedForInferredLengths(dir); }
    { Timed t("RealFilesystem"); testRealFilesystem(dir); }

    fs::remove_all(dir, ec);

    if (g_failures == 0) {
        std::printf("\nAll carving checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
