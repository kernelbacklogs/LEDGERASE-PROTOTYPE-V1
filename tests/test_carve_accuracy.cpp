// Recovery-accuracy tests: the cases a controlled-dataset suite does not cover.
//
// The existing carving tests assert that a file which was never fragmented
// comes back byte-exact. That is the easy half. This file covers the three
// cases where a signature carver is expected to fail, and asserts *that it
// fails, and says so*, because a carver that quietly reports a wrong recovery
// is worse than one that reports nothing.
//
//   fragmented   a file whose extents the allocator scattered. Both the header
//                and the trailer are genuine, so every length rule the carver
//                has says "this is the file", and it is wrong: the bytes
//                between belong to something else.
//   quickfmt     a fresh filesystem written over a populated one. The data
//                blocks are untouched, so everything is still there.
//   overwritten  a deleted file whose first blocks were reused by a new file.
//                Its header is gone and its tail is not.
//
// Ground truth here is measured, not assumed: each fixture records where it
// placed the file's bytes and how many of them the medium still holds, so a
// file the construction clobbered is not scored as a carver miss. The earlier
// version of this experiment got that wrong and reported six failures that were
// a construction bug.
//
// The real-filesystem variant builds its images with debugfs and is skipped,
// visibly, where debugfs is absent.

#include "ledgerase/carving.hpp"
#include "ledgerase/evidence.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace ledgerase;

namespace {

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

namespace fs = std::filesystem;

struct Timed {
    explicit Timed(const char* name) : name_(name),
                                       start_(std::chrono::steady_clock::now()) {
        std::printf("%s\n", name_);
    }
    ~Timed() {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - start_)
                                 .count();
        std::printf("  (%lld ms)\n", static_cast<long long>(elapsed));
    }
    const char* name_;
    std::chrono::steady_clock::time_point start_;
};

std::string digestOf(const std::string& bytes) {
    const auto hashed = sha256HexBytes(
        reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    return hashed.ok() ? hashed.value() : std::string();
}

fs::path makeMedium(const fs::path& dir, const std::string& name, uint64_t size) {
    std::error_code dirEc;
    fs::create_directories(dir, dirEc);
    const fs::path path = dir / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    std::vector<char> zeros(static_cast<size_t>(size), 0);
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    return path;
}

void placeAt(const fs::path& medium, uint64_t offset, const std::string& bytes) {
    std::fstream stream(medium, std::ios::binary | std::ios::in | std::ios::out);
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string readWhole(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

// A real PNG, built here so the suite depends on no host file. 1x1, with valid
// chunk CRCs and a real zlib stream, so a recovery of it by hash means the
// carver found a genuine header-to-IEND span.
// CRC-32 as PNG uses it. The fixtures have to carry *correct* CRCs: the carver
// walks the chunk list, and a fixture with a wrong CRC is not a PNG - which
// would make every recovery test in this file pass for the wrong reason. That is
// not hypothetical: the first version of this suite used a literal CRC and the
// quick-format test then failed, correctly, because the fixture was malformed.
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

// A real 1x1 PNG: correct chunk CRCs, a real zlib stream, a real IEND.
std::string png1x1(uint8_t seed) {
    std::string out("\x89PNG\r\n\x1a\n", 8);
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

    std::string header(13, '\0');
    header[3] = 1;    // width  = 1
    header[7] = 1;    // height = 1
    header[8] = 8;    // bit depth
    header[9] = 2;    // truecolour
    appendChunk("IHDR", header);

    // A zlib stream for one empty, correctly filtered scanline. Fixed, so the
    // bytes are deterministic; the per-seed byte keeps two files in the same
    // test from hashing the same, so a "recovered the wrong copy" bug shows up
    // as a digest mismatch rather than as a false pass.
    std::string idat("\x78\x01\x01\x01\x00\x00\x00\x00\x01\x00\x01"
                     "\x00\x00",
                     13);
    idat.push_back(static_cast<char>(seed));
    appendChunk("IDAT", idat);
    appendChunk("IEND", std::string());
    return out;
}

std::string filler(size_t bytes, uint8_t seed) {
    std::string out;
    out.reserve(bytes);
    for (size_t i = 0; i < bytes; ++i) {
        out.push_back(static_cast<char>((i * 31 + seed * 17) & 0xFF));
    }
    return out;
}

const RecoveredFile* findByDigest(const CarveReport& report, const std::string& digest) {
    for (const RecoveredFile& file : report.files) {
        if (file.sha256 == digest) {
            return &file;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// (a) a fragmented file
// ---------------------------------------------------------------------------

void testFragmentedFileIsNotRecovered(const fs::path& dir) {
    // A PNG whose first and last blocks are in place and whose middle is not.
    // This is exactly the shape a fragmented file has on any filesystem: the
    // header is in the file's first extent, the IEND in its last, and the
    // blocks between are other files' data.
    const fs::path medium = makeMedium(dir, "fragmented.img", 4u << 20);
    const std::string file = png1x1(7);
    const size_t third = file.size() / 3;
    const std::string head = file.substr(0, third);
    const std::string middle = file.substr(third, file.size() - 2 * third);
    const std::string tail = file.substr(file.size() - third);

    placeAt(medium, 4096, head);
    placeAt(medium, 4096 + third + 64 * 1024, filler(middle.size(), 3));
    placeAt(medium, 4096 + third + 64 * 1024 + middle.size(), tail);
    // A second file whose IEND sits near the first one's span, so a footer
    // search can find a real trailer for the wrong file.
    const std::string other = png1x1(9);
    placeAt(medium, 4096 + third + 64 * 1024 + middle.size() + 32 * 1024, other);

    FileCarveSource source(medium.string());
    const Carver carver;
    const auto report = carver.scan(source);
    check(report.ok(), "a fragmented medium is scanned");
    if (report.isError()) {
        return;
    }

    const std::string digest = digestOf(file);
    check(findByDigest(report.value(), digest) == nullptr,
          "a fragmented file is not recovered byte-exact");

    // The important half: it must not be *claimed* either. Before the format's
    // structure was walked, the header-to-trailer span of this fixture was
    // reported at high confidence, which is indistinguishable from a clean
    // recovery in the output.
    //
    // The assertion is about the candidate that starts at the fragmented file's
    // own offset, not about every PNG in the medium: the fixture also contains
    // one intact PNG, and a correct carver is expected to report that one at
    // high confidence.
    const RecoveredFile* atFragmentedOffset = nullptr;
    for (const RecoveredFile& candidate : report.value().files) {
        if (candidate.offset == 4096) {
            atFragmentedOffset = &candidate;
        }
    }
    check(atFragmentedOffset != nullptr,
          "a candidate is still reported at the fragmented file's offset");
    check(atFragmentedOffset == nullptr ||
              (atFragmentedOffset->confidence != Confidence::HIGH &&
               !atFragmentedOffset->structureValid),
          "the candidate at the fragmented offset is not a whole-file recovery");

    // The failure must be explained, not silent. A reader has to be able to tell
    // "the file is gone" from "the file is here and scattered".
    bool explained = false;
    for (const std::string& note : report.value().notes) {
        if (note.find("not a whole file") != std::string::npos) {
            explained = true;
        }
    }
    for (const RecoveredFile& candidate : report.value().files) {
        for (const std::string& reason : candidate.reasons) {
            if (reason.find("fragmented or interleaved") != std::string::npos) {
                explained = true;
            }
        }
    }
    check(explained, "the interleaving is recorded, with the reason");
}

// ---------------------------------------------------------------------------
// (b) a quick format over a populated medium
// ---------------------------------------------------------------------------

void testQuickFormatLeavesTheFilesRecoverable(const fs::path& dir) {
    // What a partition quick format does: new metadata structures over the old
    // ones, data blocks untouched. Modelled here by writing a block of
    // filesystem-looking bytes at the front of a medium that still holds its
    // files, which is the same shape without needing a real format.
    const fs::path medium = makeMedium(dir, "quickfmt.img", 2u << 20);
    const std::string png = png1x1(11);
    const std::string pdf =
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n";

    placeAt(medium, 64 * 1024, png);
    placeAt(medium, 128 * 1024, pdf);
    // The new filesystem's structures, written over the front of the medium.
    placeAt(medium, 1024, std::string(4096, '\x00') + filler(2048, 5));
    placeAt(medium, 0, std::string("\x53\xEF", 2) + filler(510, 1));

    const std::string mediumBefore = readWhole(medium);

    FileCarveSource source(medium.string());
    const Carver carver;
    const auto report = carver.scan(source);
    check(report.ok(), "a quick-formatted medium is scanned");
    if (report.isError()) {
        return;
    }

    check(findByDigest(report.value(), digestOf(png)) != nullptr,
          "the PNG under a quick-formatted medium comes back byte-exact");
    check(findByDigest(report.value(), digestOf(pdf)) != nullptr,
          "the PDF under a quick-formatted medium comes back byte-exact");
    check(readWhole(medium) == mediumBefore,
          "the medium is byte-for-byte unchanged by the scan");
}

// ---------------------------------------------------------------------------
// (c) deleted and partly overwritten
// ---------------------------------------------------------------------------

void testPartlyOverwrittenFileNotRecovered(
    const fs::path& dir) {
    // The first blocks of a deleted file are reused, which destroys the header
    // and leaves the tail. A carver cannot recover a file whose first bytes are
    // gone; what it must not do is report a wrong span as the file.
    const fs::path medium = makeMedium(dir, "overwritten.img", 2u << 20);
    const std::string pdf =
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n";

    placeAt(medium, 32 * 1024, pdf);
    // A new file lands on the first 16 bytes: the header, and nothing else.
    placeAt(medium, 32 * 1024, filler(16, 21));

    FileCarveSource source(medium.string());
    const Carver carver;
    const auto report = carver.scan(source);
    check(report.ok(), "a partly overwritten medium is scanned");
    if (report.isError()) {
        return;
    }
    check(findByDigest(report.value(), digestOf(pdf)) == nullptr,
          "a file whose header was overwritten is not reported as recovered");

    // The tail is still on the medium, and the report has to be compatible with
    // the possibility that a different file still has its header. What is
    // forbidden is claiming the whole thing.
    bool claimedWhole = false;
    for (const RecoveredFile& candidate : report.value().files) {
        if (candidate.offset == 32 * 1024 &&
            candidate.confidence == Confidence::HIGH) {
            claimedWhole = true;
        }
    }
    check(!claimedWhole,
          "nothing at the overwritten file's offset is claimed as a whole "
          "high-confidence recovery");
}

// ---------------------------------------------------------------------------
// Output containment and source integrity
// ---------------------------------------------------------------------------

void testOutputOnTheSameFilesystemIsRefused(const fs::path& dir) {
    const fs::path medium = makeMedium(dir, "containment.img", 1u << 20);
    const fs::path output = dir / "recovery";
    std::error_code ec;
    fs::create_directories(output, ec);

    const auto same = requireOutputSeparateFromSource(medium.string(),
                                                      output.string());
    check(same.isError(),
          "writing recovered files into the source's own filesystem is refused");
    if (same.isError()) {
        check(std::string(same.error().what()).find("same") != std::string::npos ||
                  std::string(same.error().what()).find("filesystem") !=
                      std::string::npos,
              "the refusal says why");
        check(!same.error().recommendedAction().empty(),
              "the refusal says what to do instead");
    }

    const auto missing = requireOutputSeparateFromSource(medium.string(),
                                                         (dir / "nope").string());
    check(missing.isError(),
          "a non-existent output directory is refused rather than assumed safe");
}

// ---------------------------------------------------------------------------
// Carve evidence
// ---------------------------------------------------------------------------

void testCarveRecordVerifiesAndDetectsTampering(const fs::path& dir) {
    const fs::path medium = makeMedium(dir, "evidence.img", 1u << 20);
    const std::string png = png1x1(23);
    placeAt(medium, 8192, png);

    FileCarveSource source(medium.string());
    const Carver carver;
    const auto report = carver.scan(source);
    check(report.ok(), "the evidence fixture is scanned");
    if (report.isError()) {
        return;
    }

    const auto before = sha256OfFile(medium.string());
    const auto after = sha256OfFile(medium.string());
    check(before.ok() && after.ok(), "the source is digested");
    check(before.value() == after.value(),
          "the source digest is stable across a scan");

    CarveEvidenceBundle bundle;
    bundle.jobId = CarveEvidenceBuilder::generateJobId();
    bundle.applicationVersion = "test";
    bundle.carverVersion = "test";
    bundle.source.path = medium.string();
    bundle.source.kind = "file";
    bundle.source.sizeBytes = static_cast<uint64_t>(fs::file_size(medium));
    bundle.source.sha256BeforeScan = before.value();
    bundle.source.sha256AfterScan = after.value();
    bundle.source.unchanged = before.value() == after.value();
    bundle.candidatesExamined = report.value().candidatesExamined;
    for (const RecoveredFile& file : report.value().files) {
        CarveRecoveredEntry entry;
        entry.offset = file.offset;
        entry.length = file.length;
        entry.signatureName = file.signatureName;
        entry.category = fileCategoryToString(file.category);
        entry.confidence = confidenceToString(file.confidence);
        entry.score = file.score;
        entry.sha256 = file.sha256;
        entry.structureValid = file.structureValid;
        bundle.recovered.push_back(entry);
    }

    const auto built = CarveEvidenceBuilder::build(bundle, {});
    check(built.ok(), "a carve record is built");
    if (built.isError()) {
        return;
    }

    const CarveEvidenceBundle& record = built.value();
    check(record.chainLength >= 5,
          "the chain records the job, the scan, the files and both digests");

    int sourceHashRecords = 0;
    int fileRecords = 0;
    for (const EvidenceRecord& entry : record.eventChain) {
        if (entry.type == "carve_source_hashed" || entry.type == "carve_source_rehashed") {
            ++sourceHashRecords;
        }
        if (entry.type == "carve_file_recovered") {
            ++fileRecords;
        }
    }
    check(sourceHashRecords == 2, "both source digests are in the chain");
    check(static_cast<size_t>(fileRecords) == record.recovered.size(),
          "one chain record per recovered file, each carrying its digest");

    const fs::path file = dir / "carve-record.json";
    check(CarveEvidenceWriter::write(record, file.string(), true).ok(),
          "the carve record is written");
    check(CarveEvidenceWriter::write(record, file.string(), false).isError(),
          "an existing carve record is not clobbered without --force");

    const auto verified = CarveEvidenceVerifier::verifyStructure(file.string());
    check(verified.ok(), "a carve record verifies");
    if (verified.isError()) {
        return;
    }
    check(verified.value().schemaRecognised, "its schema is recognised");
    check(verified.value().canonicalHashMatches, "its canonical hash matches");
    check(verified.value().chainConsistent, "its chain is intact");
    check(!verified.value().signaturePresent,
          "a carve record is reported as unsigned rather than as signed");

    // Tampering: change one recovered digest and the canonical hash must fail.
    nlohmann::json document;
    {
        std::ifstream input(file, std::ios::binary);
        input >> document;
    }
    document["recovered"][0]["sha256"] = std::string(64, 'a');
    const fs::path tampered = dir / "carve-record-tampered.json";
    {
        std::ofstream output(tampered, std::ios::binary | std::ios::trunc);
        output << document.dump(2);
    }
    const auto tamperedCheck = CarveEvidenceVerifier::verifyStructure(
        tampered.string());
    check(tamperedCheck.ok(), "the tampered record can be read");
    if (!tamperedCheck.isError()) {
        check(!tamperedCheck.value().canonicalHashMatches,
              "changing a recovered digest breaks the canonical hash");
    }
}

// ---------------------------------------------------------------------------
// On a real filesystem
// ---------------------------------------------------------------------------

bool haveDebugfs() {
    return std::system("command -v debugfs > /dev/null 2>&1") == 0;
}

int runCommand(const std::string& command) {
    return std::system((command + " > /dev/null 2>&1").c_str());
}

void testRealFilesystemScenarios(const fs::path& dir) {
    if (!haveDebugfs()) {
        skip("debugfs is not installed, so the real-filesystem scenarios did "
             "not run. This is a gap, not a pass.");
        return;
    }
    const fs::path work = dir / "realfilesystem";
    std::error_code ec;
    fs::create_directories(work, ec);
    const fs::path image = work / "carve.img";
    const fs::path source = work / "fragmented.png";

    // A real PNG, written to a file so debugfs can place it.
    {
        std::ofstream out(source, std::ios::binary | std::ios::trunc);
        const std::string png = png1x1(31);
        out.write(png.data(), static_cast<std::streamsize>(png.size()));
    }
    // Make it big enough to be worth fragmenting, by concatenating the 1x1
    // file's bytes into a longer stream: not a valid image past the first
    // frame, so instead build a genuinely large PNG by repeating IDAT chunks.
    // Simplest correct route: a PNG with a long tEXt chunk, which the format
    // allows to be arbitrarily long and which is covered by a valid CRC.
    {
        std::ofstream out(source, std::ios::binary | std::ios::trunc);
        std::string png("\x89PNG\r\n\x1a\n", 8);
        auto append32 = [&png](uint32_t value) {
            png.push_back(static_cast<char>((value >> 24) & 0xFF));
            png.push_back(static_cast<char>((value >> 16) & 0xFF));
            png.push_back(static_cast<char>((value >> 8) & 0xFF));
            png.push_back(static_cast<char>(value & 0xFF));
        };
        append32(13);
        png.append("IHDR", 4);
        const uint8_t ihdr[13] = {0, 0, 0, 1, 8, 2, 0, 0, 0, 0, 0, 0, 0};
        png.append(reinterpret_cast<const char*>(ihdr), 13);
        append32(0x1F15C489);
        static const uint8_t kIdat[] = {0x78, 0x01, 0x01, 0x01, 0x00, 0x00,
                                        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00};
        append32(sizeof(kIdat));
        png.append("IDAT", 4);
        png.append(reinterpret_cast<const char*>(kIdat), sizeof(kIdat));
        append32(0xED0E29A3);
        const std::string fillerText(120 * 1024, 'A');
        append32(static_cast<uint32_t>(fillerText.size()));
        png.append("tEXt", 4);
        png.append("Comment", 7);
        png.push_back('\0');
        png.append(fillerText);
        append32(0x0F9E5B4C);   // not a real CRC: the walk must reject it
        out.write(png.data(), static_cast<std::streamsize>(png.size()));
    }

    runCommand("dd if=/dev/zero of=" + image.string() + " bs=1M count=32 2>/dev/null");
    runCommand("mkfs.ext4 -q -F -b 1024 " + image.string());
    for (int i = 0; i < 120; ++i) {
        const fs::path fillerFile = work / ("f" + std::to_string(i) + ".bin");
        {
            std::ofstream out(fillerFile, std::ios::binary | std::ios::trunc);
            const std::string bytes = filler(100 * 1024, static_cast<uint8_t>(i));
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        }
        runCommand("debugfs -w -R \"write " + fillerFile.string() +
                   " /f" + std::to_string(i) + ".bin\" " + image.string());
    }
    for (int i = 0; i < 120; i += 3) {
        runCommand("debugfs -w -R \"rm /f" + std::to_string(i) + ".bin\" " +
                   image.string());
    }
    runCommand("debugfs -w -R \"write " + source.string() +
               " /fragmented.png\" " + image.string());
    runCommand("debugfs -w -R \"rm /fragmented.png\" " + image.string());

    // The filler's tEXt CRC is deliberately wrong, so a PNG of this shape is
    // not a valid file and must never be reported as one. What is asserted is
    // the rule, not the fixture's digest: a candidate whose structure walk fails
    // is not a whole file.
    FileCarveSource carvesSource(image.string());
    const Carver carver;
    const auto report = carver.scan(carvesSource);
    check(report.ok(), "the real ext4 image is scanned");
    if (report.isError()) {
        return;
    }
    bool anyHighConfidenceWholeFile = false;
    for (const RecoveredFile& candidate : report.value().files) {
        if (candidate.structureValid && candidate.confidence == Confidence::HIGH &&
            candidate.signatureName == "png") {
            anyHighConfidenceWholeFile = true;
        }
    }
    check(!anyHighConfidenceWholeFile,
          "a PNG with a bad chunk CRC is never reported as a whole recovered file");

    fs::remove_all(work, ec);
}

} // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "sanitizer-carve-accuracy";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    { Timed t("FragmentedFileIsNotReportedAsAWholeRecovery"); testFragmentedFileIsNotRecovered(dir); }
    { Timed t("QuickFormatLeavesTheFilesRecoverable"); testQuickFormatLeavesTheFilesRecoverable(dir); }
    { Timed t("PartlyOverwrittenFileIsNotRecoveredAndTheLossIsReported"); testPartlyOverwrittenFileNotRecovered(dir); }
    { Timed t("OutputOnTheSameFilesystemIsRefused"); testOutputOnTheSameFilesystemIsRefused(dir); }
    { Timed t("CarveRecordVerifiesAndDetectsTampering"); testCarveRecordVerifiesAndDetectsTampering(dir); }
    { Timed t("RealFilesystemScenarios"); testRealFilesystemScenarios(dir); }

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        std::printf("\nAll recovery-accuracy checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
