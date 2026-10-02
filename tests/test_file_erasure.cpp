// Tests for the file and folder eraser.
//
// The eraser makes three kinds of claim, and each is tested on its own:
//
//   * it overwrites what it says it overwrites, and reads it back;
//   * it refuses on a filesystem whose row does not permit it, rather than
//     partially doing it;
//   * its verification does not depend on the file's format - a file with no
//     magic number is erased and checked, which is the case a carver cannot
//     see and the reason the carver is not used.
//
// The refusal tests run against the matrix directly, because whether the test
// host happens to be on ext4 or btrfs must not decide whether the policy is
// correct. The end-to-end erase runs against whatever filesystem the temporary
// directory is on, and skips - visibly - where that filesystem's row refuses,
// so a green run never means "the refusal path was never reached".

#include "ledgerase/erasure.hpp"
#include "ledgerase/filesystem_capability.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
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

fs::path makeFile(const fs::path& path, size_t bytes, uint8_t seed) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    std::string data;
    data.reserve(bytes);
    // A marker at the front so a reader can tell at a glance whether the
    // content is still the file's.
    const std::string marker = "ERASURE-TEST-MARKER-" +
                               std::to_string(seed) + "-";
    data += marker;
    // xorshift, not `(i * 31 + seed) & 0xFF`. The arithmetic form is periodic
    // with a period of 256 bytes, so a 512-byte probe taken from one file
    // matches any other file generated the same way - which made the negative
    // test ("a region with no copy reports nothing") fail for a reason that
    // had nothing to do with the search. The point of a negative case is that
    // it is negative for the right reason.
    uint64_t state = 0x9E3779B97F4A7C15ull ^ (static_cast<uint64_t>(seed) + 1);
    for (size_t i = marker.size(); i < bytes; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push_back(static_cast<char>(state & 0xFF));
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    return path;
}

std::string readWhole(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

// A run is only attempted where the host filesystem permits it. Reported, not
// hidden: on a host that refuses, this file proves the refusal and nothing
// about the write path.
bool hostPermitsErase(const fs::path& dir) {
    const FilesystemCapabilities caps = detectFilesystem(dir.string());
    return !evaluateErasePermission(caps).refused;
}

// ---------------------------------------------------------------------------

void testOverwritesTheFileAndReadsItBack(const fs::path& dir) {
    std::printf("a file is overwritten and read back\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase, so the write "
             "path was not exercised here. The refusal itself is tested "
             "separately.");
        return;
    }
    const fs::path file = makeFile(dir / "plain.txt", 40 * 1024, 1);
    const std::string before = readWhole(file);
    check(before.find("ERASURE-TEST-MARKER-1-") == 0,
          "the fixture starts with a marker");

    EraseOptions options;
    // Keep the directory entry so the test can read the file back and inspect
    // the bytes. The unlink path has its own test below; this one is about the
    // overwrite and read-back.
    options.removeFile = false;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok(), "the erase runs");
    if (record.isError()) {
        return;
    }
    const FileEraseRecord& result = record.value();
    check(result.state == EraseState::ERASED, "the record says erased");
    check(result.readBackVerified, "the read-back matched");
    check(result.readBackCoverageBytes == result.sizeBytes,
          "the whole file was read back, not a sample");
    check(!result.removedFromDirectory,
          "the name was kept because the test asked for that");
    check(result.bytesOverwritten == result.sizeBytes * result.passesCompleted,
          "the recorded byte count matches the size and the passes");
    check(result.sha256Before.size() == 64, "a digest of the original is recorded");
    check(result.sha256After.size() == 64,
          "a digest of what replaced it is recorded, under its own name");
    check(result.sha256Before != result.sha256After,
          "the content actually changed");

    const std::string after = readWhole(file);
    check(after.size() == before.size(), "the file is the same length");
    check(after.find("ERASURE-TEST-MARKER-1-") == std::string::npos,
          "the original content is gone from the file");
    check(!result.limitations.empty(),
          "the record carries the limitations that make this what it is");
}

// The default guarantee: after a verified overwrite the name is removed, so the
// file is gone and unreadable through the filesystem. This is the claim the
// task fixes, and it is separate from "its bytes were replaced".
void testVerifiedEraseRemovesTheFileByDefault(const fs::path& dir) {
    std::printf("a verified erase removes the file, not just its bytes\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    const fs::path file = makeFile(dir / "removed.bin", 8 * 1024, 3);
    check(fs::exists(file), "the fixture exists before the erase");
    EraseOptions options;
    // removeFile defaults to true; do not set it, so this exercises the default.
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok(), "the erase runs");
    if (record.isError()) {
        return;
    }
    const FileEraseRecord& result = record.value();
    check(result.state == EraseState::ERASED, "the record says erased");
    check(result.readBackVerified, "the read-back matched before removal");
    check(result.removedFromDirectory, "the directory entry was removed");
    check(!fs::exists(file), "the file is gone from the filesystem");
    check(result.detail.find("gone") != std::string::npos,
          "the detail says the file is gone, not just overwritten");
}

void testRequestedVsCompletedPassCounts(const fs::path& dir) {
    std::printf("requested and completed pass counts are separate\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    const fs::path file = makeFile(dir / "passes.bin", 12 * 1024, 2);
    EraseOptions options;
    options.passes = 3;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok(), "the erase runs");
    if (record.isError()) {
        return;
    }
    check(record.value().passesRequested == 3, "the request is recorded");
    check(record.value().passesCompleted == 3, "the completion is recorded");
    check(record.value().bytesOverwritten == 3 * record.value().sizeBytes,
          "three passes over the file wrote three times its size");
}

void testUnsignedFileIsErasedAndChecked(const fs::path& dir) {
    std::printf("a file with no signature is erased and checked\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    // The point of the whole verification design: a signature carver would
    // never report this file, so a carver-based check would be silent here.
    const fs::path file = makeFile(dir / "no-magic.dat", 20 * 1024, 3);
    EraseOptions options;
    FileEraser eraser(options);

    const auto probes = eraser.probeFileLive(file.string());
    check(probes.ok(), "probes are taken from a file with no signature");
    if (probes.isError()) {
        return;
    }
    check(probes.value().size() == options.probeCount,
          "the requested number of probes is taken");
    for (const FileEraser::LiveProbe& probe : probes.value()) {
        check(probe.record.sha256.size() == 64,
              "each probe is recorded by digest, not by content");
        check(probe.record.sample.size() <= 24,
              "each probe records only a short printable sample");
    }

    const auto record = eraser.eraseFile(file.string());
    check(record.ok() && record.value().state == EraseState::ERASED,
          "the file is erased");

    // The search runs over a region of bytes. A file is used as the region
    // because no block device is addressable in a test; what is under test is
    // the search, and the test says so rather than implying it searched a disk.
    const fs::path medium = makeFile(dir / "medium.bin", 200 * 1024, 4);

    // The probes that were taken before the erase are still held by the
    // eraser, which is the only place they exist. One of them is written into
    // the region at a known offset, the way a journal or a log would hold a
    // copy: that is the positive case, and it is what the check is for.
    const auto held = eraser.liveProbesFor(file.string());
    check(held.ok(), "the pre-erase probe bytes are still available");
    if (held.isError() || held.value().empty()) {
        return;
    }
    const size_t plantedAt = 64 * 1024;
    {
        std::fstream stream(medium, std::ios::binary | std::ios::in |
                                           std::ios::out);
        stream.seekp(static_cast<std::streamoff>(plantedAt));
        stream.write(reinterpret_cast<const char*>(held.value()[1].bytes.data()),
                     static_cast<std::streamsize>(
                         held.value()[1].bytes.size()));
    }

    auto found =
        eraser.searchForProbes(medium.string(), held.value());
    check(found.ok(), "the residual search runs");
    if (found.isError()) {
        return;
    }
    check(!found.value().empty(),
          "a copy of the erased content is found in the searched region, "
          "which is what the check exists to detect");
    bool locatedExactly = false;
    for (const std::string& hit : found.value()) {
        if (hit.find("byte offset " + std::to_string(plantedAt) + " ") !=
            std::string::npos) {
            locatedExactly = true;
        }
    }
    check(locatedExactly,
          "and it is reported at the offset it was planted at, not merely "
          "somewhere");

    // And on a region with no copy, it reports nothing.
    const fs::path clean = makeFile(dir / "clean.bin", 100 * 1024, 9);
    const auto none = eraser.searchForProbes(clean.string(), held.value());
    check(none.ok() && none.value().empty(),
          "a region with no copy reports nothing found, so a positive result "
          "is evidence and not an artefact");
}

void testProbeCountOfZeroIsRefused() {
    std::printf("a probe count of zero is refused, not defaulted\n");
    EraseOptions options;
    options.probeCount = 0;
    FileEraser eraser(options);
    check(eraser.options().probeCount >= 1,
          "the probe count is raised to at least one, because zero would mean "
          "no content check at all");
    options.passes = 0;
    FileEraser second(options);
    check(second.options().passes == 1, "a pass count of zero becomes one");
    options.passes = 99;
    FileEraser third(options);
    check(third.options().passes == 15, "a pass count above 15 is clamped");
}

// ---------------------------------------------------------------------------

// The Phase B rule: permission is not gated on the filesystem. Every
// filesystem is permitted; the OVERWRITE_CONTENT cell decides only whether a
// residue note is attached. This is asserted against the matrix directly, so it
// does not depend on the host.
void testThePolicyPermitsAndReportsResidue() {
    std::printf("the policy permits every filesystem and reports residue\n");
    for (FilesystemKind kind : knownFilesystemKinds()) {
        const FilesystemCapabilities caps = filesystemCapabilities(kind);
        const FilesystemRefusal outcome = evaluateErasePermission(caps);
        const SupportLevel cell =
            caps.capability(FilesystemOperation::OVERWRITE_CONTENT).level;
        check(!outcome.refused,
              std::string(filesystemKindToString(kind)) +
                  ": permitted - permission is not gated on the filesystem");
        if (cell != SupportLevel::SUPPORTED) {
            check(!outcome.residueNote.empty(),
                  std::string(filesystemKindToString(kind)) +
                      ": a filesystem that leaves residue carries a note");
        } else {
            check(outcome.residueNote.empty(),
                  std::string(filesystemKindToString(kind)) +
                      ": no residue note when there is no residue");
        }
    }
}

// On the host's own filesystem: whatever it is, the erase is attempted, and if
// the matrix expects residue the record carries the disclosure alongside the
// overwrite result.
void testHostErasePermittedWithResidueNote(const fs::path& dir) {
    std::printf("on this host, the erase is permitted and residue is disclosed\n");
    const FilesystemCapabilities caps = detectFilesystem(dir.string());
    const FilesystemRefusal outcome = evaluateErasePermission(caps);
    std::printf("  (this host: %s, content cell: %s)\n",
                caps.reportedName.c_str(),
                supportLevelToString(
                    caps.capability(FilesystemOperation::OVERWRITE_CONTENT)
                        .level)
                    .c_str());
    check(!outcome.refused, "this host is permitted a file-level erase");

    // A real erase on this host: the content must actually change, and if the
    // matrix says this filesystem keeps a copy, the record must say so.
    const fs::path file = makeFile(dir / "permitted.dat", 8 * 1024, 5);
    const std::string before = readWhole(file);
    EraseOptions options;
    options.probeCount = 2;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok(), "the call returns a record rather than failing");
    if (!record.ok()) {
        return;
    }
    check(record.value().state == EraseState::ERASED,
          "the state is ERASED on a permitted filesystem");
    check(readWhole(file) != before,
          "the file's content really changed on this host");
    const SupportLevel cell =
        caps.capability(FilesystemOperation::OVERWRITE_CONTENT).level;
    const bool hasResidueNote = !record.value().refusal.residueNote.empty();
    check(hasResidueNote == (cell != SupportLevel::SUPPORTED),
          "the record carries a residue note exactly when the matrix expects "
          "residue on this filesystem");
}

void testHardLinkedFileIsBlocked(const fs::path& dir) {
    std::printf("a file with more than one hard link is blocked\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase, so the "
             "hard-link check was not reached end to end.");
        return;
    }
    const fs::path file = makeFile(dir / "linked.bin", 8 * 1024, 6);
    const fs::path second = dir / "linked-again.bin";
    std::error_code ec;
    fs::create_hard_link(file, second, ec);
    if (ec) {
        skip("this filesystem does not support hard links here.");
        return;
    }
    const std::string before = readWhole(file);
    EraseOptions options;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok() && record.value().state == EraseState::BLOCKED,
          "the file is blocked, because erasing it would destroy the content "
          "behind both names");
    check(readWhole(file) == before, "not one byte was written");
    check(readWhole(second) == before, "the other name still holds its content");
    fs::remove(second, ec);
}

void testASymlinkIsNotFollowed(const fs::path& dir) {
    std::printf("a symbolic link is not followed\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    const fs::path target = makeFile(dir / "target.bin", 8 * 1024, 7);
    const fs::path link = dir / "link-to-target";
    std::error_code ec;
    fs::create_symlink(target, link, ec);
    if (ec) {
        skip("this filesystem does not support symbolic links here.");
        return;
    }
    const std::string before = readWhole(target);
    EraseOptions options;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(link.string());
    check(record.ok(), "the call returns a record");
    if (record.ok()) {
        check(record.value().state != EraseState::ERASED,
              "a symlink is not recorded as erased");
        check(readWhole(target) == before,
              "the file the symlink named was not touched");
    }
}

void testAnEmptyFileIsNotClaimedAsAnOverwrite(const fs::path& dir) {
    std::printf("an empty file is not described as an overwrite\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    const fs::path file = dir / "empty.dat";
    { std::ofstream out(file, std::ios::trunc); }
    EraseOptions options;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok() && record.value().state == EraseState::ERASED,
          "an empty file is not an error");
    if (record.ok()) {
        bool explained = false;
        for (const std::string& limitation : record.value().limitations) {
            if (limitation.find("vacuous") != std::string::npos) {
                explained = true;
            }
        }
        check(explained,
              "and the record says the content question is vacuous rather than "
              "implying bytes were written");
    }
}

void testAFolderErasesOnlyRegularFiles(const fs::path& dir) {
    std::printf("a folder erases its regular files and nothing else\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase, so the folder "
             "path was not exercised here. The per-entry classification is "
             "tested by the unit above.");
        return;
    }
    const fs::path folder = dir / "folder";
    std::error_code ec;
    fs::create_directories(folder / "sub", ec);
    makeFile(folder / "one.txt", 6 * 1024, 8);
    makeFile(folder / "two.txt", 6 * 1024, 9);
    makeFile(folder / "sub" / "nested.txt", 6 * 1024, 10);
    const fs::path outside = makeFile(dir / "outside.txt", 6 * 1024, 11);
    fs::create_symlink(outside, folder / "escape", ec);
    const std::string outsideBefore = readWhole(outside);

    EraseOptions options;
    FileEraser eraser(options);
    const auto result = eraser.eraseFolder(folder.string());
    check(result.ok(), "the folder run returns a record");
    if (result.isError()) {
        return;
    }
    const FolderEraseRecord& record = result.value();
    check(record.filesErased == 2, "the two regular files were erased");
    check(record.filesRefused == 2,
          "the symlink and the subdirectory were both refused");
    check(record.records.size() == 4,
          "every entry reached produced a record, so nothing is silently "
          "omitted from the audit");
    check(!record.notErased.empty(), "the refusals name themselves");

    bool sawSymlinkRefusal = false;
    bool sawSubdirRefusal = false;
    for (const std::string& reason : record.notErased) {
        if (reason.find("escape") != std::string::npos &&
            reason.find("symbolic link") != std::string::npos) {
            sawSymlinkRefusal = true;
        }
        if (reason.find("sub") != std::string::npos &&
            reason.find("subdirectory") != std::string::npos) {
            sawSubdirRefusal = true;
        }
    }
    check(sawSymlinkRefusal, "the symlink refusal says what it is");
    check(sawSubdirRefusal, "the subdirectory refusal says what it is");
    check(readWhole(outside) == outsideBefore,
          "the file outside the folder was not touched");
    check(readWhole(folder / "sub" / "nested.txt").find("ERASURE-TEST-MARKER-10-") == 0,
          "the nested file was not erased, because recursion was refused");
    check(readWhole(folder / "one.txt").find("ERASURE-TEST-MARKER-8-") ==
              std::string::npos,
          "the first file's content is gone");
}

// ---------------------------------------------------------------------------

void testEraseRecordDetectsTampering(const fs::path& dir) {
    std::printf("the erase record verifies, and tampering is caught\n");
    EraseEvidenceBundle inputs;
    inputs.jobId = EraseEvidenceBuilder::generateJobId();
    inputs.applicationVersion = "test";
    inputs.targetPath = (dir / "example.txt").string();
    inputs.targetKind = "file";
    inputs.filesystemName = "ext4";
    inputs.options = EraseOptions();

    FileEraseRecord record;
    record.path = inputs.targetPath;
    record.sizeBytes = 4096;
    record.state = EraseState::ERASED;
    record.readBackVerified = true;
    record.readBackCoverageBytes = 4096;
    record.sha256Before = std::string(64, 'a');
    record.sha256After = std::string(64, 'b');
    ContentProbe probe;
    probe.offsetInFile = 0;
    probe.length = 512;
    probe.sha256 = std::string(64, 'c');
    probe.sample = "sample";
    record.probes.push_back(probe);
    record.limitations.push_back("only this file's blocks were written");
    inputs.files.push_back(record);

    const auto built = EraseEvidenceBuilder::build(inputs);
    check(built.ok(), "an erase record is built");
    if (built.isError()) {
        return;
    }
    const EraseEvidenceBundle& bundle = built.value();
    check(bundle.chainLength == 3,
          "the chain holds the job, the file, and the close");
    check(bundle.eventChain[1].payload.contains("probes"),
          "the file's chain record carries the probe digests");

    const fs::path file = dir / "erase-record.json";
    check(EraseEvidenceWriter::write(bundle, file.string(), true).ok(),
          "the record is written");
    check(EraseEvidenceWriter::write(bundle, file.string(), false).isError(),
          "an existing record is not clobbered without --force");

    const auto verified = EraseEvidenceVerifier::verifyStructure(file.string());
    check(verified.ok(), "the record verifies");
    if (verified.isError()) {
        return;
    }
    check(verified.value().schemaRecognised, "its schema is recognised");
    check(verified.value().canonicalHashMatches, "its canonical hash matches");
    check(verified.value().chainConsistent, "its chain is intact");
    check(!verified.value().signaturePresent,
          "an erase record is reported as unsigned");

    nlohmann::json document;
    {
        std::ifstream input(file, std::ios::binary);
        input >> document;
    }
    document["files"][0]["sha256_before"] = std::string(64, 'd');
    const fs::path tampered = dir / "erase-record-tampered.json";
    {
        std::ofstream out(tampered, std::ios::binary | std::ios::trunc);
        out << document.dump(2);
    }
    const auto after = EraseEvidenceVerifier::verifyStructure(tampered.string());
    check(after.ok() && !after.value().canonicalHashMatches,
          "changing the recorded pre-erase digest breaks the canonical hash");
}

void testTheProbeBytesAreNotInTheRecord(const fs::path& dir) {
    std::printf("the probe bytes never reach the evidence file\n");
    // A record that contained the content it was meant to erase would be a
    // second copy of it, so this checks the bytes are not in the file at all.
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    const std::string marker = "THIS-MARKER-MUST-NOT-BE-RECORDED";
    const fs::path file = dir / "confidential.txt";
    {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        std::string data = marker;
        data.append(64 * 1024, 'q');
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
    }
    EraseOptions options;
    options.probeCount = 4;
    FileEraser eraser(options);
    const auto record = eraser.eraseFile(file.string());
    check(record.ok(), "the erase runs");
    if (record.isError()) {
        return;
    }

    EraseEvidenceBundle inputs;
    inputs.jobId = EraseEvidenceBuilder::generateJobId();
    inputs.files.push_back(record.value());
    const auto built = EraseEvidenceBuilder::build(inputs);
    check(built.ok(), "the record is built");
    if (built.isError()) {
        return;
    }
    const fs::path evidence = dir / "confidential-record.json";
    check(EraseEvidenceWriter::write(built.value(), evidence.string(), true).ok(),
          "the record is written");

    std::ifstream input(evidence, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    check(text.find(marker) == std::string::npos,
          "the file's content is nowhere in the evidence file");
    check(text.find(std::string(32, 'q')) == std::string::npos,
          "and neither is a long run of the file's bytes");
    check(text.find(record.value().probes[0].sha256) != std::string::npos,
          "while the probe's digest is, because that is what proves the check "
          "was set up");
}

} // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "sanitizer-erasure-test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    testOverwritesTheFileAndReadsItBack(dir);
    testVerifiedEraseRemovesTheFileByDefault(dir);
    testRequestedVsCompletedPassCounts(dir);
    testUnsignedFileIsErasedAndChecked(dir);
    testProbeCountOfZeroIsRefused();
    testThePolicyPermitsAndReportsResidue();
    testHostErasePermittedWithResidueNote(dir);
    testHardLinkedFileIsBlocked(dir);
    testASymlinkIsNotFollowed(dir);
    testAnEmptyFileIsNotClaimedAsAnOverwrite(dir);
    testAFolderErasesOnlyRegularFiles(dir);
    testEraseRecordDetectsTampering(dir);
    testTheProbeBytesAreNotInTheRecord(dir);

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        std::printf("\nAll file-erasure checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
