// evidence migrate: moving the bundles that were written before audit/ and
// reports/ were separated.
//
// The rule the command exists to keep is that a record is moved and never
// re-written. A bundle is bytes on disk and a third party verifies those
// bytes, so a move that re-serialised the document would produce a different
// record even when nothing had changed. The move is checked before and after:
// the hash and the chain have to verify in the old place and in the new one.
//
// The cases here are the ones that decide whether the command is safe to
// point at a directory of records: a dry run that changes nothing, a run that
// moves, a second run that does nothing again, a destination that is already
// occupied, and a bundle that does not verify.

#include "test_support.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

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

std::string readWhole(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void writeWhole(const fs::path& path, const std::string& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << bytes;
}

// A flat bundle, written where the command would find one: directly in the
// evidence directory, with a job-id name.
bool makeFlatBundle(const fs::path& directory, const std::string& name) {
    const fs::path target = directory / "medium.img";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        const std::vector<char> zeros(64 * 1024, 0);
        out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    }
    const std::string output = runCli({"sanitize", target.string(), "--assurance",
                                       "clear", "--force", "--no-progress",
                                       "--evidence", (directory / name).string()});
    return fs::exists(directory / name) && contains(output, "Evidence bundle written");
}

void testDryRunChangesNothing(const fs::path& dir) {
    std::printf("a dry run reports what it would do and changes nothing\n");
    const fs::path evidence = dir / "dry-run";
    fs::create_directories(evidence);
    if (!makeFlatBundle(evidence, "20260101T000000Z-0001.json")) {
        skip("the sanitize run did not produce a bundle here.");
        return;
    }
    const std::string before = readWhole(evidence / "20260101T000000Z-0001.json");

    const std::string output = runCli({"evidence", "migrate", evidence.string()});
    check(contains(output, "would move"),
          "the dry run says what it would move");
    check(fs::exists(evidence / "20260101T000000Z-0001.json"),
          "the bundle is still where it was");
    check(!fs::exists(evidence / "audit"),
          "and the audit/ directory was not created");
    check(readWhole(evidence / "20260101T000000Z-0001.json") == before,
          "the bundle's bytes are untouched");
}

void testApplyMovesTheFileUnchanged(const fs::path& dir) {
    std::printf("applying the move keeps the bytes and the hash\n");
    const fs::path evidence = dir / "apply";
    fs::create_directories(evidence);
    if (!makeFlatBundle(evidence, "20260101T000001Z-0002.json")) {
        skip("the sanitize run did not produce a bundle here.");
        return;
    }
    const fs::path source = evidence / "20260101T000001Z-0002.json";
    const std::string before = readWhole(source);
    check(!before.empty(), "the bundle was written");

    const std::string output =
        runCli({"evidence", "migrate", evidence.string(), "--apply"});
    check(contains(output, "moved"), "the move is reported");
    check(!fs::exists(source), "the flat bundle is no longer in the directory");
    const fs::path destination = evidence / "audit" / "20260101T000001Z-0002.json";
    check(fs::exists(destination), "the bundle is in audit/");
    if (!fs::exists(destination)) {
        return;
    }
    check(readWhole(destination) == before,
          "the bytes are identical: the file was moved, not re-written");

    const std::string verified = runCli({"verify-log", destination.string()});
    check(contains(verified, "Content unaltered:   yes"),
          "the bundle still verifies against its own hash where it now is");
    check(contains(verified, "Event chain:         intact"),
          "and its chain is still intact");
}

void testSecondRunDoesNothing(const fs::path& dir) {
    std::printf("a second run finds nothing left to do\n");
    const fs::path evidence = dir / "second-run";
    fs::create_directories(evidence);
    if (!makeFlatBundle(evidence, "20260101T000002Z-0003.json")) {
        skip("the sanitize run did not produce a bundle here.");
        return;
    }
    runCli({"evidence", "migrate", evidence.string(), "--apply"});
    const fs::path destination = evidence / "audit" / "20260101T000002Z-0003.json";
    if (!fs::exists(destination)) {
        skip("the first run did not move the bundle.");
        return;
    }
    const std::string before = readWhole(destination);

    const std::string output =
        runCli({"evidence", "migrate", evidence.string(), "--apply"});
    check(contains(output, "0 bundle(s) moved"),
          "the second run moved nothing");
    check(fs::exists(destination), "the moved bundle is still there");
    check(readWhole(destination) == before, "and its bytes are unchanged");
}

void testExistingDestinationIsNotOverwritten(const fs::path& dir) {
    std::printf("a destination that is already occupied is not overwritten\n");
    const fs::path evidence = dir / "occupied";
    fs::create_directories(evidence / "audit");
    if (!makeFlatBundle(evidence, "20260101T000003Z-0004.json")) {
        skip("the sanitize run did not produce a bundle here.");
        return;
    }
    // Something else is already at the destination.
    const fs::path destination = evidence / "audit" / "20260101T000003Z-0004.json";
    const std::string occupant = "{\"schema\": \"ledgerase.evidence_bundle/3\"}\n";
    writeWhole(destination, occupant);

    const std::string output =
        runCli({"evidence", "migrate", evidence.string(), "--apply"});
    check(contains(output, "refused to overwrite"),
          "the occupied destination is refused, and said so");
    check(fs::exists(evidence / "20260101T000003Z-0004.json"),
          "the flat bundle was left where it was");
    check(readWhole(destination) == occupant,
          "and the file at the destination was not touched");
}

void testCorruptedBundleIsNotMoved(const fs::path& dir) {
    std::printf("a bundle that does not verify is left where it is\n");
    const fs::path evidence = dir / "corrupt";
    fs::create_directories(evidence);
    if (!makeFlatBundle(evidence, "20260101T000004Z-0005.json")) {
        skip("the sanitize run did not produce a bundle here.");
        return;
    }
    const fs::path source = evidence / "20260101T000004Z-0005.json";
    std::string text = readWhole(source);
    // Damage the recorded hash, so the document is still JSON and still
    // carries a recognised schema, but no longer matches its own content.
    const std::string marker = "\"canonical_hash\": \"";
    const std::size_t at = text.find(marker);
    if (at == std::string::npos) {
        skip("the bundle does not carry a canonical hash to damage.");
        return;
    }
    const std::size_t hashAt = at + marker.size();
    if (hashAt >= text.size()) {
        skip("the bundle does not carry a canonical hash to damage.");
        return;
    }
    const char damaged = (text[hashAt] == 'a') ? 'b' : 'a';
    text[hashAt] = damaged;
    writeWhole(source, text);

    const std::string output =
        runCli({"evidence", "migrate", evidence.string(), "--apply"});
    check(contains(output, "NOT VERIFIED"),
          "the damaged bundle is reported as not verified");
    check(fs::exists(source), "the damaged bundle is left where it is");
    check(!fs::exists(evidence / "audit" / "20260101T000004Z-0005.json"),
          "and it was not moved into audit/");
}

void testReportsAreLeftAlone(const fs::path& dir) {
    std::printf("reports/ is not touched\n");
    const fs::path evidence = dir / "reports-alone";
    fs::create_directories(evidence / "reports");
    const fs::path inReports = evidence / "reports" / "20260101T000005Z-0006.json";
    writeWhole(inReports, "{\"schema\": \"ledgerase.evidence_bundle/3\"}\n");

    const std::string output =
        runCli({"evidence", "migrate", evidence.string(), "--apply"});
    check(fs::exists(inReports), "the file in reports/ is still there");
    check(!contains(output, "20260101T000005Z-0006.json"),
          "and it was not considered for moving");
}

}  // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "ledgerase-evidence-migrate-test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    testDryRunChangesNothing(dir);
    testApplyMovesTheFileUnchanged(dir);
    testSecondRunDoesNothing(dir);
    testExistingDestinationIsNotOverwritten(dir);
    testCorruptedBundleIsNotMoved(dir);
    testReportsAreLeftAlone(dir);

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        if (g_skipped > 0) {
            return kSkipExitCode;
        }
        std::printf("\nAll evidence migrate checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
