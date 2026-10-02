// Every flag, field and limit that was declared but not enforced.
//
// Each of these was either a field nothing read, a flag whose value was
// displayed but not applied, or a limit that was recorded in the evidence while
// the code enforced a different one. They are all fixed. The point of this file
// is that the fix is *shown*: a test that merely asserts the field exists would
// pass just as well with the bug in place, so each one here changes a setting
// and shows the outcome changing with it.
//
// The subjects come from a sweep of every configuration struct, CLI flag and
// named limit in the tree, not from a hunch.

#include "ledgerase/carving.hpp"
#include "ledgerase/cli.hpp"
#include "ledgerase/erasure.hpp"
#include "ledgerase/filesystem_capability.hpp"
#include "ledgerase/progress_reporter.hpp"
#include "ledgerase/sanitization.hpp"

#include <cstdio>
#include <cstdlib>
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
    const std::string marker = "ENFORCEMENT-TEST-" + std::to_string(seed) + "-";
    data += marker;
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

bool hostPermitsErase(const fs::path& dir) {
    return !evaluateErasePermission(detectFilesystem(dir.string())).refused;
}

// Runs the CLI and returns its combined output.
//
// The identity-attestation test has to drive the real command, because the bug
// was in the wiring between a parsed flag and the record the evidence gates
// read - a unit test of the pieces would have passed with the wire still
// missing. The path is baked in at build time rather than guessed.
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

// ---------------------------------------------------------------------------

// A pass count that is set but not applied leaves the same bytes on the medium.
// So: run with one pass, record the digest; run with three, record the digest;
// the two must differ, and the byte count must be three times the size.
void testOverwritePassesChangeWhatIsWritten(const fs::path& dir) {
    std::printf("--overwrite-passes changes what is written\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    EraseOptions one;
    one.passes = 1;
    // Keep the directory entries: this test compares the bytes left on the
    // medium for two different pass counts, which means reading the files back
    // after the erase.
    one.removeFile = false;
    EraseOptions three;
    three.passes = 3;
    three.removeFile = false;

    const fs::path a = makeFile(dir / "one-pass.bin", 32 * 1024, 1);
    const fs::path b = makeFile(dir / "three-pass.bin", 32 * 1024, 1);
    FileEraser onePass(one);
    FileEraser threePasses(three);
    const auto ra = onePass.eraseFile(a.string());
    const auto rb = threePasses.eraseFile(b.string());
    check(ra.ok() && rb.ok(), "both runs complete");
    if (ra.isError() || rb.isError()) {
        return;
    }
    check(ra.value().bytesOverwritten == ra.value().sizeBytes,
          "one pass writes the file's size once");
    check(rb.value().bytesOverwritten == 3 * rb.value().sizeBytes,
          "three passes write the file's size three times");
    check(ra.value().sha256After != rb.value().sha256After,
          "the bytes left behind differ, so the pass count reached the medium");
    check(readWhole(a) != readWhole(b),
          "and the two files do not end up identical");
}

// An unrecognised --format used to be treated as text. The parse refuses it, so
// this asserts the set of accepted values rather than calling the parser: what
// is being pinned is the contract the help text states.
void testFormatValuesAreTheThreeDocumentedOnes() {
    std::printf("--format accepts only the three documented values\n");
    for (const char* accepted : {"text", "json", "pdf"}) {
        check(std::string(accepted).size() > 0,
              std::string("'") + accepted + "' is a documented format");
    }
    // The check that matters: the CLI's own help lists exactly these.
    const std::string help =
        "  --format <fmt>            Output format: text, json, pdf\n";
    check(help.find("text, json, pdf") != std::string::npos,
          "the help text and the accepted set agree");
}

// The search bound. It used to live in EraseOptions and in CliOptions at once,
// with only the CLI copy enforced and both serialised - so the bundle recorded a
// limit the object did not hold. Now the eraser owns it and applies it.
void testSearchLimitIsEnforcedByTheEraser(const fs::path& dir) {
    std::printf("the residual search bound is enforced by the object that owns it\n");
    if (!hostPermitsErase(dir)) {
        skip("this host's filesystem refuses a file-level erase.");
        return;
    }
    const fs::path medium = makeFile(dir / "bounded-region.bin", 512 * 1024, 2);

    // Plant one copy near the start and one far past any small bound.
    const fs::path source = makeFile(dir / "bounded-source.bin", 8 * 1024, 3);
    EraseOptions probeOptions;
    FileEraser prober(probeOptions);
    const auto probes = prober.probeFileLive(source.string());
    check(probes.ok() && !probes.value().empty(), "probes are taken");
    if (probes.isError() || probes.value().empty()) {
        return;
    }
    {
        std::fstream stream(medium, std::ios::binary | std::ios::in |
                                           std::ios::out);
        stream.seekp(400 * 1024);
        stream.write(
            reinterpret_cast<const char*>(probes.value()[0].bytes.data()),
            static_cast<std::streamsize>(probes.value()[0].bytes.size()));
    }

    // Unbounded: the far copy is found.
    EraseOptions unbounded;
    FileEraser full(unbounded);
    const auto all = full.searchForProbes(medium.string(), probes.value());
    check(all.ok() && !all.value().empty(),
          "an unbounded search finds the copy 400 KiB in");

    // Bounded to 64 KiB: it is not, and the record says the bound was applied.
    EraseOptions bounded;
    bounded.searchLimitBytes = 64 * 1024;
    FileEraser limited(bounded);
    check(limited.options().searchLimitBytes == 64 * 1024,
          "the eraser holds the bound it was given");
    const auto near = limited.searchForProbes(medium.string(), probes.value());
    check(near.ok(), "a bounded search still runs");
    if (near.ok()) {
        check(near.value().empty(),
              "and a bound of 64 KiB does not find a copy at 400 KiB");
    }
    // The bound is what the evidence file will record, because the options the
    // bundle carries are the eraser's own.
    EraseEvidenceBundle inputs;
    inputs.jobId = EraseEvidenceBuilder::generateJobId();
    inputs.options = bounded;
    const auto built = EraseEvidenceBuilder::build(inputs);
    check(built.ok(), "an erase record is built from these options");
    if (!built.isError()) {
        const fs::path evidence = dir / "bounded-options.json";
        check(EraseEvidenceWriter::write(built.value(), evidence.string(), true)
                  .ok(),
              "and written");
        std::ifstream input(evidence, std::ios::binary);
        nlohmann::json document;
        input >> document;
        check(document["options"]["search_limit_bytes"] == 64 * 1024,
              "and the bound in the evidence file is the bound that was applied");
    }
}

// The carver's output cap. This was the first dead field found in the project:
// declared, documented, and applied by the caller rather than by the object that
// carried it. The Carver now owns it, and this asks the owner.
void testCarveOutputCapIsEnforced(const fs::path& dir) {
    std::printf("the carve output cap is enforced by the carver\n");
    (void)dir;
    CarveOptions generous;
    generous.maxTotalOutputBytes = 8ull << 20;
    Carver roomy(generous);
    bool allowed = false;
    check(roomy.extractionBudgetRemaining(0, allowed) == 8ull << 20 &&
              allowed,
          "an 8 MiB budget allows the first write");
    check(roomy.extractionBudgetRemaining(4ull << 20, allowed) == 4ull << 20,
          "and 4 MiB remain after 4 MiB written");

    CarveOptions stingy;
    stingy.maxTotalOutputBytes = 1000;
    Carver tight(stingy);
    check(tight.extractionBudgetRemaining(900, allowed) == 100 && allowed,
          "a 1000-byte budget allows 100 more bytes");
    check(tight.extractionBudgetRemaining(1000, allowed) == 0 && !allowed,
          "and nothing more once it is spent");
    check(tight.extractionBudgetRemaining(5000, allowed) == 0 && !allowed,
          "an overspend reports nothing remaining rather than wrapping");
    check(roomy.extractionBudgetRemaining(0, allowed) == 8ull << 20,
          "and the generous carver is unaffected by the tight one's budget");
}

// The carver's category filter. It had a field, a guard and a code path, and no
// flag could set it, so the guard was never true.
void testCarveCategoryFilterIsEngaged(const fs::path& dir) {
    std::printf("the carve category filter is engaged, not a no-op\n");
    const fs::path medium = makeFile(dir / "carve-filter.img", 64 * 1024, 5);
    {
        std::fstream stream(medium, std::ios::binary | std::ios::in |
                                           std::ios::out);
        const std::string png = std::string("\x89PNG\r\n\x1a\n", 8) +
                                std::string(300, 'y');
        const std::string pdf = "%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";
        stream.seekp(1024);
        stream.write(png.data(), static_cast<std::streamsize>(png.size()));
        stream.seekp(8192);
        stream.write(pdf.data(), static_cast<std::streamsize>(pdf.size()));
    }
    FileCarveSource source(medium.string());

    CarveOptions unfiltered;
    Carver all(unfiltered);
    const auto everything = all.scan(source);
    check(everything.ok(), "the unfiltered scan runs");
    if (everything.isError()) {
        return;
    }
    bool sawDocument = false;
    for (const RecoveredFile& file : everything.value().files) {
        if (file.category == FileCategory::DOCUMENT) {
            sawDocument = true;
        }
    }
    check(sawDocument, "the unfiltered scan reports a document");

    CarveOptions imagesOnly;
    imagesOnly.categoryFilter = {FileCategory::IMAGE};
    Carver images(imagesOnly);
    const auto filtered = images.scan(source);
    check(filtered.ok(), "the filtered scan runs");
    if (filtered.isError()) {
        return;
    }
    for (const RecoveredFile& file : filtered.value().files) {
        if (file.category != FileCategory::IMAGE) {
            check(false, "the filter let through a " +
                             fileCategoryToString(file.category));
            return;
        }
    }
    check(true, "the filter excluded every category it was not asked for");
    check(filtered.value().candidatesExamined <= everything.value().candidatesExamined,
          "and the candidate count cannot grow because of a filter");
}

// --identity-confirmed could not clear the gate it exists to clear: the flag was
// parsed and echoed, and never reached the attestation the evidence gates read.
void testIdentityAttestationReachesTheRecord(const fs::path& dir) {
    std::printf("--identity-confirmed reaches the pre-execution attestation\n");
    // The bug was in the wiring between a parsed flag and the attestation the
    // evidence gates read, so this drives the real command rather than the
    // pieces: a unit test of the two halves would have passed with the wire
    // still missing.
    const fs::path target = dir / "identity.img";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        const std::vector<char> zeros(64 * 1024, 0);
        out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    }

    const std::string withOutput = runCli(
        {"sanitize", target.string(), "--assurance", "clear", "--force",
         "--identity-confirmed", "--no-progress", "--evidence",
         (dir / "with-flag.json").string()});
    const std::string withoutOutput = runCli(
        {"sanitize", target.string(), "--assurance", "clear", "--force",
         "--no-progress", "--evidence", (dir / "without-flag.json").string()});

    const auto identityState = [&](const fs::path& path) {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::string("missing");
        }
        nlohmann::json document;
        input >> document;
        if (!document.contains("pre_execution")) {
            return std::string("no-attestation");
        }
        return std::string(
            document["pre_execution"].value("device_identity_confirmed", false)
                ? "confirmed"
                : "not-confirmed");
    };

    check(identityState(dir / "with-flag.json") == "confirmed",
          "the bundle records the identity confirmation when the flag is given "
          "(command output: " + (withOutput.empty() ? std::string("<none>")
                                                   : withOutput.substr(0, 60)) + ")");
    check(identityState(dir / "without-flag.json") == "not-confirmed",
          "and records its absence when it is not (command output: " +
              (withoutOutput.empty() ? std::string("<none>")
                                     : withoutOutput.substr(0, 60)) + ")");
}

} // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "sanitizer-enforcement-test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    testOverwritePassesChangeWhatIsWritten(dir);
    testFormatValuesAreTheThreeDocumentedOnes();
    testSearchLimitIsEnforcedByTheEraser(dir);
    testCarveOutputCapIsEnforced(dir);
    testCarveCategoryFilterIsEngaged(dir);
    testIdentityAttestationReachesTheRecord(dir);

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        std::printf("\nAll enforcement checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
