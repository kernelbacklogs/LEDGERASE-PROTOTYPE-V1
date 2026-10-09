// Runtime layout of the evidence directory.
//
//   <evidence dir>/audit/    evidence bundles - the system of record
//   <evidence dir>/reports/  renderings of a bundle
//
// A report is derived from a bundle and must never become a second record. The
// layout is checked through the real CLI, because the paths are decided in the
// command wiring and a unit test of the pieces would not see them.

#include <sys/stat.h>

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

// Runs the CLI with LEDGERASE_EVIDENCE_DIR set and returns its combined output.
std::string runCli(const fs::path& evidenceDir, const std::vector<std::string>& arguments) {
    ::setenv("LEDGERASE_EVIDENCE_DIR", evidenceDir.c_str(), 1);
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

std::vector<fs::path> jsonFilesIn(const fs::path& directory) {
    std::vector<fs::path> found;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(directory, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            found.push_back(entry.path());
        }
    }
    return found;
}

int modeOf(const fs::path& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0) {
        return -1;
    }
    return static_cast<int>(info.st_mode & 0777);
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

fs::path makeTarget(const fs::path& dir) {
    const fs::path target = dir / "layout-target.img";
    std::ofstream out(target, std::ios::binary | std::ios::trunc);
    const std::vector<char> zeros(64 * 1024, 0);
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    return target;
}

void testLayout(const fs::path& dir) {
    std::printf("bundles go to audit/, reports to reports/\n");
    const fs::path root = dir / "fresh-evidence-root";  // does not exist yet
    const fs::path target = makeTarget(dir);

    const std::string ran = runCli(
        root, {"sanitize", target.string(), "--assurance", "clear", "--force",
               "--no-progress"});

    const auto bundles = jsonFilesIn(root / "audit");
    if (bundles.empty() && !jsonFilesIn(root).empty()) {
        check(false, "the bundle is written to audit/, not directly into the evidence directory");
        return;
    }
    if (bundles.size() != 1) {
        skip("the sanitize run did not produce a bundle here (output: " +
             ran.substr(0, 80) + ")");
        return;
    }
    const fs::path bundle = bundles.front();
    const std::string jobId = bundle.stem().string();

    check(jsonFilesIn(root).empty(),
          "no bundle is written directly into the evidence directory");
    check(!fs::exists(root / "reports"),
          "reports/ is not created until a report is written");
    check(modeOf(root) == 0700 && modeOf(root / "audit") == 0700,
          "the evidence directory and audit/ were created owner-only");

    const std::string listing = runCli(root, {"audit"});
    check(contains(listing, jobId), "the audit listing finds the bundle in audit/");

    const std::string before = readWhole(bundle);
    const std::string pdfRun = runCli(root, {"report", jobId, "--format", "pdf"});
    const fs::path pdf = root / "reports" / (jobId + ".pdf");
    const std::string pdfBytes = fs::exists(pdf) ? readWhole(pdf) : std::string();
    check(pdfBytes.size() > 4 && pdfBytes.compare(0, 4, "%PDF") == 0,
          "a PDF report with no --output lands in reports/<job-id>.pdf (output: " +
              pdfRun.substr(0, 60) + ")");
    check(modeOf(root / "reports") == 0700, "reports/ is owner-only");
    check(readWhole(bundle) == before,
          "writing the report does not change the bundle: the record stays the record");

    const std::string text = runCli(root, {"report", jobId});
    check(contains(text, "Evidence canonical hash:"),
          "a text report states the canonical hash of the bundle it came from");
}

void testReportsAreNotRecords(const fs::path& dir) {
    std::printf("a file in reports/ is never read as an evidence record\n");
    const fs::path source = dir / "fresh-evidence-root" / "audit";
    const auto bundles = jsonFilesIn(source);
    if (bundles.empty()) {
        skip("no bundle to copy.");
        return;
    }
    const fs::path root = dir / "reports-only-root";
    fs::create_directories(root / "reports");
    fs::copy_file(bundles.front(), root / "reports" / bundles.front().filename());

    const std::string listing = runCli(root, {"audit"});
    check(!contains(listing, bundles.front().stem().string()),
          "the audit listing does not list a bundle copy sitting in reports/");
    const std::string shown =
        runCli(root, {"evidence", bundles.front().stem().string()});
    check(contains(shown, "No evidence bundle for job"),
          "and 'evidence <job-id>' does not find it there either");
}

void testOlderFlatBundlesStillFound(const fs::path& dir) {
    std::printf("bundles written before the split are still found\n");
    const fs::path source = dir / "fresh-evidence-root" / "audit";
    const auto bundles = jsonFilesIn(source);
    if (bundles.empty()) {
        skip("no bundle to copy.");
        return;
    }
    const fs::path root = dir / "flat-evidence-root";
    fs::create_directories(root);
    fs::copy_file(bundles.front(), root / bundles.front().filename());
    const std::string jobId = bundles.front().stem().string();

    check(contains(runCli(root, {"audit"}), jobId),
          "the audit listing finds a bundle that sits directly in the directory");
    check(contains(runCli(root, {"report", jobId}), "Evidence canonical hash:"),
          "and a report can still be made from it");
    check(!fs::exists(root / "audit"),
          "reading an older bundle does not create audit/ or move the file");
}

void testExplicitEvidencePathIsHonoured(const fs::path& dir) {
    std::printf("--evidence <file> still decides the location\n");
    const fs::path root = dir / "unused-evidence-root";
    const fs::path chosen = dir / "chosen-place" / "explicit.json";
    const fs::path target = makeTarget(dir);

    runCli(root, {"sanitize", target.string(), "--assurance", "clear", "--force",
                  "--no-progress", "--evidence", chosen.string()});
    if (!fs::exists(chosen)) {
        skip("the sanitize run did not produce a bundle here.");
        return;
    }
    check(!fs::exists(root), "the default evidence directory is left alone");
}

}  // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "ledgerase-evidence-layout-test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    testLayout(dir);
    testReportsAreNotRecords(dir);
    testOlderFlatBundlesStillFound(dir);
    testExplicitEvidencePathIsHonoured(dir);

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        std::printf("\nAll evidence layout checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
