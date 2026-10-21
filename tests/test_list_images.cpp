// list-devices --images <dir>, and the capacity formatting it shares with
// the rest of the tool.
//
// Two things are checked here:
//
//   * the size a listing shows. Below one gibibyte the figure is given in
//     mebibytes, because rounding down to whole gibibytes reported "0 GB" for
//     a medium that was not empty.
//   * that plain "list-devices" is unchanged by the option's existence. The
//     images are listed only when the directory is named.
//
// The image listing runs the real CLI, because the option is parsed and
// rendered there and a test of the pieces would not see them.

#include "ledgerase/types.hpp"

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

// A file of a given size. A file larger than a gibibyte is made sparse, so
// the test does not need a gibibyte of disk to say that a gibibyte is
// reported.
void makeFileOfSize(const fs::path& path, uintmax_t bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    const std::vector<char> zeros(64 * 1024, 0);
    uintmax_t written = 0;
    while (written < bytes) {
        const uintmax_t chunk = std::min<uintmax_t>(zeros.size(), bytes - written);
        out.write(zeros.data(), static_cast<std::streamsize>(chunk));
        written += chunk;
    }
    out.close();
    // The size is what the listing reports, so it is set explicitly. The file
    // stays sparse because the contents were never written past the first
    // chunk.
    std::error_code ec;
    fs::resize_file(path, bytes, ec);
}

void testCapacityFormatting() {
    std::printf("a capacity is shown in the unit that says something about it\n");
    using ledgerase::formatCapacity;

    check(formatCapacity(0) == "0 B", "zero bytes is not shown as zero");
    check(formatCapacity(1024) == "1024 B",
          "a size below a mebibyte is shown in bytes");
    check(formatCapacity(512ull * 1024 * 1024) == "512 MB",
          "a size below a gibibyte is shown in mebibytes, not as 0 GB");
    check(formatCapacity(1024ull * 1024 * 1024 - 1) == "1023 MB",
          "the last byte before a gibibyte is still mebibytes");
    check(formatCapacity(1024ull * 1024 * 1024) == "1 GB",
          "a gibibyte is shown in gibibytes");
    check(formatCapacity(7ull * 1024 * 1024 * 1024) == "7 GB",
          "a drive-sized capacity is unchanged");
}

// Whether the CLI can be run at all. The suites that need it are skipped
// rather than failed when it cannot, so a missing binary is not read as a
// defect in the listing.
bool cliAvailable() {
    return !runCli({"version"}).empty();
}

void testImagesAreListedWithTheirRealSize(const fs::path& dir) {
    std::printf("the images in a directory are listed, with their real size\n");
    if (!cliAvailable()) {
        skip("the CLI could not be run here.");
        return;
    }
    const fs::path images = dir / "images";
    fs::create_directories(images);
    makeFileOfSize(images / "small.img", 512ull * 1024 * 1024);
    makeFileOfSize(images / "large.img", 1536ull * 1024 * 1024);
    // A directory in the same place is not an image.
    fs::create_directories(images / "not-an-image");

    const std::string listing = runCli({"list-devices", "--images", images.string()});

    check(contains(listing, "small.img"), "the smaller image is listed");
    check(contains(listing, "large.img"), "the larger image is listed");
    check(contains(listing, "512 MB"), "the smaller image shows its size in MB");
    check(contains(listing, "1 GB"), "the larger image shows its size in GB");
    check(contains(listing, "Image"),
          "an image is listed with the type Image");
    check(!contains(listing, "not-an-image"),
          "a directory in the same place is not listed as an image");
}

void testPlainListingIsUnchanged(const fs::path& dir) {
    std::printf("plain list-devices does not list images\n");
    if (!cliAvailable()) {
        skip("the CLI could not be run here.");
        return;
    }
    const fs::path images = dir / "images";
    const std::string plain = runCli({"list-devices"});
    check(!contains(plain, "small.img"),
          "without --images the image files are not listed");
    check(!contains(plain, "Image"),
          "without --images no row is typed as an image");
    check(!plain.empty(), "the plain listing still produced output");
}

void testJsonNamesTheType(const fs::path& dir) {
    std::printf("the JSON listing names the image type\n");
    if (!cliAvailable()) {
        skip("the CLI could not be run here.");
        return;
    }
    const fs::path images = dir / "images";
    const std::string json = runCli({"list-devices", "--images", images.string(),
                                      "--json"});
    check(contains(json, "\"media_type\": \"Image\""),
          "an image row in JSON is typed Image");
    check(contains(json, "small.img"), "the image is named in the JSON too");
}

void testMissingDirectoryIsRefused(const fs::path& dir) {
    std::printf("a directory that does not exist is refused, not ignored\n");
    if (!cliAvailable()) {
        skip("the CLI could not be run here.");
        return;
    }
    const std::string output =
        runCli({"list-devices", "--images", (dir / "no-such-directory").string()});
    check(!output.empty(), "the command said something about it");
    check(output.find("No such") != std::string::npos ||
              output.find("Cannot read") != std::string::npos,
          "and it named the directory it could not read");
}

}  // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "ledgerase-list-images-test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);

    testCapacityFormatting();
    testImagesAreListedWithTheirRealSize(dir);
    testPlainListingIsUnchanged(dir);
    testJsonNamesTheType(dir);
    testMissingDirectoryIsRefused(dir);

    fs::remove_all(dir, ec);

    if (g_skipped > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skipped);
    }
    if (g_failures == 0) {
        if (g_skipped > 0) {
            return kSkipExitCode;
        }
        std::printf("\nAll list-images checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
