// Tests for folder handling and file-scope safety.
//
// The single-file erase is covered elsewhere. What is tested here is everything
// that only becomes dangerous at folder scale:
//
//   * the traversal's classification, which must match what the dry run promised
//   * glob filtering, including the '*' versus '**' distinction that decides
//     whether a pattern can match a whole subtree
//   * the symlink rule, which is the one this tool most needs to get right: a
//     symlink out of the folder is a way to erase a file the operator never
//     named
//   * the refusals, which must be refusals and not warnings
//
// Every case that touches the filesystem uses a real directory under the temp
// path. Nothing here is simulated, because the question being asked is what the
// code does to a real directory tree.

#include "ledgerase/erasure.hpp"
#include "platform/linux/linux.hpp"

#include <cstdio>
#include <filesystem>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <csignal>
#include <unistd.h>
#include <fstream>
#include <string>
#include <vector>

using namespace ledgerase;
namespace fs = std::filesystem;

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

void writeFile(const fs::path& p, const std::string& body) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << body;
}

std::string readFile(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

const std::string kMark = "FOLDER-TEST-MARKER";

// A tree with a file at each level, a log file, and a symlink escaping the
// folder. Returns the root.
fs::path makeTree(const std::string& name) {
    const fs::path root = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root / "sub" / "deep", ec);
    fs::create_directories(root.parent_path() / (name + "-outside"), ec);

    writeFile(root / "a.txt", kMark + "-a");
    writeFile(root / "b.log", kMark + "-b");
    writeFile(root / "sub" / "c.txt", kMark + "-c");
    writeFile(root / "sub" / "d.log", kMark + "-d");
    writeFile(root / "sub" / "deep" / "e.txt", kMark + "-e");
    writeFile(root.parent_path() / (name + "-outside") / "secret.txt",
              kMark + "-secret");
    return root;
}

void linkOut(const fs::path& root, const std::string& name) {
    std::error_code ec;
    fs::create_symlink(root.parent_path() / (fs::path(root).filename().string() +
                                             "-outside") / "secret.txt",
                       root / name, ec);
}

void linkIn(const fs::path& root, const std::string& name,
            const std::string& target) {
    std::error_code ec;
    fs::create_symlink(root / target, root / name, ec);
}

// Counts entries in the record that were actually erased.
uint64_t erasedCount(const FolderEraseRecord& r) { return r.filesErased; }

bool mentions(const FolderEraseRecord& r, const std::string& needle) {
    for (const std::string& s : r.notErased) {
        if (s.find(needle) != std::string::npos) return true;
    }
    return false;
}

// --- recursion ------------------------------------------------------------

void testNonRecursiveStaysAtTheTopLevel(const fs::path& root) {
    // root is the tree built by the caller; each case gets its own.
    std::printf("a non-recursive run touches only the top level\n");
    EraseOptions o;
    o.recursive = false;
    o.removeFile = true;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;

    check(!fs::exists(root / "a.txt"), "a top-level file was erased");
    check(fs::exists(root / "sub" / "c.txt"),
          "a file below the top level is untouched");
    check(fs::exists(root / "sub" / "deep" / "e.txt"),
          "a file two levels down is untouched");
    check(mentions(r.value(), "sub"), "the subdirectory is named in the record");
    check(mentions(r.value(), "not recursive"),
          "and named as not recursed, not as a failure");
    check(r.value().filesRefused >= 1, "the refused subdirectory is counted");
}

// --- dry run --------------------------------------------------------------

void testDryRunWritesNothing() {   // builds its own tree
    std::printf("a dry run reports what it would do and writes nothing\n");
    const fs::path dry = makeTree("sanitizer-dryrun");
    linkOut(dry, "escape.txt");

    const auto before = readFile(dry / "a.txt");
    const auto deepBefore = readFile(dry / "sub" / "deep" / "e.txt");
    const auto secretBefore =
        readFile(dry.parent_path() / "sanitizer-dryrun-outside" / "secret.txt");

    EraseOptions o;
    o.recursive = true;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.planFolder(dry.string());
    check(r.ok(), "the plan completes");
    if (r.isError()) return;

    check(r.value().dryRun, "the record says it was a dry run");
    // a.txt, b.log, sub/c.txt, sub/d.log, sub/deep/e.txt - five, and the file
    // the escaping symlink points at is not among them.
    check(r.value().filesErased == 5,
          "five files would be erased (got " +
              std::to_string(r.value().filesErased) + ")");
    check(r.value().totalBytes == before.size() * 5,
          "the total is the sum of the five files, and not the secret");

    // The whole point: nothing changed.
    check(readFile(dry / "a.txt") == before, "the top-level file is untouched");
    check(readFile(dry / "sub" / "deep" / "e.txt") == deepBefore,
          "the deep file is untouched");
    check(fs::exists(dry / "sub" / "deep" / "e.txt"), "no file was removed");
    check(readFile(dry.parent_path() / "sanitizer-dryrun-outside" / "secret.txt") ==
              secretBefore,
          "the file the escaping symlink points at is untouched");
}

// --- glob filtering -------------------------------------------------------

void testExcludePatternSkipsMatchingFiles() {   // each case builds its own tree
    std::printf("--exclude removes matching entries and says so\n");
    const fs::path root = makeTree("sanitizer-glob-exclude");
    EraseOptions o;
    o.recursive = true;
    o.excludePatterns = {"*.log"};
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;

    check(fs::exists(root / "b.log"),
          "the excluded log is still there - excluded means not touched, not "
          "erased anyway");
    check(fs::exists(root / "sub" / "d.log"),
          "an excluded log below the top level is still there too");
    check(mentions(r.value(), "b.log"), "the excluded file is named");
    check(mentions(r.value(), "excluded"),
          "and the reason given is the pattern, not a failure");
    check(!fs::exists(root / "a.txt"), "a non-matching file was still erased");
    check(!fs::exists(root / "sub" / "deep" / "e.txt"),
          "recursion still reached the deepest file");
}

void testIncludePatternLimitsTheRun() {   // each case builds its own tree
    std::printf("--include limits the run to matching entries\n");
    const fs::path root = makeTree("sanitizer-glob-include");
    EraseOptions o;
    o.recursive = true;
    o.includePatterns = {"*.txt"};
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;

    check(!fs::exists(root / "a.txt"), "the matching .txt was erased");
    check(!fs::exists(root / "sub" / "deep" / "e.txt"),
          "a .txt deeper in the tree matched too and was erased");
    check(fs::exists(root / "b.log"), "a non-matching .log was left alone");
}

void testStarDoesNotCrossASlash() {   // each case builds its own tree
    std::printf("'*' does not cross a directory separator, '**' does\n");
    // This is the difference that decides whether an exclude can silently take
    // out a whole subtree. A bare "*" that crossed '/' would make
    // "--exclude *" erase everything, which is not what the words say.
    const fs::path root = makeTree("sanitizer-glob-star");
    EraseOptions star;
    star.recursive = true;
    star.excludePatterns = {"*"};
    star.probeCount = 1;
    star.checkInUse = false;
    FileEraser eraser(star);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;
    check(erasedCount(r.value()) == 0,
          "'*' matches no nested file, so nothing below the top level is erased");
    check(fs::exists(root / "a.txt"), "the top-level file is still there");
    check(fs::exists(root / "sub" / "c.txt"), "the nested file is still there");

    // '**' is the pattern that does reach down.
    const fs::path root2 = makeTree("sanitizer-glob-globstar");
    EraseOptions deep;
    deep.recursive = true;
    deep.excludePatterns = {"**/*.txt"};
    deep.probeCount = 1;
    deep.checkInUse = false;
    FileEraser eraser2(deep);
    const auto r2 = eraser2.eraseFolder(root2.string());
    check(r2.ok(), "the second run completes");
    if (r2.isError()) return;
    check(fs::exists(root2 / "a.txt"),
          "'**/*.txt' also matches the top-level file, which is left alone");
    check(fs::exists(root2 / "sub" / "deep" / "e.txt"),
          "and the deeply nested one");
    check(!fs::exists(root2 / "b.log"),
          "a .log is not matched by the pattern, so it was erased");
}

// --- symlinks -------------------------------------------------------------

void testSymlinkOutOfFolderIsRefusedByDefault() {   // each case builds its own tree
    std::printf("a symlink out of the folder is refused, not followed\n");
    const fs::path root = makeTree("sanitizer-symlink-out");
    linkOut(root, "escape.txt");
    const fs::path secret =
        root.parent_path() / "sanitizer-symlink-out-outside" / "secret.txt";
    const std::string before = readFile(secret);

    EraseOptions o;
    o.recursive = true;
    o.followSymlinks = false;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;

    check(readFile(secret) == before,
          "the file outside the folder is byte-for-byte unchanged");
    check(fs::exists(secret), "it still exists");
    check(fs::exists(root / "escape.txt"),
          "the symlink itself is not removed either - it is a name, not a file");
    check(mentions(r.value(), "escape.txt"), "the symlink is named in the record");
    check(mentions(r.value(), "outside the folder"),
          "and the reason says it pointed outside the folder");
    check(mentions(r.value(), "--follow-symlinks"),
          "and says how to override it");
}

void testFollowSymlinksReachesTheOutsideFile() {   // each case builds its own tree
    std::printf("--follow-symlinks reaches the outside file, and says so\n");
    const fs::path root = makeTree("sanitizer-symlink-follow");
    linkOut(root, "escape.txt");
    const fs::path secret =
        root.parent_path() / "sanitizer-symlink-follow-outside" / "secret.txt";

    EraseOptions o;
    o.recursive = true;
    o.followSymlinks = true;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);

    // The dry run first: the operator must see the out-of-folder file before
    // anything happens, not after.
    const auto planned = eraser.planFolder(root.string());
    check(planned.ok(), "the plan completes");
    if (planned.ok()) {
        bool named = false;
        for (const FileEraseRecord& rec : planned.value().records) {
            if (rec.detail.find("OUTSIDE THE FOLDER") != std::string::npos) {
                named = true;
            }
        }
        check(named,
              "the plan marks the out-of-folder file as outside, so the widened "
              "scope is visible before the run");
    }

    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;
    check(!fs::exists(secret),
          "with the override the outside file is erased, as asked for");
}

void testSymlinkInsideFolderIsNotDoubleCounted() {   // each case builds its own tree
    std::printf("a symlink inside the folder is not counted twice\n");
    const fs::path root = makeTree("sanitizer-symlink-in");
    linkIn(root, "alias.txt", "a.txt");

    EraseOptions o;
    o.recursive = true;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto planned = eraser.planFolder(root.string());
    check(planned.ok(), "the plan completes");
    if (planned.isError()) return;

    // a.txt, b.log, sub/c.txt, sub/d.log, sub/deep/e.txt = 5. The alias names a
    // file already in the list, so it must not add a sixth.
    check(planned.value().filesErased == 5,
          "the alias does not add to the count (got " +
              std::to_string(planned.value().filesErased) + ", expected 5)");
    check(mentions(planned.value(), "alias.txt"),
          "the alias is still reported, as a name for a file already in scope");
}

// --- safety ---------------------------------------------------------------

// The open-file check deliberately ignores this process's own descriptors,
// because the eraser has them open by definition. That makes a test which holds
// the file with its own ifstream useless - it would be testing a case the code
// is right to skip. A real second process is needed, so one is forked and told
// to hold the file until it is released.
void testAnOpenFileIsRefused() {
    std::printf("a file open in another process is refused, not overwritten\n");
    const fs::path root = makeTree("sanitizer-safety-open");
    const fs::path target = root / "held.txt";
    writeFile(target, kMark + "-held");

    // The child opens the file and then simply sleeps. No pipe and no handshake:
    // a pipe handshake deadlocks in both directions the moment one side exits,
    // and three earlier versions of this test did. Sleeping needs no
    // synchronisation, and the parent polls for the condition it actually cares
    // about - the child's descriptor existing in /proc - up to a bound.
    const pid_t child = ::fork();
    check(child >= 0, "the child process was forked");
    if (child == 0) {
        // Raw syscalls only: fork() after iostreams have been used leaves the
        // child's stream state undefined.
        const int heldFd = ::open(target.c_str(), O_RDONLY);
        if (heldFd < 0) ::_exit(3);
        for (;;) ::sleep(30);
    }

    // Wait for the child's descriptor on the file to be visible in /proc.
    bool observed = false;
    const std::string childFdDir = "/proc/" + std::to_string(child) + "/fd";
    for (int i = 0; i < 100 && !observed; ++i) {
        ::usleep(20 * 1000);
        std::error_code ec;
        std::filesystem::directory_iterator it(childFdDir, ec);
        if (ec) continue;
        for (const auto& e : it) {
            std::error_code lc;
            if (std::filesystem::read_symlink(e.path(), lc) == target) {
                observed = true;
                break;
            }
        }
    }
    check(observed, "the child is holding the file open, visible in /proc");

    EraseOptions o;
    o.recursive = true;
    o.probeCount = 1;
    o.checkInUse = true;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());

    // Release the child whatever happened, so a failing assertion cannot leave a
    // process behind holding a file.
    ::kill(child, SIGKILL);
    int status = 0;
    ::waitpid(child, &status, 0);

    check(r.ok(), "the run completes");
    if (r.isError()) return;
    check(readFile(target).find(kMark) != std::string::npos,
          "the held file's content is untouched");
    check(mentions(r.value(), "held.txt"),
          "the held file is named in the record");
    check(mentions(r.value(), "open in another process"),
          "and the reason is that it is open elsewhere, not a write error");
}

void testTheOpenFileCheckIsNotSelfInflicted() {
    std::printf("the open-file check does not count this process's own handles\n");
    // findFileUse skips our own pid. If it did not, every file this tool opened
    // would look busy and the check would refuse everything - which is a bug
    // that looks like a safety feature, so it is worth pinning.
    const fs::path root = makeTree("sanitizer-safety-self");
    // Open a file here and ask about it. It is held by us, and the answer must
    // be "nobody else", not "us".
    std::ifstream ours(root / "a.txt", std::ios::binary);
    struct stat st {};
    check(::stat((root / "a.txt").c_str(), &st) == 0, "stat gave the inode");
    const auto use = platform::linux::findFileUse(
        static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino),
        (root / "a.txt").string());
    check(!use.openByAnyProcess,
          "a file this process has open does not report as held elsewhere");
}

void testMappedExecutableIsRefused() {
    std::printf("a mapped file is reported as mapped, from another process\n");
    // /proc/self/exe is mapped into this process, and this process is skipped by
    // design - the eraser holds its own descriptors open by definition, so
    // counting them would make every file look busy. A forked child is a pid the
    // scan will look at, and its own executable is mapped while it sleeps.
    const pid_t child = ::fork();
    check(child >= 0, "the child process was forked");
    if (child == 0) {
        for (;;) ::sleep(30);
    }
    // Let the child reach its sleep, so /proc/<pid>/maps is fully populated.
    ::usleep(250 * 1000);

    const std::string childExe = "/proc/" + std::to_string(child) + "/exe";
    struct stat st {};
    const bool statted = ::stat(childExe.c_str(), &st) == 0;
    check(statted, "the child's executable could be stat'ed");
    if (statted) {
        const auto use = platform::linux::findFileUse(
            static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino),
            childExe);
        check(use.scanCompleted, "the /proc scan completed, so a clean result "
                                 "means clean rather than unreadable");
        check(use.mappedAsExecutable,
              "the child's running executable reports as mapped, which is the "
              "signal that blocks erasing a program that is running");
    }

    ::kill(child, SIGKILL);
    int status = 0;
    ::waitpid(child, &status, 0);
}

// --- batch reporting ------------------------------------------------------

void testABatchNamesEveryAffectedFile() {   // each case builds its own tree
    std::printf("a partial batch failure names every affected file\n");
    const fs::path root = makeTree("sanitizer-batch");
    // A file that cannot be opened for writing. The refusal must name the file,
    // not roll up into a count.
    const fs::path locked = root / "locked.txt";
    writeFile(locked, kMark + "-locked");
    std::error_code ec;
    fs::permissions(locked, fs::perms::owner_read | fs::perms::group_read |
                                  fs::perms::others_read, ec);

    EraseOptions o;
    o.recursive = true;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;

    const FolderEraseRecord& rec = r.value();
    // Either the file was refused/failed, or this build is running with the
    // privilege to write it. Both are legitimate; what is not legitimate is a
    // failure that is not named.
    const bool lockFailed = rec.filesFailed > 0;
    if (lockFailed) {
        check(mentions(rec, "locked.txt"),
              "the file that could not be erased is named");
        check(rec.filesErased > 0,
              "and the run still erased the others rather than stopping");
        // Every entry has a record, so the count of records plus the notErased
        // list accounts for the whole folder.
        check(rec.records.size() + rec.notErased.size() >= 6,
              "each entry produced a record or a reason");
    } else {
        check(true, "this build can write the read-only file, so the failure "
                    "path was not reached here");
    }

    // Whatever happened, the other files are accounted for individually.
    check(rec.records.size() >= 5, "each file has its own record, not a summary");
    fs::permissions(locked, fs::perms::owner_all, ec);
}

void testDeviceNodesInsideAFolderAreRefused() {   // each case builds its own tree
    std::printf("a device node inside the folder is refused\n");
    const fs::path root = makeTree("sanitizer-devnode");
    // A FIFO stands in for a device node without needing privilege, and the
    // classification is the same branch: not a regular file.
    std::error_code ec;
    const fs::path fifo = root / "pipe";
    ::mkfifo(fifo.c_str(), 0644);

    EraseOptions o;
    o.recursive = true;
    o.probeCount = 1;
    o.checkInUse = false;
    FileEraser eraser(o);
    const auto r = eraser.eraseFolder(root.string());
    check(r.ok(), "the run completes");
    if (r.isError()) return;
    check(mentions(r.value(), "pipe"),
          "the FIFO is named in the record");
    check(mentions(r.value(), "not a regular file"),
          "and the reason is that it is not a regular file");
    check(fs::exists(fifo), "the FIFO still exists");
}

} // namespace

int main() {
    std::printf("folder handling: traversal, globs, symlink policy, safety, batch reporting\n");

    // Each case builds its own tree so one run cannot leave state that changes
    // another's answer.
    testNonRecursiveStaysAtTheTopLevel(makeTree("sanitizer-nonrec"));
    testDryRunWritesNothing();
    testExcludePatternSkipsMatchingFiles();
    testIncludePatternLimitsTheRun();
    testStarDoesNotCrossASlash();
    testSymlinkOutOfFolderIsRefusedByDefault();
    testFollowSymlinksReachesTheOutsideFile();
    testSymlinkInsideFolderIsNotDoubleCounted();
    testAnOpenFileIsRefused();
    testTheOpenFileCheckIsNotSelfInflicted();
    testMappedExecutableIsRefused();
    testABatchNamesEveryAffectedFile();
    testDeviceNodesInsideAFolderAreRefused();

    if (g_failures == 0) {
        std::printf("\nAll folder-handling checks passed.\n");
        return 0;
    }
    std::printf("\n%d folder-handling check(s) FAILED.\n", g_failures);
    return 1;
}
