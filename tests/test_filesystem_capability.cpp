// Tests for the filesystem capability matrix and the refusal policy.
//
// The matrix is a claim about what this tool can do to somebody's filesystem,
// so the tests are about two things: that the table says what it is supposed to
// say, and that the refusal is *actionable* rather than a bare "no". A refusal
// that does not tell the operator what to do instead is indistinguishable from
// a bug, and the tests treat it as one.

#include "ledgerase/filesystem_capability.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
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

// Every cell in the matrix carries a reason, and it is not filler.
void testEveryCellHasAReason() {
    std::printf("every matrix cell carries a reason\n");
    for (FilesystemKind kind : knownFilesystemKinds()) {
        const FilesystemCapabilities caps = filesystemCapabilities(kind);
        check(caps.cells.size() == 5,
              std::string(filesystemKindToString(kind)) +
                  " has all five operations");
        for (const FilesystemCapability& cell : caps.cells) {
            check(!cell.reason.empty(),
                  std::string(filesystemKindToString(kind)) + " / " +
                      filesystemOperationToString(cell.operation) +
                      " has a reason");
            check(cell.reason.size() > 20,
                  std::string(filesystemKindToString(kind)) + " / " +
                      filesystemOperationToString(cell.operation) +
                      " has a substantive reason, not a placeholder");
        }
    }
}

// The cell the whole tool's honesty rests on.
void testDeleteTraceRemovalIsNeverClaimed() {
    std::printf("removing delete traces is never claimed as supported\n");
    for (FilesystemKind kind : knownFilesystemKinds()) {
        const FilesystemCapabilities caps = filesystemCapabilities(kind);
        const FilesystemCapability traces =
            caps.capability(FilesystemOperation::REMOVE_DELETE_TRACES);
        check(traces.level != SupportLevel::SUPPORTED,
              std::string(filesystemKindToString(kind)) +
                  " does not claim that delete traces can be removed");
    }
}

// The rule (Phase B): permission is NOT gated on the filesystem. A pwrite is
// attempted on every filesystem; the OVERWRITE_CONTENT cell describes residue,
// which is reported rather than enforced against. So every filesystem, including
// an unidentified one, is *permitted*, and a filesystem that leaves residue
// carries a residueNote instead of a refusal.
void testPermissionIsNotGatedOnResidue() {
    std::printf("permission is not gated on residue; residue is reported\n");

    // No filesystem is refused any more, and the policy is not vacuous: at least
    // one must actually leave residue, which is what the note is for.
    int residueFilesystems = 0;
    for (FilesystemKind kind : knownFilesystemKinds()) {
        const FilesystemCapabilities caps = filesystemCapabilities(kind);
        const SupportLevel level =
            caps.capability(FilesystemOperation::OVERWRITE_CONTENT).level;
        const FilesystemRefusal outcome = evaluateErasePermission(caps);
        check(!outcome.refused,
              std::string(filesystemKindToString(kind)) +
                  " is permitted: a file-level erase is attempted on it");
        if (level != SupportLevel::SUPPORTED) {
            ++residueFilesystems;
            check(!outcome.residueNote.empty(),
                  std::string(filesystemKindToString(kind)) +
                      " discloses the residue it leaves");
            check(!outcome.residue.empty(),
                  std::string(filesystemKindToString(kind)) +
                      " records what the residue is");
            // The note has to name the command that reaches the copies a file
            // cannot, not just say "some residue remains".
            check(outcome.residueNote.find("sanitize") != std::string::npos,
                  std::string(filesystemKindToString(kind)) +
                      " points at the command that does reach the copies");
        } else {
            check(outcome.residueNote.empty(),
                  std::string(filesystemKindToString(kind)) +
                      " carries no residue note when it leaves none");
        }
    }
    check(residueFilesystems > 0,
          "at least one filesystem leaves residue, so the disclosure is real");
}

// A residue disclosure the operator cannot act on is a bug in the tool.
void testEveryResidueNoteSaysWhatToDoInstead() {
    std::printf("every residue note says what to do instead\n");
    for (FilesystemKind kind : knownFilesystemKinds()) {
        const FilesystemRefusal outcome =
            evaluateErasePermission(filesystemCapabilities(kind));
        if (outcome.residueNote.empty()) {
            continue;
        }
        check(!outcome.residue.empty(),
              std::string(filesystemKindToString(kind)) +
                  " says what residue it leaves");
        check(outcome.residueNote.find("sanitize") != std::string::npos,
              std::string(filesystemKindToString(kind)) +
                  " points at the command that does reach the copies");
        check(outcome.residueNote.find("try again") == std::string::npos,
              std::string(filesystemKindToString(kind)) +
                  " does not tell the operator to try the same thing again");
    }
}

// An unidentified filesystem must not inherit a convenient row, but it is still
// *permitted* to be written to - the refusal is gone, and the residue is UNKNOWN.
void testUnknownFilesystemClaimsNothing() {
    std::printf("an unidentified filesystem claims nothing, and is permitted\n");
    const FilesystemCapabilities caps = filesystemCapabilities(FilesystemKind::UNKNOWN);
    for (const FilesystemCapability& cell : caps.cells) {
        check(cell.level == SupportLevel::UNKNOWN,
              std::string(filesystemOperationToString(cell.operation)) +
                  " is UNKNOWN on an unidentified filesystem");
    }
    const FilesystemRefusal outcome = evaluateErasePermission(caps);
    check(!outcome.refused, "an unidentified filesystem is still permitted");
    check(outcome.level == SupportLevel::UNKNOWN,
          "the outcome reports UNKNOWN residue, because the tool does not know "
          "enough to say what is unsupported or supported");
}

// "ext4" and "ext4dev" are different answers.
void testFilesystemNamesAreNotCollapsed() {
    std::printf("filesystem names are not collapsed by prefix\n");
    check(filesystemKindFromName("ext4") == FilesystemKind::EXT2_EXT3_EXT4,
          "ext4 is ext2/ext3/ext4");
    check(filesystemKindFromName("ext2") == FilesystemKind::EXT2_EXT3_EXT4,
          "ext2 is ext2/ext3/ext4");
    check(filesystemKindFromName("ntfs3") == FilesystemKind::NTFS, "ntfs3 is ntfs");
    check(filesystemKindFromName("vfat") == FilesystemKind::VFAT, "vfat is vfat");
    check(filesystemKindFromName("tmpfs") == FilesystemKind::TMPFS,
          "tmpfs is tmpfs");
    check(filesystemKindFromName("") == FilesystemKind::UNKNOWN,
          "an empty name is unknown, not a default");
    check(filesystemKindFromName("zfs") == FilesystemKind::ZFS, "zfs is zfs");
    check(filesystemKindFromName("apfs") == FilesystemKind::APFS,
          "apfs is apfs, and separately unsupported");
    check(filesystemKindFromName("bcachefs") == FilesystemKind::OTHER,
          "a filesystem with no measurements is OTHER, which is refused");
}

// A lookup for an operation the matrix does not carry must not read as a
// deliberate answer.
void testMissingOperationIsNotSilentlySupported() {
    std::printf("a missing operation is UNKNOWN, never supported\n");
    FilesystemCapabilities caps = filesystemCapabilities(FilesystemKind::EXT2_EXT3_EXT4);
    caps.cells.clear();
    const FilesystemCapability missing =
        caps.capability(FilesystemOperation::OVERWRITE_FREE_SPACE);
    check(missing.level == SupportLevel::UNKNOWN,
          "an absent cell reads as UNKNOWN");
    check(!missing.reason.empty(), "an absent cell explains itself");
}

// The live detection path, against this machine's own filesystem.
void testDetectionNamesTheFilesystemAFileIsOn() {
    std::printf("detection names the filesystem a real file is on\n");
    const FilesystemCapabilities caps = detectFilesystem("/etc/hostname");
    check(caps.kind != FilesystemKind::UNKNOWN,
          "a file on a mounted filesystem is identified");
    check(!caps.reportedName.empty(),
          "the name the system reported is recorded verbatim");

    const SupportLevel level =
        caps.capability(FilesystemOperation::OVERWRITE_CONTENT).level;
    const FilesystemRefusal outcome = evaluateErasePermission(caps);
    check(!outcome.refused,
          "a live filesystem is permitted, whatever its residue level is");
    check((level == SupportLevel::SUPPORTED) == outcome.residueNote.empty(),
          "the live residue note appears exactly when the matrix says residue "
          "is not SUPPORTED");

    // A path that does not exist must be UNKNOWN with a reason, not a crash and
    // not a default.
    const FilesystemCapabilities missing =
        detectFilesystem("/nonexistent/definitely/not/here");
    check(missing.kind == FilesystemKind::UNKNOWN ||
              missing.reportedName.empty(),
          "a path that does not exist is not claimed to be on a filesystem");
}

// The matrix and the documentation must not drift apart.
void testDocumentationCoversEveryRow() {
    std::printf("the documented table covers every matrix row\n");
    const fs::path doc =
        fs::path(LEDGERASE_SOURCE_DIR) / "docs" / "FILESYSTEMS.md";
    if (!fs::exists(doc)) {
        std::printf("  SKIP docs/FILESYSTEMS.md is not present\n");
        return;
    }
    std::ifstream input(doc);
    const std::string text((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    for (FilesystemKind kind : knownFilesystemKinds()) {
        check(text.find(filesystemKindToString(kind)) != std::string::npos,
              std::string("docs/FILESYSTEMS.md documents ") +
                  filesystemKindToString(kind));
    }
    for (FilesystemOperation operation :
         {FilesystemOperation::DETECT, FilesystemOperation::OVERWRITE_CONTENT,
          FilesystemOperation::REMOVE_DELETE_TRACES,
          FilesystemOperation::HANDLE_JOURNAL,
          FilesystemOperation::OVERWRITE_FREE_SPACE}) {
        check(text.find(filesystemOperationToString(operation)) !=
                  std::string::npos,
              std::string("docs/FILESYSTEMS.md names the operation ") +
                  filesystemOperationToString(operation));
    }
}

} // namespace

int main() {
    testEveryCellHasAReason();
    testDeleteTraceRemovalIsNeverClaimed();
    testPermissionIsNotGatedOnResidue();
    testEveryResidueNoteSaysWhatToDoInstead();
    testUnknownFilesystemClaimsNothing();
    testFilesystemNamesAreNotCollapsed();
    testMissingOperationIsNotSilentlySupported();
    testDetectionNamesTheFilesystemAFileIsOn();
    testDocumentationCoversEveryRow();

    if (g_failures == 0) {
        std::printf("\nAll filesystem-capability checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
