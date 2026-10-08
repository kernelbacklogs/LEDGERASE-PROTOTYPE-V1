// What this tool can actually do to a filesystem, per filesystem.
//
// A file eraser is not a device sanitizer, and the operations that make sense
// on a disk do not all make sense on a directory entry. The question this file
// answers is narrower than "can you erase a file": for a given filesystem, can
// this tool *detect* that it is there, *overwrite the content it is asked to
// erase*, *remove the traces of the deletion*, and *handle the journal*? Each
// answer is one of three values, and the three are not interchangeable.
//
//   SUPPORTED    done, and the result is checked afterwards
//   PARTIAL      partly done, and the remainder is recorded as a limitation
//   UNSUPPORTED  not done. Refused rather than silently skipped.
//
// The refusal is the point. An eraser that overwrites a file's blocks and then
// reports "erased" would be claiming to have removed something it demonstrably
// did not: on ext4 the inode's extent map survives an ordinary delete (measured,
// docs/RESIDUE.md §3), and an eraser working on one file cannot reach the inode
// table, the journal, or the blocks of files someone deleted before it ran.
//
// Three states rather than two because "supported" would be the wrong word for
// overwriting a file's blocks. It is exactly what was asked and no more: the
// file's own extents are overwritten and read back, and everything outside them
// is out of scope. Saying "supported" without qualification is how a tool ends
// up implying an assurance it did not deliver.
//
// Every row carries a one-line reason, and the reason is part of the answer: an
// unexplained refusal is indistinguishable from a bug, and an unexplained
// "supported" cannot be reviewed.

#ifndef LEDGERASE_FILESYSTEM_CAPABILITY_HPP
#define LEDGERASE_FILESYSTEM_CAPABILITY_HPP

#include <string>
#include <vector>

namespace ledgerase {

// The operations the matrix is about. Chosen to be the ones an operator would
// assume are covered by "erase this file".
enum class FilesystemOperation {
    // Establish that the filesystem is this one, from something other than a
    // file name.
    DETECT,
    // Overwrite the content of a single open file through its descriptor, and
    // verify it by reading it back.
    OVERWRITE_CONTENT,
    // Remove the traces an ordinary delete leaves: the inode's extent map and
    // size, the directory entry's history, the blocks freed by an earlier
    // delete.
    REMOVE_DELETE_TRACES,
    // Deal with the journal, where a copy of the data can persist after the
    // file's blocks have been overwritten.
    HANDLE_JOURNAL,
    // Overwrite the whole free space of the filesystem, so blocks belonging to
    // files deleted before this run cannot be recovered.
    OVERWRITE_FREE_SPACE,
};

std::string filesystemOperationToString(FilesystemOperation operation);

enum class SupportLevel {
    SUPPORTED,
    PARTIAL,
    UNSUPPORTED,
    UNKNOWN,   // the filesystem was not identified, so nothing can be claimed
};

std::string supportLevelToString(SupportLevel level);

// A filesystem this tool knows something about.
enum class FilesystemKind {
    UNKNOWN,
    EXT2_EXT3_EXT4,
    XFS,
    BTRFS,
    F2FS,
    TMPFS,
    VFAT,
    NTFS,
    APFS,
    OVERLAYFS,
    ZFS,
    SWAP,
    OTHER,
};

std::string filesystemKindToString(FilesystemKind kind);

// One cell of the matrix.
struct FilesystemCapability {
    FilesystemOperation operation = FilesystemOperation::DETECT;
    SupportLevel level = SupportLevel::UNKNOWN;
    // One line, and it is part of the answer. Never empty for a level other
    // than UNKNOWN.
    std::string reason;
};

struct FilesystemCapabilities {
    FilesystemKind kind = FilesystemKind::UNKNOWN;
    // The name as the system reported it, so a reader can see that "ext4" and
    // "ext4dev" were distinguished.
    std::string reportedName;
    std::vector<FilesystemCapability> cells;

    // Looks up one cell. Returns UNKNOWN with an explanatory reason when the
    // matrix has no entry, rather than a default-constructed one that reads as
    // a deliberate answer.
    FilesystemCapability capability(FilesystemOperation operation) const;
};

// The whole matrix, in one table. `rows()` returns one entry per filesystem
// this tool has an opinion about, in the order of the documentation.
const std::vector<FilesystemKind>& knownFilesystemKinds();

// The full matrix for one filesystem, with a reason on every cell.
FilesystemCapabilities filesystemCapabilities(FilesystemKind kind);

// Maps a `statfs`/`blkid` filesystem name to a kind. Names are matched
// exactly, then by prefix; "ext4" and "ext4dev" are different answers, and
// "overlay" is not "ext4".
FilesystemKind filesystemKindFromName(const std::string& reportedName);

// Asks the system what filesystem a path is on.
//
// `reportedName` comes from the system and is recorded whatever it says,
// including when it says nothing. A file on a filesystem this tool cannot
// identify is UNKNOWN, which lowers the outcome - it does not default to a
// filesystem that would have been convenient.
FilesystemCapabilities detectFilesystem(const std::string& path);

// The filesystem name the platform reports for a path (for example "ext4"), or
// an empty string when the platform reports nothing. This is the same name
// detectFilesystem() records in `reportedName`; it is exposed on its own so a
// caller that needs only the name does not have to reach into the platform
// layer, which is not part of the public API.
std::string reportedFilesystemName(const std::string& path);

// Whether this tool will erase a file on this filesystem at all.
//
// The filesystem's OVERWRITE_CONTENT cell describes the *residue* a file-level
// erase leaves (copy-on-write, snapshots, resident data, the inter-file gap),
// not whether the write is permitted. Permission is therefore not gated on it:
// a pwrite is attempted on every writable filesystem and the residue is
// reported in the evidence and shown by the residual search.
//
// A non-empty `residueNote` on a permitted outcome is the disclosure the
// operator reads. Genuine safety refusals are decided at file scope from the
// file itself, not from the filesystem's name.
struct FilesystemRefusal {
    bool refused = false;
    // The OVERWRITE_CONTENT level, kept so a reader can see how much residue
    // the matrix expects even when the erase is permitted.
    SupportLevel level = SupportLevel::UNKNOWN;
    std::string filesystem;
    // The residue this filesystem's erase leaves, in the matrix's words.
    std::string residue;
    // Present when residue is not SUPPORTED: what remains, and the command that
    // reaches it. This is a note on a permitted run, not a block.
    std::string residueNote;
};

FilesystemRefusal evaluateErasePermission(const FilesystemCapabilities& caps);

} // namespace ledgerase

#endif // LEDGERASE_FILESYSTEM_CAPABILITY_HPP
