// The filesystem capability matrix, and the refusal policy built on it.
//
// The table in docs/FILESYSTEMS.md is generated from what is here, so the
// documentation and the code cannot disagree. Each cell's reason is written
// here rather than in the docs because a refusal with no explanation is
// indistinguishable from a defect, and a "supported" with no explanation cannot
// be reviewed by anyone who does not read this source.
//
// The measurement behind several of these cells is in docs/RESIDUE.md. Where a
// cell says PARTIAL or UNSUPPORTED because of something unmeasured, the reason
// says that too, rather than borrowing authority from a document.

#include "ledgerase/filesystem_capability.hpp"
#include "platform/linux/linux.hpp"

#include <sys/statfs.h>
#include <sys/vfs.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace ledgerase {

std::string filesystemOperationToString(FilesystemOperation operation) {
    switch (operation) {
        case FilesystemOperation::DETECT:
            return "detect";
        case FilesystemOperation::OVERWRITE_CONTENT:
            return "overwrite content";
        case FilesystemOperation::REMOVE_DELETE_TRACES:
            return "remove delete traces";
        case FilesystemOperation::HANDLE_JOURNAL:
            return "handle journal";
        case FilesystemOperation::OVERWRITE_FREE_SPACE:
            return "overwrite free space";
    }
    return "unknown operation";
}

std::string supportLevelToString(SupportLevel level) {
    switch (level) {
        case SupportLevel::SUPPORTED:
            return "supported";
        case SupportLevel::PARTIAL:
            return "partial";
        case SupportLevel::UNSUPPORTED:
            return "unsupported";
        case SupportLevel::UNKNOWN:
            return "unknown";
    }
    return "unknown";
}

std::string filesystemKindToString(FilesystemKind kind) {
    switch (kind) {
        case FilesystemKind::EXT2_EXT3_EXT4: return "ext2/ext3/ext4";
        case FilesystemKind::XFS: return "xfs";
        case FilesystemKind::BTRFS: return "btrfs";
        case FilesystemKind::F2FS: return "f2fs";
        case FilesystemKind::TMPFS: return "tmpfs";
        case FilesystemKind::VFAT: return "vfat";
        case FilesystemKind::NTFS: return "ntfs";
        case FilesystemKind::APFS: return "apfs";
        case FilesystemKind::OVERLAYFS: return "overlayfs";
        case FilesystemKind::ZFS: return "zfs";
        case FilesystemKind::SWAP: return "swap";
        case FilesystemKind::OTHER: return "other";
        case FilesystemKind::UNKNOWN: return "unknown";
    }
    return "unknown";
}

const std::vector<FilesystemKind>& knownFilesystemKinds() {
    static const std::vector<FilesystemKind> kinds = {
        FilesystemKind::EXT2_EXT3_EXT4,
        FilesystemKind::XFS,
        FilesystemKind::BTRFS,
        FilesystemKind::F2FS,
        FilesystemKind::TMPFS,
        FilesystemKind::VFAT,
        FilesystemKind::NTFS,
        FilesystemKind::APFS,
        FilesystemKind::OVERLAYFS,
        FilesystemKind::ZFS,
        FilesystemKind::SWAP,
        FilesystemKind::OTHER,
    };
    return kinds;
}

FilesystemKind filesystemKindFromName(const std::string& reportedName) {
    if (reportedName.empty()) {
        return FilesystemKind::UNKNOWN;
    }
    // Exact matches first. "ext4" and "ext4dev" are different answers, and a
    // prefix match that merged them would report ext4's measured behaviour for a
    // filesystem nobody has measured.
    if (reportedName == "ext2" || reportedName == "ext3" || reportedName == "ext4") {
        return FilesystemKind::EXT2_EXT3_EXT4;
    }
    if (reportedName == "xfs") return FilesystemKind::XFS;
    if (reportedName == "btrfs") return FilesystemKind::BTRFS;
    if (reportedName == "f2fs") return FilesystemKind::F2FS;
    if (reportedName == "tmpfs" || reportedName == "ramfs") {
        return FilesystemKind::TMPFS;
    }
    if (reportedName == "vfat" || reportedName == "msdos" ||
        reportedName == "exfat") {
        return FilesystemKind::VFAT;
    }
    if (reportedName == "ntfs" || reportedName == "ntfs3") {
        return FilesystemKind::NTFS;
    }
    if (reportedName == "apfs") return FilesystemKind::APFS;
    if (reportedName == "overlay" || reportedName == "overlayfs") {
        return FilesystemKind::OVERLAYFS;
    }
    if (reportedName == "zfs") return FilesystemKind::ZFS;
    if (reportedName == "swap") return FilesystemKind::SWAP;

    // Prefix matches, for the names the kernel appends a revision or a variant
    // to. Recorded through reportedName, so the reader still sees the exact
    // string the system gave.
    for (const char* prefix : {"ext4", "ext3", "ext2"}) {
        if (reportedName.rfind(prefix, 0) == 0) {
            return FilesystemKind::EXT2_EXT3_EXT4;
        }
    }
    if (reportedName.rfind("fuseblk", 0) == 0 || reportedName.rfind("ntfs", 0) == 0) {
        return FilesystemKind::NTFS;
    }
    return FilesystemKind::OTHER;
}

namespace {

struct Row {
    FilesystemKind kind;
    SupportLevel detect;
    const char* detectReason;
    SupportLevel overwrite;
    const char* overwriteReason;
    SupportLevel traces;
    const char* tracesReason;
    SupportLevel journal;
    const char* journalReason;
    SupportLevel freeSpace;
    const char* freeSpaceReason;
};

// The matrix.
//
// Read the overwrite column first and the rest follows. "Overwrite content"
// means: open the file, write a pattern over its own bytes through that
// descriptor, read it back. It does not mean the file is gone, and it does not
// mean anything outside the file was touched.
//
// "Remove delete traces" is UNSUPPORTED on every filesystem in this table, and
// that is the most important cell. On ext4 it is measurable and the measurement
// is in docs/RESIDUE.md §3: after an ordinary delete the file's name is gone
// but its inode is still addressable and its extent tree still points at the
// data blocks. Erasing content does not touch that, and an eraser working on
// one open file cannot reach the inode table for other files, the free block
// bitmap, or blocks freed before the run started.
const std::vector<Row>& matrix() {
    static const std::vector<Row> rows = {
        {FilesystemKind::EXT2_EXT3_EXT4, SupportLevel::SUPPORTED,
         "statfs reports ext2/ext3/ext4 and the name is matched exactly",
         SupportLevel::SUPPORTED,
         "the file's own blocks are overwritten through its descriptor and "
         "read back; nothing else on the filesystem is touched",
         SupportLevel::UNSUPPORTED,
         "measured: the inode survives an ordinary delete, still addressable, "
         "still holding the extent map and size (docs/RESIDUE.md §3)",
         SupportLevel::PARTIAL,
         "fsync/syncfs is called so pending transactions commit, which bounds "
         "the window; already-committed journal blocks are not zeroed and this "
         "tool cannot reach the journal's own space",
         SupportLevel::UNSUPPORTED,
         "freeing a file's blocks and overwriting the free list means writing "
         "blocks this tool was not asked to write; not attempted"},

        {FilesystemKind::XFS, SupportLevel::SUPPORTED,
         "statfs reports xfs and the name is matched exactly",
         SupportLevel::SUPPORTED,
         "the file's own blocks are overwritten through its descriptor and "
         "read back; nothing else on the filesystem is touched",
         SupportLevel::UNSUPPORTED,
         "not measured here; on the same inode-and-extent design as ext4 the "
         "metadata outlives the delete, and this tool does not attempt to "
         "remove it either way",
         SupportLevel::PARTIAL,
         "fsync/syncfs is called; the log's own space is not zeroed",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::BTRFS, SupportLevel::SUPPORTED,
         "statfs reports btrfs and the name is matched exactly",
         SupportLevel::PARTIAL,
         "a file's blocks can be overwritten, but btrfs is copy-on-write: the "
         "previous version of the block is left in a snapshot, in a different "
         "tree, and the space this tool writes may itself be snapshotted",
         SupportLevel::UNSUPPORTED,
         "not measured here; erasing a file in the top-level tree does not "
         "reach its snapshots, and this tool does not enumerate them",
         SupportLevel::PARTIAL,
         "fsync/syncfs is called; the log's own space is not zeroed",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::F2FS, SupportLevel::SUPPORTED,
         "statfs reports f2fs and the name is matched exactly",
         SupportLevel::PARTIAL,
         "the data can be overwritten, but f2fs is a log-structured filesystem: "
         "the superseded version is in the node area until a checkpoint, and "
         "nothing here reaches it",
         SupportLevel::UNSUPPORTED,
         "not measured here; the log-structured metadata outlives the delete",
         SupportLevel::PARTIAL,
         "fsync/syncfs is called; the log's own space is not zeroed",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::TMPFS, SupportLevel::SUPPORTED,
         "statfs reports tmpfs or ramfs",
         SupportLevel::SUPPORTED,
         "the file's own pages are overwritten and read back. A tmpfs file's "
         "content is held only in those pages, so overwriting them removes the "
         "file's content from the filesystem. The pages may also be mapped by "
         "something else, which is a limit on what the memory holds rather than "
         "on what the filesystem holds, and it is recorded as a limitation",
         SupportLevel::PARTIAL,
         "the name is unlinked afterwards, so the directory entry goes; there "
         "is no on-disk inode or free-block map to clear",
         SupportLevel::SUPPORTED,
         "there is no journal: tmpfs has none, so there is nothing that could "
         "hold a copy",
         SupportLevel::SUPPORTED,
         "tmpfs has no persistent free space; the pages are released when the "
         "last reference goes and this tool does not keep one"},

        {FilesystemKind::VFAT, SupportLevel::SUPPORTED,
         "statfs reports vfat, msdos or exfat",
         SupportLevel::PARTIAL,
         "the file's cluster chain is overwritten, but vfat has no slack to "
         "clear per file, it has slack between the end of one file and the start "
         "of the next, and that belongs to no single file",
         SupportLevel::PARTIAL,
         "the directory entry is removed by the unlink and its first character "
         "is deliberately overwritten with 0xE5; the remaining bytes of the "
         "entry are not cleared by this tool",
         SupportLevel::UNSUPPORTED,
         "vfat has no journal, so there is nothing to reach; recorded so the "
         "cell is not mistaken for an oversight",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::NTFS, SupportLevel::SUPPORTED,
         "statfs reports ntfs or ntfs3, or fuseblk",
         SupportLevel::PARTIAL,
         "the file's data runs can be overwritten, but the $MFT record and the "
         "resident/indirected data of a small file live in the same structure, "
         "and this tool does not edit the MFT",
         SupportLevel::UNSUPPORTED,
         "not measured here; NTFS records the deletion in the MFT and keeps "
         "clusters in its free space, and this tool touches neither",
         SupportLevel::PARTIAL,
         "fsync/syncfs is called; the $LogFile's own space is not zeroed",
         SupportLevel::UNSUPPORTED,
         "overwriting every free cluster means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::APFS, SupportLevel::UNSUPPORTED,
         "apfs is not a Linux filesystem; there is no Linux path to ask",
         SupportLevel::UNSUPPORTED,
         "apfs is copy-on-write with a container checksummed snapshot system; "
         "a Linux build cannot address its volumes at all",
         SupportLevel::UNSUPPORTED,
         "not applicable: unreachable from Linux",
         SupportLevel::UNSUPPORTED,
         "not applicable: unreachable from Linux",
         SupportLevel::UNSUPPORTED,
         "not applicable: unreachable from Linux"},

        {FilesystemKind::OVERLAYFS, SupportLevel::PARTIAL,
         "statfs reports overlay, which is a stack, not a filesystem",
         SupportLevel::UNSUPPORTED,
         "an overlay's writes go to the upper layer, and the file being erased "
         "may be in a lower layer where an erase would be a copy-up of a delete; "
         "refused rather than done to the wrong layer",
         SupportLevel::UNSUPPORTED,
         "not applicable: a copy-up changes which filesystem holds the data, "
         "which this tool would have to reason about and cannot verify",
         SupportLevel::PARTIAL,
         "the underlying filesystem's journal is the one that matters and it is "
         "not this tool's to reach",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::ZFS, SupportLevel::SUPPORTED,
         "statfs reports zfs and the name is matched exactly",
         SupportLevel::PARTIAL,
         "a file's blocks are overwritten, but zfs is copy-on-write and copy-on-"
         "write with snapshots: a snapshot taken before this run still holds the "
         "old bytes",
         SupportLevel::UNSUPPORTED,
         "not measured here; snapshots are not enumerated and not destroyed",
         SupportLevel::PARTIAL,
         "fsync/syncfs is called; the zil is not zeroed",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},

        {FilesystemKind::SWAP, SupportLevel::UNSUPPORTED,
         "swap is a type of use, not a filesystem this tool erases files on",
         SupportLevel::UNSUPPORTED,
         "a page may have been swapped in from any filesystem; this tool has no "
         "way to know which, and erasing a page in one place does not erase the "
         "original",
         SupportLevel::UNSUPPORTED,
         "not applicable: a page in memory has no delete trace of its own. The "
         "trace that matters is the original file's, on a filesystem this tool "
         "is not touching",
         SupportLevel::UNSUPPORTED,
         "not applicable: swap has no journal, so there is nothing here that "
         "could hold a copy of a page",
         SupportLevel::UNSUPPORTED,
         "not applicable: swap is not a filesystem, so it has no free space to "
         "overwrite. The free space that matters belongs to whichever "
         "filesystem the page came from"},

        {FilesystemKind::OTHER, SupportLevel::PARTIAL,
         "the system named a filesystem this tool has no measurements for",
         SupportLevel::UNSUPPORTED,
         "refused: overwriting content without knowing the filesystem means not "
         "knowing whether the bytes are a copy, a log, or a snapshot",
         SupportLevel::UNSUPPORTED,
         "not measured, and not attempted",
         SupportLevel::UNSUPPORTED,
         "unknown journal semantics; not attempted",
         SupportLevel::UNSUPPORTED,
         "overwriting every free block means writing storage that holds "
         "other people\u2019s data with no record of which; not attempted"},
    };
    return rows;
}

const Row* rowFor(FilesystemKind kind) {
    for (const Row& row : matrix()) {
        if (row.kind == kind) {
            return &row;
        }
    }
    return nullptr;
}

} // namespace

FilesystemCapabilities filesystemCapabilities(FilesystemKind kind) {
    FilesystemCapabilities caps;
    caps.kind = kind;

    const Row* row = rowFor(kind);
    if (row == nullptr) {
        // An unidentified filesystem gets an all-UNKNOWN table, and every cell
        // says so. It does not inherit a convenient row: the whole point is that
        // an unknown filesystem lowers the outcome instead of quietly reading as
        // a familiar one.
        for (FilesystemOperation operation :
             {FilesystemOperation::DETECT,
              FilesystemOperation::OVERWRITE_CONTENT,
              FilesystemOperation::REMOVE_DELETE_TRACES,
              FilesystemOperation::HANDLE_JOURNAL,
              FilesystemOperation::OVERWRITE_FREE_SPACE}) {
            caps.cells.push_back(
                {operation, SupportLevel::UNKNOWN,
                 "the filesystem was not identified, so nothing is claimed"});
        }
        return caps;
    }

    caps.cells = {
        {FilesystemOperation::DETECT, row->detect, row->detectReason},
        {FilesystemOperation::OVERWRITE_CONTENT, row->overwrite,
         row->overwriteReason},
        {FilesystemOperation::REMOVE_DELETE_TRACES, row->traces,
         row->tracesReason},
        {FilesystemOperation::HANDLE_JOURNAL, row->journal, row->journalReason},
        {FilesystemOperation::OVERWRITE_FREE_SPACE, row->freeSpace,
         row->freeSpaceReason},
    };
    return caps;
}

FilesystemCapability FilesystemCapabilities::capability(
    FilesystemOperation operation) const {
    for (const FilesystemCapability& cell : cells) {
        if (cell.operation == operation) {
            return cell;
        }
    }
    return {operation, SupportLevel::UNKNOWN,
            "this build's matrix has no row for this operation"};
}

std::string reportedFilesystemName(const std::string& path) {
    return platform::linux::filesystemTypeOf(path);
}

FilesystemCapabilities detectFilesystem(const std::string& path) {
    FilesystemCapabilities caps;
    struct statfs info {};
    if (::statfs(path.c_str(), &info) != 0) {
        caps.kind = FilesystemKind::UNKNOWN;
        caps.reportedName = "";
        caps = filesystemCapabilities(FilesystemKind::UNKNOWN);
        caps.cells[0].reason =
            std::string("statfs failed: ") + std::strerror(errno) +
            ". The filesystem is not identified, so nothing is claimed.";
        return caps;
    }
    // The kernel's magic-to-name table lives in the kernel, not in a header
    // this project links against, so blkid is asked instead. It is a library
    // call, not a subprocess: no shell, no path interpolation.
    const std::string reported =
        platform::linux::filesystemTypeOf(path);
    caps.reportedName = reported;
    caps.kind = filesystemKindFromName(reported);
    caps = filesystemCapabilities(caps.kind);
    caps.kind = filesystemKindFromName(reported);
    caps.reportedName = reported;
    return caps;
}

// Permission is not filesystem-gated.
//
// A pwrite through the file's own descriptor is attempted on every writable
// filesystem. The matrix's OVERWRITE_CONTENT cell describes what a file-level
// erase *leaves behind* on a given filesystem (copy-on-write, snapshots, the
// inter-file gap, resident files), not whether the write is permitted. So that
// cell is reported, not enforced: a PARTIAL residue becomes a limitation and a
// note in the evidence, and the erase proceeds.
//
// The guarantee this function's name used to promise is narrower and is stated
// in docs/RESIDUE.md: after a successful file erase the file's content is no
// longer readable through the filesystem. It does not claim the content is gone
// from the medium - that is sanitize <device>, and only that.
//
// Genuine safety refusals (wrong owner, no write access, read-only mount, a
// file mapped into the running system) are decided at file scope in the eraser,
// from the file itself, not from the filesystem's name.
FilesystemRefusal evaluateErasePermission(const FilesystemCapabilities& caps) {
    FilesystemRefusal outcome;
    const FilesystemCapability content =
        caps.capability(FilesystemOperation::OVERWRITE_CONTENT);

    outcome.filesystem = caps.reportedName.empty()
                             ? filesystemKindToString(caps.kind)
                             : caps.reportedName;

    // Permitted on every filesystem, including one this tool could not
    // identify. Refusing here would mean refusing to write to storage whose
    // residue it has not characterised - which is a residue question, and one
    // the residual search answers by looking rather than by guessing.
    outcome.refused = false;
    outcome.level = content.level;
    outcome.residue = content.reason;

    if (content.level == SupportLevel::SUPPORTED) {
        return outcome;
    }

    // Anything other than SUPPORTED is residue to disclose, and the disclosure
    // has to name the command that reaches the layers a file cannot.
    outcome.residueNote =
        "This is what a file-level erase leaves on " + outcome.filesystem +
        ": " + content.reason +
        ". The erase still makes the file's content unreadable through the "
        "filesystem, which is the guarantee it gives. To reach the copies a "
        "file cannot - copy-on-write blocks, snapshots, resident data, the "
        "inter-file gap - use 'ledgerase-cli sanitize <device>'. The residual "
        "search reports what is actually still on the medium.";
    return outcome;
}

} // namespace ledgerase
