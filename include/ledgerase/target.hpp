// What a sanitization or recovery job is pointed at.
//
// Everything in this codebase was written for block devices, and the
// device-centric fields (DeviceInfo, the ioctl platform layer, the mount and
// boot checks) all still describe device work. This header introduces the
// wider notion without changing any of that: a job that names a block device
// is classified as one and takes exactly the same path it always did.
//
// The kinds exist because the same pipeline has to serve work with materially
// different safety questions. A device can be the system disk; a file cannot,
// but it can be a hard link or a symlink. A recovery image is opened read-only
// and must never be written at all.

#ifndef LEDGERASE_TARGET_HPP
#define LEDGERASE_TARGET_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace ledgerase {

enum class TargetKind {
    // A block device: /dev/sda, /dev/nvme0n1. Destructive device-level methods
    // are meaningful.
    BLOCK_DEVICE,
    // A regular file used as a disk image. Overwritten in place; its contents
    // are destroyed and the filesystem it may contain is not.
    DISK_IMAGE,
    // A single regular file. A file-level target.
    FILE,
    // A directory and everything under it.
    FOLDER,
    // A file opened read-only as a source for recovery. Never written.
    RECOVERY_IMAGE,
    // The path did not resolve to anything this tool recognises.
    UNKNOWN,
};

std::string targetKindToString(TargetKind kind);

// The three properties that decide the safety questions, taken from one stat()
// so they cannot disagree with each other.
struct TargetProperties {
    bool exists = false;
    bool isBlockDevice = false;
    bool isDirectory = false;
    bool isRegularFile = false;
    bool isSymlink = false;
    bool isCharDevice = false;
    // Hard link count, from st_nlink. A regular file with more than one link
    // shares its content with another name, so erasing one name silently
    // destroys the other.
    uint32_t linkCount = 1;
    uint64_t sizeBytes = 0;
    uint64_t deviceId = 0;   // st_dev
    uint64_t inodeNumber = 0;  // st_ino
    uint32_t modeBits = 0;   // st_mode
    int errorNumber = 0;     // errno, when !exists

    // A size of zero for a regular file is legal but usually means the caller
    // wanted something that is not there.
    bool isEmpty() const { return sizeBytes == 0; }
};

// stat()s the path, following symlinks, and fills in the properties.
TargetProperties statTarget(const std::string& path);

// stat()s without following, so a symlink is identified as one.
TargetProperties lstatTarget(const std::string& path);

// Classifies a path into a kind.
//
// `properties` may be supplied by the caller when it has already stat()ed the
// path, which is the normal case: the caller needs the properties anyway, and
// stat()ing twice invites the two answers to disagree.
TargetKind classifyTarget(const std::string& path,
                          const TargetProperties* properties = nullptr);

// A disk image is distinguished from an ordinary file by intent, not by
// content. `isRecoverySource` selects RECOVERY_IMAGE over DISK_IMAGE for a
// regular file, because the two are treated oppositely: one is overwritten,
// the other must never be.
TargetKind classifyTarget(const std::string& path,
                          const TargetProperties* properties,
                          bool isRecoverySource);

// A labelled description of the target, for a plan and for the evidence record.
struct SanitizationTarget {
    TargetKind kind = TargetKind::UNKNOWN;
    std::string path;
    // How the target is named in output. For a device this is the device path;
    // for a folder it is the folder, and its contents are named in the
    // inventory rather than here.
    std::string label;
    // Number of items the target refers to: 1 for a device or a file, the
    // entry count for a folder, 0 when not known yet.
    uint64_t itemCount = 0;

    bool isDevice() const {
        return kind == TargetKind::BLOCK_DEVICE || kind == TargetKind::DISK_IMAGE;
    }
    // True when the job may write to the target at all. A recovery source is
    // read-only by construction.
    bool isWritableTarget() const {
        return kind != TargetKind::RECOVERY_IMAGE && kind != TargetKind::UNKNOWN;
    }
};

std::string describeTarget(const SanitizationTarget& target);

} // namespace ledgerase

#endif // LEDGERASE_TARGET_HPP
