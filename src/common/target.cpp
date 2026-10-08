#include "ledgerase/target.hpp"

#include "ledgerase/types.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <sstream>

namespace ledgerase {

namespace {

void fillFromStat(struct stat& st, TargetProperties& out) {
    out.exists = true;
    out.isBlockDevice = S_ISBLK(st.st_mode);
    out.isDirectory = S_ISDIR(st.st_mode);
    out.isRegularFile = S_ISREG(st.st_mode);
    out.isCharDevice = S_ISCHR(st.st_mode);
    out.linkCount = static_cast<uint32_t>(st.st_nlink);
    out.sizeBytes = static_cast<uint64_t>(st.st_size);
    out.deviceId = static_cast<uint64_t>(st.st_dev);
    out.inodeNumber = static_cast<uint64_t>(st.st_ino);
    out.modeBits = static_cast<uint32_t>(st.st_mode);
}

} // namespace

TargetProperties statTarget(const std::string& path) {
    TargetProperties properties;
    struct stat st {};
    if (::stat(path.c_str(), &st) == 0) {
        fillFromStat(st, properties);
        return properties;
    }
    properties.errorNumber = errno;
    return properties;
}

TargetProperties lstatTarget(const std::string& path) {
    TargetProperties properties;
    struct stat st {};
    if (::lstat(path.c_str(), &st) == 0) {
        fillFromStat(st, properties);
        // lstat does not follow, so S_ISLNK is meaningful here. The mode bits
        // of a symlink describe the link, not what it points at.
        properties.isSymlink = S_ISLNK(st.st_mode);
        return properties;
    }
    properties.errorNumber = errno;
    return properties;
}

TargetKind classifyTarget(const std::string& path,
                          const TargetProperties* properties) {
    return classifyTarget(path, properties, /*isRecoverySource=*/false);
}

TargetKind classifyTarget(const std::string& path,
                          const TargetProperties* properties,
                          bool isRecoverySource) {
    (void)path;
    if (properties == nullptr) {
        TargetProperties probed = statTarget(path);
        return classifyTarget(path, &probed, isRecoverySource);
    }
    if (!properties->exists) {
        return TargetKind::UNKNOWN;
    }
    if (properties->isBlockDevice) {
        return TargetKind::BLOCK_DEVICE;
    }
    if (properties->isDirectory) {
        return TargetKind::FOLDER;
    }
    if (properties->isRegularFile) {
        // A regular file is a disk image or a recovery source depending on what
        // the job is for. The two are treated oppositely downstream, so the
        // distinction has to be made here rather than inferred later.
        return isRecoverySource ? TargetKind::RECOVERY_IMAGE
                                : TargetKind::DISK_IMAGE;
    }
    return TargetKind::UNKNOWN;
}

std::string targetKindToString(TargetKind kind) {
    switch (kind) {
        case TargetKind::BLOCK_DEVICE:
            return "block device";
        case TargetKind::DISK_IMAGE:
            return "disk image";
        case TargetKind::FILE:
            return "file";
        case TargetKind::FOLDER:
            return "folder";
        case TargetKind::RECOVERY_IMAGE:
            return "recovery image";
        case TargetKind::UNKNOWN:
        default:
            return "unknown";
    }
}

std::string describeTarget(const SanitizationTarget& target) {
    std::ostringstream out;
    out << targetKindToString(target.kind) << " " << target.path;
    if (target.kind == TargetKind::FOLDER && target.itemCount > 0) {
        out << " (" << target.itemCount << " items)";
    }
    return out.str();
}

} // namespace ledgerase
