#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace ledgerase {

class DeviceManager {
public:
    DeviceManager();
    ~DeviceManager();

    Result<std::vector<DeviceInfo>> discoverDevices(bool includePartitions = true);
    Result<DeviceInfo> inspectDevice(const std::string& devicePath);
    Result<void> refreshDevice(const std::string& devicePath);

    // True for a target this tool is willing to sanitize: a block device, or a
    // regular file acting as a disk image.
    //
    // Image files are accepted deliberately. They are the only way to exercise
    // the destructive path - including a full overwrite and its read-back
    // verification - without a physical disk, and this project is required to
    // support exactly that (the .img files under tests/, and whatever directory
    // the operator points at).
    static bool isSanitizableTarget(const std::string& path);

    // True only for a real block device. Kept separate because a few checks -
    // mount, system disk, boot disk - are only meaningful for one.
    static bool isBlockDevice(const std::string& path);

    // A regular file used as a disk image, or an empty string.
    static bool isDiskImage(const std::string& path);
    static bool isMounted(const std::string& path);
    static bool isSystemDisk(const std::string& path);
    static bool isBootDisk(const std::string& path);
    static std::vector<std::string> getMountPoints(const std::string& devicePath);

    Result<std::string> getDeviceSysfsPath(const std::string& devicePath) const;
    Result<std::string> readSysfsAttribute(const std::string& sysfsPath, const std::string& attribute) const;
    Result<uint64_t> readSysfsUint64(const std::string& sysfsPath, const std::string& attribute) const;
    Result<uint32_t> readSysfsUint32(const std::string& sysfsPath, const std::string& attribute) const;
    Result<bool> readSysfsBool(const std::string& sysfsPath, const std::string& attribute) const;
    Result<std::vector<PartitionInfo>> readPartitions(const std::string& devicePath) const;
    Result<std::vector<FilesystemInfo>> readFilesystems(const std::string& devicePath) const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class DeviceInspector {
public:
    explicit DeviceInspector(const DeviceManager& manager);
    ~DeviceInspector();

    Result<DeviceInfo> inspect(const std::string& devicePath);
    Result<DeviceInfo> inspectFromSysfs(const std::string& sysfsPath);

    // Builds a DeviceInfo for a regular file used as a disk image. Nothing is
    // inferred: the bus, media type and identity are UNKNOWN, which limits the
    // outcome to a host overwrite at CLEAR.
    Result<DeviceInfo> inspectDiskImage(const std::string& imagePath);

    Result<std::string> identifyTransport(const std::string& sysfsPath);
    Result<MediaType> identifyMediaType(const std::string& sysfsPath, const std::string& transport);

    // Sets info.rotationalDisputed when the kernel's rotational flag contradicts
    // the derived media type. A flag about the evidence, not a correction: the
    // kernel is reporting what the bridge told it, and hiding that would lose a
    // real disagreement.
    static void noteRotationalDisagreement(DeviceInfo& info);
    Result<bool> isRotational(const std::string& sysfsPath);
    Result<std::string> readModel(const std::string& sysfsPath);
    Result<std::string> readVendor(const std::string& sysfsPath);
    Result<std::string> readSerial(const std::string& sysfsPath);
    Result<std::string> readFirmware(const std::string& sysfsPath);
    Result<std::string> readWWN(const std::string& sysfsPath);
    Result<uint64_t> readCapacity(const std::string& sysfsPath);
    Result<uint32_t> readLogicalBlockSize(const std::string& sysfsPath);
    Result<uint32_t> readPhysicalBlockSize(const std::string& sysfsPath);
    Result<bool> isRemovable(const std::string& sysfsPath);
    Result<bool> isReadOnly(const std::string& sysfsPath);

    Result<std::vector<PartitionInfo>> readPartitions(const std::string& devicePath);
    Result<std::vector<FilesystemInfo>> readFilesystems(const std::string& devicePath);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    const DeviceManager& manager_;
};

} // namespace ledgerase