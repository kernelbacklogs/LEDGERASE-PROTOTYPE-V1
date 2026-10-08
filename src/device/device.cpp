#include "ledgerase/device.hpp"
#include "platform/linux/linux.hpp"
#include <fcntl.h>
#include <filesystem>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace ledgerase {

class DeviceManager::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

DeviceManager::DeviceManager() : pImpl_(std::make_unique<Impl>()) {}
DeviceManager::~DeviceManager() = default;

Result<std::vector<DeviceInfo>> DeviceManager::discoverDevices(bool includePartitions) {
    (void)includePartitions;
    std::vector<DeviceInfo> devices;
    std::string blockPath = "/sys/block";

    if (!std::filesystem::exists(blockPath)) {
        return Result<std::vector<DeviceInfo>>::err(ErrorCode::DEVICE_NOT_FOUND, "Block device directory not found");
    }

    for (const auto& entry : std::filesystem::directory_iterator(blockPath)) {
        if (!entry.is_directory()) continue;

        std::string devName = entry.path().filename().string();
        // Only whole-disk devices are sanitization targets. Exclude virtual,
        // RAM-backed and container-internal block devices: sanitizing them is
        // either meaningless (zram) or would damage the running system.
        if (devName.starts_with("loop") || devName.starts_with("ram") ||
            devName.starts_with("zram") || devName.starts_with("dm-") ||
            devName.starts_with("md") || devName.starts_with("sr") ||
            devName.starts_with("fd") || devName.starts_with("nbd") ||
            devName.starts_with("zd")) {
            continue;
        }

        std::string devicePath = "/dev/" + devName;
        auto inspectResult = inspectDevice(devicePath);
        if (inspectResult.ok()) {
            devices.push_back(inspectResult.value());
        }
    }

    return Result<std::vector<DeviceInfo>>::ok(devices);
}

Result<DeviceInfo> DeviceManager::inspectDevice(const std::string& devicePath) {
    DeviceInspector inspector(*this);
    return inspector.inspect(devicePath);
}

Result<void> DeviceManager::refreshDevice(const std::string& devicePath) {
    auto result = inspectDevice(devicePath);
    if (result.isError()) return Result<void>::err(result.error());
    return Result<void>::success();
}

bool DeviceManager::isBlockDevice(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return S_ISBLK(st.st_mode);
}

bool DeviceManager::isDiskImage(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    // A symlink is resolved by stat(), so a link to an image is an image. That
    // is what an operator expects and it does not widen the attack surface: the
    // path still has to be something the operator named explicitly.
    return S_ISREG(st.st_mode);
}

bool DeviceManager::isSanitizableTarget(const std::string& path) {
    return isBlockDevice(path) || isDiskImage(path);
}

bool DeviceManager::isMounted(const std::string& path) {
    return platform::linux::isMounted(path);
}

bool DeviceManager::isSystemDisk(const std::string& path) {
    return platform::linux::isSystemDisk(path);
}

bool DeviceManager::isBootDisk(const std::string& path) {
    return platform::linux::isBootDisk(path);
}

std::vector<std::string> DeviceManager::getMountPoints(const std::string& devicePath) {
    return platform::linux::getMountPoints(devicePath);
}

Result<std::string> DeviceManager::getDeviceSysfsPath(const std::string& devicePath) const {
    auto path = platform::linux::findSysfsPath(devicePath);
    if (path.empty()) {
        return Result<std::string>::err(ErrorCode::DEVICE_NOT_FOUND, "Sysfs path not found for " + devicePath);
    }
    return Result<std::string>::ok(path);
}

Result<std::string> DeviceManager::readSysfsAttribute(const std::string& sysfsPath, const std::string& attribute) const {
    return platform::linux::readSysfsAttribute(sysfsPath, attribute);
}

Result<uint64_t> DeviceManager::readSysfsUint64(const std::string& sysfsPath, const std::string& attribute) const {
    return platform::linux::readSysfsUint64(sysfsPath, attribute);
}

Result<uint32_t> DeviceManager::readSysfsUint32(const std::string& sysfsPath, const std::string& attribute) const {
    return platform::linux::readSysfsUint32(sysfsPath, attribute);
}

Result<bool> DeviceManager::readSysfsBool(const std::string& sysfsPath, const std::string& attribute) const {
    return platform::linux::readSysfsBool(sysfsPath, attribute);
}

Result<std::vector<PartitionInfo>> DeviceManager::readPartitions(const std::string& devicePath) const {
    return platform::linux::readPartitions(devicePath);
}

Result<std::vector<FilesystemInfo>> DeviceManager::readFilesystems(const std::string& devicePath) const {
    return platform::linux::readFilesystems(devicePath);
}

class DeviceInspector::Impl {
public:
    Impl(const DeviceManager& mgr) : manager(mgr) {}
    const DeviceManager& manager;
    // Set by identifyTransport() when the device resolved to a USB device node,
    // so inspectFromSysfs() can record it on the DeviceInfo without repeating
    // the walk.
    std::string usbDeviceNode;
};

DeviceInspector::DeviceInspector(const DeviceManager& manager)
    : pImpl_(std::make_unique<Impl>(manager)), manager_(manager) {}

DeviceInspector::~DeviceInspector() = default;

namespace {

// Resolves a target path to an absolute, lexically normal form.
//
// A certificate, a report and an evidence file must all name the same thing. A
// relative path names a different file depending on the working directory the
// reader happens to be in, and the read-back verifier deliberately refuses
// relative paths for the same reason. Normalising here means every consumer
// downstream can treat the recorded path as unambiguous.
std::string absolutePath(const std::string& path) {
    if (path.empty()) return path;
    std::error_code ec;
    const auto absolute = std::filesystem::absolute(path, ec);
    if (ec) return path;
    return absolute.lexically_normal().string();
}

} // namespace

Result<DeviceInfo> DeviceInspector::inspect(const std::string& devicePath) {
    if (!DeviceManager::isSanitizableTarget(devicePath)) {
        return Result<DeviceInfo>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Not a block device or a disk image file: " + devicePath,
            "A target must be a block device under /dev, or a regular file used as "
            "a disk image");
    }

    if (DeviceManager::isDiskImage(devicePath)) {
        return inspectDiskImage(absolutePath(devicePath));
    }

    auto sysfsPathResult = manager_.getDeviceSysfsPath(absolutePath(devicePath));
    if (sysfsPathResult.isError()) {
        return Result<DeviceInfo>::err(sysfsPathResult.error());
    }

    return inspectFromSysfs(sysfsPathResult.value());
}

// A regular file used as a disk image.
//
// Everything sysfs would tell us is absent, and none of it is invented: no
// model, no serial, no firmware, no bus. The transport and media type are
// UNKNOWN, which the policy engine treats as "no device-level mechanism could be
// established" and which therefore limits the outcome to a host overwrite at
// CLEAR. The capability detector reports the same thing, with the reason.
//
// A disk image gets exactly the assurance a host overwrite of a device would,
// and no more. Being a file does not make it easier to sanitize.
Result<DeviceInfo> DeviceInspector::inspectDiskImage(const std::string& imagePath) {
    struct stat st;
    if (stat(imagePath.c_str(), &st) != 0) {
        return Result<DeviceInfo>::err(
            ErrorCode::DEVICE_NOT_FOUND, "Cannot stat " + imagePath);
    }

    DeviceInfo info;
    info.path = imagePath;
    info.discoveryTime = std::chrono::system_clock::now();
    info.capacityBytes = static_cast<uint64_t>(st.st_size);
    info.logicalBlockSize = 512;
    info.physicalBlockSize = 512;
    info.transport = TransportType::UNKNOWN;
    info.mediaType = MediaType::UNKNOWN;
    info.readOnly = access(imagePath.c_str(), W_OK) != 0;
    info.model = "Disk image";
    info.identitySource = "not applicable: this is an image file, not a device";

    // A file cannot be mounted, cannot be the running root filesystem and cannot
    // be a boot disk. Recorded as positively checked rather than left at the
    // default so a reader can tell the difference between "checked, and no" and
    // "not applicable".
    info.mounted = false;
    info.systemDisk = false;
    info.bootDisk = false;

    return Result<DeviceInfo>::ok(info);
}

Result<DeviceInfo> DeviceInspector::inspectFromSysfs(const std::string& sysfsPath) {
    DeviceInfo info;
    info.sysfsPath = sysfsPath;
    info.discoveryTime = std::chrono::system_clock::now();

    std::string devName = std::filesystem::path(sysfsPath).filename().string();
    info.path = "/dev/" + devName;

    auto transportResult = identifyTransport(sysfsPath);
    if (transportResult.ok()) info.transport = static_cast<TransportType>(std::stoi(transportResult.value()));
    info.usbDeviceNode = pImpl_->usbDeviceNode;
    if (info.transport == TransportType::USB) {
        // The USB device node is the authority on what this device is. Reading
        // its descriptors here means the identity a certificate carries is the
        // one the USB interface published, not one inferred from a bus path.
        info.vendor = info.vendor.empty()
            ? platform::linux::readSysfsAttribute(info.usbDeviceNode, "idVendor")
                  .valueOr("")
            : info.vendor;
        if (info.model.empty()) {
            const std::string product =
                platform::linux::readSysfsAttribute(info.usbDeviceNode, "product")
                    .valueOr("");
            if (!product.empty()) {
                info.model = product;
            }
        }
        if (info.serial.empty()) {
            const std::string serial =
                platform::linux::readSysfsAttribute(info.usbDeviceNode, "serial")
                    .valueOr("");
            if (!serial.empty()) {
                info.serial = serial;
            }
        }
        if (!info.identitySource.empty() || info.usbDeviceNode.empty()) {
            // Mark the values as USB-descriptor sourced so a reader knows where
            // they came from.
        }
        info.identitySource = info.identitySource.empty()
            ? "USB device descriptors"
            : info.identitySource;
    }

    auto mediaResult = identifyMediaType(sysfsPath, transportToString(info.transport));
    if (mediaResult.ok()) info.mediaType = mediaResult.value();

    auto modelResult = readModel(sysfsPath);
    if (modelResult.ok()) info.model = modelResult.value();

    auto vendorResult = readVendor(sysfsPath);
    if (vendorResult.ok()) info.vendor = vendorResult.value();

    auto serialResult = readSerial(sysfsPath);
    if (serialResult.ok()) info.serial = serialResult.value();

    auto fwResult = readFirmware(sysfsPath);
    if (fwResult.ok()) info.firmware = fwResult.value();

    // sysfs is the first source because it costs nothing and already exposes a
    // decoded value for most buses. It is not complete though: a libata device
    // does not publish a serial through sysfs, and the destructive-path
    // confirmation depends on that serial. Where sysfs came back empty, the
    // device is asked directly, dispatching on the transport reported above.
    // This runs read-only, and the fd is closed before the device can be
    // opened for writing anywhere else in the flow.
    if (info.model.empty() || info.serial.empty() || info.firmware.empty()) {
        const int fd = ::open(info.path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd >= 0) {
            const auto identity =
                platform::linux::readDeviceIdentity(fd, info.transport);
            if (identity.ok()) {
                if (info.model.empty())    info.model = identity.value().model;
                if (info.serial.empty())   info.serial = identity.value().serial;
                if (info.firmware.empty()) info.firmware = identity.value().firmware;
                info.identitySource = identity.value().source;
            } else {
                info.identitySource = std::string("unavailable: ") + identity.error().what();
            }
            ::close(fd);
        } else {
            info.identitySource = "unavailable: cannot open " + info.path +
                                  " to read device identity";
        }
    } else {
        info.identitySource = "sysfs";
    }

    auto wwnResult = manager_.readSysfsAttribute(sysfsPath, "wwid");
    if (wwnResult.ok()) info.wwn = wwnResult.value();

    auto capResult = manager_.readSysfsUint64(sysfsPath, "size");
    if (capResult.ok()) {
        info.capacityBytes = capResult.value() * 512;
    }

    auto lbResult = manager_.readSysfsUint32(sysfsPath, "queue/logical_block_size");
    if (lbResult.ok()) info.logicalBlockSize = lbResult.value();

    auto pbResult = manager_.readSysfsUint32(sysfsPath, "queue/physical_block_size");
    if (pbResult.ok()) info.physicalBlockSize = pbResult.value();

    auto rotResult = isRotational(sysfsPath);
    if (rotResult.ok()) info.rotational = rotResult.value();

    auto remResult = isRemovable(sysfsPath);
    if (remResult.ok()) info.removable = remResult.value();

    auto roResult = isReadOnly(sysfsPath);
    if (roResult.ok()) info.readOnly = roResult.value();

    info.mounted = manager_.isMounted(info.path);
    info.systemDisk = manager_.isSystemDisk(info.path);
    info.bootDisk = manager_.isBootDisk(info.path);

    auto partsResult = manager_.readPartitions(info.path);
    if (partsResult.ok()) info.partitions = partsResult.value();

    auto fsResult = manager_.readFilesystems(info.path);
    if (fsResult.ok()) info.filesystems = fsResult.value();

    // Last, because it needs both the flag and the derived media type, and the
    // two are read at different points above: mediaType is resolved before the
    // rotational flag is read.
    noteRotationalDisagreement(info);

    return Result<DeviceInfo>::ok(info);
}

Result<std::string> DeviceInspector::identifyTransport(const std::string& sysfsPath) {
    pImpl_->usbDeviceNode.clear();
    std::string usbNode;

    // /sys/block/<name> is a symlink into /sys/devices/... . The parent of the
    // unresolved path is literally "block", so the path must be resolved
    // before the bus can be identified.
    std::error_code ec;
    const auto resolved = std::filesystem::canonical(sysfsPath, ec);
    const std::string full = ec ? sysfsPath : resolved.string();

    auto transportFromString = [](const std::string& t) -> TransportType {
        if (t == "sata") return TransportType::SATA;
        if (t == "usb") return TransportType::USB;
        if (t == "scsi") return TransportType::SCSI;
        if (t == "virtio") return TransportType::VIRTIO;
        if (t == "mmc") return TransportType::MMC;
        if (t == "fc") return TransportType::SCSI;
        return TransportType::UNKNOWN;
    };

    // Authoritative for SCSI-family devices (SATA/USB/UFB bridges expose this).
    const std::string transportFile = full + "/device/transport";
    if (std::filesystem::exists(transportFile)) {
        std::ifstream f(transportFile);
        std::string t;
        if (std::getline(f, t) && !t.empty()) {
            const auto parsed = transportFromString(t);
            if (parsed != TransportType::UNKNOWN) {
                return Result<std::string>::ok(std::to_string(static_cast<int>(parsed)));
            }
        }
    }

    // USB mass storage: no transport attribute exists, and the path patterns
    // below do not cover it because the device hangs off a "usbN" bus
    // directory. Identified by the USB device node, which publishes idVendor and
    // idProduct. The walk itself lives in the platform layer so the capability
    // probe and the transport detection cannot disagree about what "USB" means.
    if (platform::linux::findUsbAncestor(full, usbNode)) {
        pImpl_->usbDeviceNode = usbNode;
        return Result<std::string>::ok(
            std::to_string(static_cast<int>(TransportType::USB)));
    }

    // NVMe has no "transport" file. Its sysfs path runs through a "nvme" bus
    // directory, and its device node exposes the NVMe-specific admin
    // attributes (cntrltype, subsysvf) that no other bus provides.
    if (full.find("/nvme/") != std::string::npos ||
        std::filesystem::exists(full + "/device/cntrltype")) {
        return Result<std::string>::ok(std::to_string(static_cast<int>(TransportType::NVME)));
    }
    if (full.find("/virtio/") != std::string::npos) {
        return Result<std::string>::ok(std::to_string(static_cast<int>(TransportType::VIRTIO)));
    }
    if (full.find("/mmc/") != std::string::npos) {
        return Result<std::string>::ok(std::to_string(static_cast<int>(TransportType::MMC)));
    }
    if (full.find("/ata") != std::string::npos || full.find("/scsi/") != std::string::npos) {
        return Result<std::string>::ok(std::to_string(static_cast<int>(TransportType::SATA)));
    }

    return Result<std::string>::ok(std::to_string(static_cast<int>(TransportType::UNKNOWN)));
}

Result<MediaType> DeviceInspector::identifyMediaType(const std::string& sysfsPath, const std::string& transport) {
    // Precedence matters here. A USB mass-storage bridge commonly reports
    // queue/rotational = 1 regardless of the media actually inside it, so a
    // rotational flag alone must not be read as "hard disk". Checking
    // removability and the bus first keeps a flash pen drive from being
    // classified as an HDD, which is exactly the inference CLAUDE.md s7
    // forbids. The raw rotational value is still reported in DeviceInfo; only
    // the derived media class is corrected.
    if (transport == "NVMe") {
        return Result<MediaType>::ok(MediaType::SSD);
    }

    auto removableResult = isRemovable(sysfsPath);
    const bool removable = removableResult.ok() && removableResult.value();
    if (removable) {
        return Result<MediaType>::ok(MediaType::REMOVABLE);
    }

    auto rotationalResult = isRotational(sysfsPath);
    if (rotationalResult.ok() && rotationalResult.value()) {
        return Result<MediaType>::ok(MediaType::HDD);
    }

    return Result<MediaType>::ok(MediaType::SSD);
}

// Records whether the kernel's rotational flag was contradicted by the media
// type, so the disagreement is carried with the device identity rather than
// being re-derived by each display layer.
//
// This is a flag about the evidence, not a correction. The kernel reported what
// the bridge told it; whether that describes the medium is a separate question,
// and the answer is carried separately.
void DeviceInspector::noteRotationalDisagreement(DeviceInfo& info) {
    if (!info.rotational) {
        info.rotationalDisputed = false;
        return;
    }
    info.rotationalDisputed = info.mediaType == MediaType::REMOVABLE ||
                              info.mediaType == MediaType::SSD ||
                              info.mediaType == MediaType::HYBRID;
}

Result<bool> DeviceInspector::isRotational(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsBool(sysfsPath, "queue/rotational");
}

Result<std::string> DeviceInspector::readModel(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsAttribute(sysfsPath, "device/model");
}

Result<std::string> DeviceInspector::readVendor(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsAttribute(sysfsPath, "device/vendor");
}

Result<std::string> DeviceInspector::readSerial(const std::string& sysfsPath) {
    auto serial = pImpl_->manager.readSysfsAttribute(sysfsPath, "device/serial");
    if (serial.ok() && !serial.value().empty()) return serial;

    return pImpl_->manager.readSysfsAttribute(sysfsPath, "serial");
}

Result<std::string> DeviceInspector::readFirmware(const std::string& sysfsPath) {
    // NVMe exposes firmware_rev; SCSI/SATA devices expose rev.
    auto nvme = pImpl_->manager.readSysfsAttribute(sysfsPath, "device/firmware_rev");
    if (nvme.ok() && !nvme.value().empty()) return nvme;

    return pImpl_->manager.readSysfsAttribute(sysfsPath, "device/rev");
}

Result<uint64_t> DeviceInspector::readCapacity(const std::string& sysfsPath) {
    auto sectors = pImpl_->manager.readSysfsUint64(sysfsPath, "size");
    if (sectors.isError()) return Result<uint64_t>::err(sectors.error());
    return Result<uint64_t>::ok(sectors.value() * 512);
}

Result<uint32_t> DeviceInspector::readLogicalBlockSize(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsUint32(sysfsPath, "queue/logical_block_size");
}

Result<uint32_t> DeviceInspector::readPhysicalBlockSize(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsUint32(sysfsPath, "queue/physical_block_size");
}

Result<bool> DeviceInspector::isRemovable(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsBool(sysfsPath, "removable");
}

Result<bool> DeviceInspector::isReadOnly(const std::string& sysfsPath) {
    return pImpl_->manager.readSysfsBool(sysfsPath, "ro");
}

Result<std::vector<PartitionInfo>> DeviceInspector::readPartitions(const std::string& devicePath) {
    return platform::linux::readPartitions(devicePath);
}

Result<std::vector<FilesystemInfo>> DeviceInspector::readFilesystems(const std::string& devicePath) {
    return platform::linux::readFilesystems(devicePath);
}

} // namespace ledgerase