#include "ledgerase/safety.hpp"
#include "platform/linux/linux.hpp"
#include <iostream>
#include <string>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

namespace ledgerase {

class SafetyManager::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

SafetyManager::SafetyManager() : pImpl_(std::make_unique<Impl>()) {}
SafetyManager::~SafetyManager() = default;

void SafetyReport::addCheck(const SafetyCheck& check) {
    checks.push_back(check);
    if (check.result == SafetyCheckResult::FAIL) {
        overallPass = false;
        if (check.critical) hasCriticalFailure = true;
    }
}

void SafetyReport::addCheck(const std::string& name, SafetyCheckResult result,
                            const std::string& message, const std::string& recommendation,
                            bool critical) {
    SafetyCheck check;
    check.name = name;
    check.result = result;
    check.message = message;
    check.recommendation = recommendation;
    check.critical = critical;
    addCheck(check);
}

namespace {

// How a read-only determination was reached, in words an operator can act on.
//
// Named in the check's message rather than collapsed into a boolean because the
// sources differ in what they establish. BLKROGET is the device answering for
// itself. sysfs is the kernel's published attribute, which is right but does not
// require permission to open the device. A regular file is neither - it is a
// disk image, which has no read-only flag at all, and what was checked is
// whether the file can be written.
std::string readOnlySourceName(platform::linux::ReadOnlySource source) {
    switch (source) {
        case platform::linux::ReadOnlySource::BLKROGET_IOCTL:
            return "BLKROGET on the opened device";
        case platform::linux::ReadOnlySource::SYSFS:
            return "sysfs /sys/block/*/ro, which needs no permission to open "
                   "the device";
        case platform::linux::ReadOnlySource::REGULAR_FILE:
            return "a direct writability check - this target is a regular "
                   "file (a disk image), which has no block-device read-only "
                   "flag";
        case platform::linux::ReadOnlySource::UNDETERMINED:
            break;
    }
    return "no source could establish it";
}

} // namespace

Result<SafetyReport> SafetyManager::checkDeviceSafety(const std::string& devicePath,
                                                       bool requireUnmounted,
                                                       bool allowSystemDisk) {
    SafetyReport report;

    // Note on the two parameters.
    //
    // requireUnmounted=false relaxes only the mount check, and is not used by
    // the destructive path. allowSystemDisk exists so a non-destructive command
    // can inspect the running system disk; the sanitization path must never set
    // it, which is why checkPreSanitization() below hardcodes it to false
    // rather than taking it from the caller.
    if (!platform::linux::isMounted(devicePath) && !requireUnmounted) {
        report.addCheck("Mount Check", SafetyCheckResult::PASS,
                        "Device is not mounted", "", false);
    } else if (platform::linux::isMounted(devicePath)) {
        auto mountPoints = platform::linux::getMountPoints(devicePath);
        std::string mounts;
        for (const auto& mp : mountPoints) {
            if (!mounts.empty()) mounts += ", ";
            mounts += mp;
        }
        report.addCheck("Mount Check", SafetyCheckResult::FAIL,
                        "Device is mounted at: " + mounts,
                        "Unmount all partitions before sanitization",
                        true);
    }

    if (!allowSystemDisk && platform::linux::isSystemDisk(devicePath)) {
        report.addCheck("System Disk Check", SafetyCheckResult::FAIL,
                        "Device contains the active root filesystem",
                        "Cannot sanitize the system disk from the running OS",
                        true);
    } else {
        report.addCheck("System Disk Check", SafetyCheckResult::PASS,
                        "Device is not the system disk", "", false);
    }

    if (platform::linux::isBootDisk(devicePath)) {
        report.addCheck("Boot Disk Check", SafetyCheckResult::FAIL,
                        "Device is the boot device",
                        "Cannot sanitize the boot device from the running OS",
                        true);
    } else {
        report.addCheck("Boot Disk Check", SafetyCheckResult::PASS,
                        "Device is not the boot disk", "", false);
    }

    auto swapDevices = platform::linux::getActiveSwapDevices();
    bool onSwap = false;
    for (const auto& swap : swapDevices) {
        // deviceContains(), not a raw prefix compare. "/dev/sda" is a prefix of
        // both "/dev/sda1" (correctly flagged) and "/dev/sdaa" (a different
        // disk, which must not be), and the old test could not tell them apart.
        if (platform::linux::deviceContains(devicePath, swap)) {
            onSwap = true;
            break;
        }
    }
    if (onSwap) {
        report.addCheck("Swap Check", SafetyCheckResult::FAIL,
                        "Device is used for active swap",
                        "Disable swap before sanitization",
                        true);
    } else {
        report.addCheck("Swap Check", SafetyCheckResult::PASS,
                        "Device is not used for swap", "", false);
    }

    if (platform::linux::isDeviceMapperInUse(devicePath)) {
        report.addCheck("Device Mapper Check", SafetyCheckResult::WARNING,
                        "Device is used by device-mapper (LVM/dm-crypt)",
                        "Ensure no logical volumes are active on this device",
                        false);
    } else {
        report.addCheck("Device Mapper Check", SafetyCheckResult::PASS,
                        "Device is not used by device-mapper", "", false);
    }

    if (platform::linux::isLvmInUse(devicePath)) {
        report.addCheck("LVM Check", SafetyCheckResult::WARNING,
                        "Device appears to be part of an LVM volume group",
                        "Deactivate volume group before sanitization",
                        false);
    } else {
        report.addCheck("LVM Check", SafetyCheckResult::PASS,
                        "Device is not used by LVM", "", false);
    }

    if (platform::linux::isRaidInUse(devicePath)) {
        report.addCheck("RAID Check", SafetyCheckResult::WARNING,
                        "Device appears to be part of a RAID array",
                        "Stop RAID array before sanitization",
                        false);
    } else {
        report.addCheck("RAID Check", SafetyCheckResult::PASS,
                        "Device is not used by RAID", "", false);
    }

    // Whether *this process* can write to the device, asked of the kernel
    // rather than inferred from the mode bits.
    //
    // The previous version tested S_IWUSR, which asks whether the *owner* may
    // write. A root-owned block node is brw-rw----, so S_IWUSR is set for every
    // user and the check reported "write permission available" to a process
    // that could not open the device. That produced a report reading
    // "Permissions: PASS" beside "Read-Only: cannot open device" - two checks
    // about the same access, disagreeing, with no way for the operator to tell
    // which to believe.
    struct stat st;
    if (::stat(devicePath.c_str(), &st) != 0) {
        report.addCheck("Permissions Check", SafetyCheckResult::FAIL,
                        "Cannot stat the device: " +
                            std::string(std::strerror(errno)),
                        "Check the path", false);
    } else if (const auto writable = platform::linux::canOpenForWrite(devicePath);
               writable.ok() && writable.value()) {
        report.addCheck("Permissions Check", SafetyCheckResult::PASS,
                        "This process can open the device for writing", "",
                        false);
    } else {
        // Not critical on its own: running without the privilege to write is a
        // recoverable mistake, and making it critical here meant a forgotten
        // sudo and a genuinely mounted system disk produced the same abort.
        // It is not critical here, and the read-only check below now reports
        // the underlying errno, so an operator can see why.
        report.addCheck("Permissions Check", SafetyCheckResult::FAIL,
                        std::string("This process cannot open the device for "
                                    "writing") +
                            (writable.ok()
                                 ? std::string()
                                 : std::string(": ") + writable.error().what()),
                        "Run with appropriate privileges (sudo), or add the "
                        "operator to the group that owns the device node",
                        false);
    }

    // The read-only *state*, which is a different question from whether this
    // process may open the device, and which used to be answered by the open
    // alone.
    //
    // deviceReadOnlyStatus() tries BLKROGET first and then the sysfs attribute,
    // and reports which one answered. Previously this was `openDevice` and
    // nothing else, so an unprivileged operator on a perfectly writable drive
    // was told the device could not be checked at all, while `lsblk` on the
    // same machine reported RO=0 - and the errno that would have explained it
    // was discarded.
    {
        const platform::linux::ReadOnlyStatus ro =
            platform::linux::deviceReadOnlyStatus(devicePath);
        if (!ro.established) {
            // Fail closed. The state is genuinely unknown, and unknown is not
            // writable. The check stays a blocking one.
            report.addCheck("Read-Only Check", SafetyCheckResult::FAIL,
                            "Cannot determine the read-only state: " +
                                ro.diagnostic(),
                            "Both BLKROGET and the sysfs attribute were "
                            "unavailable. Do not proceed on an unknown state; "
                            "make the device node readable, or run with the "
                            "privilege to open it, and re-check.",
                            true);
        } else if (ro.readOnly) {
            report.addCheck("Read-Only Check", SafetyCheckResult::FAIL,
                            std::string("Target is read-only (established via ") +
                                readOnlySourceName(ro.source) + ")",
                            "Clear the hardware write-protect, or re-issue the "
                            "removable media as writable",
                            true);
        } else {
            // The state is established. The source is named so a reader knows
            // whether the device itself answered, whether the kernel's published
            // attribute did, or whether this is a disk image - a difference in
            // confidence, and in what the check actually established, that a
            // reader is entitled to see.
            report.addCheck("Read-Only Check", SafetyCheckResult::PASS,
                            "Target is writable (established via " +
                                readOnlySourceName(ro.source) + ")",
                            "", false);
        }
    }

    return Result<SafetyReport>::ok(report);
}

Result<SafetyReport> SafetyManager::checkSimulatedDeviceSafety(const DeviceInfo& device) {
    SafetyReport report;

    report.addCheck("Simulation Scope", SafetyCheckResult::WARNING,
                    "This is a simulated device. The safety checks below reflect the "
                    "state the mock device declares, NOT the state of the machine "
                    "this process is running on.",
                    "Do not read this report as a statement about any real hardware. "
                    "It exists to demonstrate the decision logic.",
                    false);

    if (device.path.empty()) {
        report.addCheck("Target", SafetyCheckResult::FAIL,
                        "No device path was supplied",
                        "There is nothing to sanitize", true);
        return Result<SafetyReport>::ok(report);
    }

    report.addCheck("Mount Check",
                    device.mounted ? SafetyCheckResult::FAIL : SafetyCheckResult::PASS,
                    device.mounted ? "The simulated device is mounted" : "not mounted",
                    "", device.mounted);

    report.addCheck("System Disk Check",
                    device.systemDisk ? SafetyCheckResult::FAIL : SafetyCheckResult::PASS,
                    device.systemDisk ? "The simulated device is the system disk"
                                       : "not the system disk",
                    "", device.systemDisk);

    report.addCheck("Boot Disk Check",
                    device.bootDisk ? SafetyCheckResult::FAIL : SafetyCheckResult::PASS,
                    device.bootDisk ? "The simulated device is the boot disk"
                                     : "not the boot disk",
                    "", device.bootDisk);

    report.addCheck("Read-Only Check",
                    device.readOnly ? SafetyCheckResult::FAIL : SafetyCheckResult::PASS,
                    device.readOnly ? "The simulated device is read-only" : "writable",
                    "", device.readOnly);

    // The identity confirmation cannot be performed against a device that does
    // not exist, so it is recorded as unattested rather than assumed. The mock
    // profiles carry a serial, so a demo run can show the real confirmation
    // flow; one that carries none is refused by the confirmation itself.
    if (device.serial.empty()) {
        report.addCheck("Identity Confirmation", SafetyCheckResult::FAIL,
                        "The simulated device declares no serial, so the operator "
                        "cannot confirm the target by serial suffix",
                        "Use --force to stand in for the confirmation in a demo, "
                        "knowing that nothing was actually confirmed", true);
    } else {
        report.addCheck("Identity Confirmation", SafetyCheckResult::PASS,
                        "The simulated device declares a serial (" + device.serial +
                            "), so the confirmation prompt can be answered",
                        "", false);
    }

    return Result<SafetyReport>::ok(report);
}

Result<SafetyReport> SafetyManager::addPlanChecks(const SafetyReport& basic,
                                                    const DeviceInfo& device,
                                                    const CapabilityInfo& capabilities,
                                                    SanitizationCategory category [[maybe_unused]],
                                                    SanitizationMethod method) {
    SafetyReport report = basic;

    if (method == SanitizationMethod::UNSUPPORTED) {
        report.addCheck("Method Support", SafetyCheckResult::FAIL,
                        "Selected sanitization method is not supported by this device",
                        "Choose a supported method or use a different device",
                        true);
    }

    if (device.systemDisk || device.bootDisk) {
        report.addCheck("Critical Device", SafetyCheckResult::FAIL,
                        "Target is system or boot disk",
                        "Cannot sanitize system/boot disk from running OS",
                        true);
    }

    if (!capabilities.limitations.empty()) {
        for (const std::string& lim : capabilities.limitations.texts()) {
            report.addCheck("Capability Limitation", SafetyCheckResult::WARNING,
                            lim, "Review device capabilities before proceeding", false);
        }
    }

    return Result<SafetyReport>::ok(report);
}

Result<SafetyReport> SafetyManager::checkPreSanitization(const DeviceInfo& device,
                                                           const CapabilityInfo& capabilities,
                                                           SanitizationCategory category,
                                                           SanitizationMethod method) {
    auto basicResult = checkDeviceSafety(device.path, true, false);
    if (basicResult.isError()) {
        return Result<SafetyReport>::err(basicResult.error());
    }
    return addPlanChecks(basicResult.value(), device, capabilities, category,
                         method);
}

Result<void> SafetyManager::verifyDeviceIdentity(const DeviceInfo& device,
                                                  const std::string& expectedSerialSuffix) {
    if (device.serial.size() < static_cast<size_t>(expectedSerialSuffix.size())) {
        return Result<void>::err(ErrorCode::CONFIRMATION_FAILED,
                                "Device serial too short for verification");
    }

    std::string actualSuffix = device.serial.substr(device.serial.size() - expectedSerialSuffix.size());
    if (actualSuffix != expectedSerialSuffix) {
        return Result<void>::err(ErrorCode::CONFIRMATION_FAILED,
                                "Serial number suffix does not match. Expected: " + expectedSerialSuffix +
                                ", Got: " + actualSuffix,
                                "Verify you have selected the correct device");
    }

    return Result<void>::success();
}

std::vector<std::string> SafetyManager::getActiveSwapDevices() {
    return platform::linux::getActiveSwapDevices();
}

bool SafetyManager::isDeviceMapperInUse(const std::string& devicePath) {
    return platform::linux::isDeviceMapperInUse(devicePath);
}

bool SafetyManager::isLvmInUse(const std::string& devicePath) {
    return platform::linux::isLvmInUse(devicePath);
}

bool SafetyManager::isRaidInUse(const std::string& devicePath) {
    return platform::linux::isRaidInUse(devicePath);
}

class ConfirmationManager::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

ConfirmationManager::ConfirmationManager() : pImpl_(std::make_unique<Impl>()) {}
ConfirmationManager::~ConfirmationManager() = default;

// The final path component of a target path, which is what an operator reads
// off the screen to confirm they picked the right file.
std::string basenameOf(const std::string& path) {
    const std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

Result<void> ConfirmationManager::requireTargetConfirmation(
    const DeviceInfo& device,
    ConfirmationBasis basis,
    int requiredSuffixLength,
    const std::string& expectedSerial,
    const std::string& expectedName) {
    // Asked of the filesystem, not guessed from the path.
    //
    // This used to be `path.rfind("/dev/", 0) == 0`, which treats every
    // directory under /dev as a block device: /dev/shm, /dev/mnt, /dev/pts, and
    // any folder a user made there. `ledgerase-cli erase-folder /dev/shm/x`
    // therefore demanded a serial for a directory, and refused with advice
    // about reading a serial off a drive label. Found by running the command
    // rather than by reading the code - the tests used a temporary directory
    // that does not live under /dev.
    //
    // An explicit basis from the caller still wins: a caller that knows the
    // target is a device says so, and this is only the fallback for callers
    // that did not.
    bool isBlockDevice = false;
    if (!device.path.empty()) {
        struct stat st {};
        if (::stat(device.path.c_str(), &st) == 0) {
            isBlockDevice = S_ISBLK(st.st_mode);
        } else {
            // The path could not be read. Fall back to the path shape rather
            // than silently treating an unreadable /dev node as a file, where
            // it would be confirmed by its name.
            isBlockDevice = device.path.rfind("/dev/", 0) == 0 &&
                            !DeviceManager::isDiskImage(device.path);
        }
    }

    if (basis == ConfirmationBasis::SERIAL_SUFFIX || isBlockDevice) {
        // --expect-serial is the non-interactive form of the same check.
        if (!expectedSerial.empty()) {
            if (device.serial.empty()) {
                return Result<void>::err(
                    ErrorCode::CONFIRMATION_FAILED,
                    "--expect-serial was given but no serial was established for " +
                        device.path,
                    "A block device is confirmed by its serial. Either drop "
                    "--expect-serial to be prompted, or supply a device whose "
                    "serial this tool can read.");
            }
            if (device.serial != expectedSerial) {
                return Result<void>::err(
                    ErrorCode::CONFIRMATION_FAILED,
                    "--expect-serial does not match the device: expected '" +
                        expectedSerial + "', the device reports '" + device.serial +
                        "'",
                    "Operation cancelled for safety.");
            }
            return Result<void>::success();
        }
        return requireSerialConfirmation(device, requiredSuffixLength);
    }

    // A file or an image. It has no serial, so the name is the confirmation.
    const std::string name = basenameOf(device.path);

    std::cout << "\n=== FILE CONFIRMATION REQUIRED ===\n";
    std::cout << "Target:   " << device.path << "\n";
    if (device.capacityBytes > 0) {
        std::cout << "Size:     " << device.capacityBytes << " bytes\n";
    }
    if (!device.model.empty()) {
        std::cout << "Model:    " << device.model << "\n";
    }
    std::cout << "\nTHIS OPERATION IS IRREVERSIBLE.\n";

    if (name.empty()) {
        return Result<void>::err(
            ErrorCode::CONFIRMATION_FAILED,
            "The target has no file name to confirm: " + device.path,
            "Name the file explicitly and re-run.");
    }

    if (!expectedName.empty()) {
        // The non-interactive form. Compared in full, because a file name is
        // short and the point is to catch a wrong path, not to make typing
        // tedious.
        if (expectedName != name) {
            return Result<void>::err(
                ErrorCode::CONFIRMATION_FAILED,
                "--expect-name does not match the target: expected '" +
                    expectedName + "', the target is '" + name + "'",
                "The target is a file, so it is confirmed by its name. Use "
                "--expect-name with the name of the file you intend to erase.");
        }
        return Result<void>::success();
    }

    std::cout << "Type the file name to confirm: " << name << "\n";
    std::cout << "> ";

    std::string input;
    if (!std::getline(std::cin, input)) {
        return Result<void>::err(ErrorCode::CONFIRMATION_FAILED,
                                 "No confirmation was entered",
                                 "Operation cancelled for safety");
    }
    while (!input.empty() && (input.back() == '\r' || input.back() == ' ')) {
        input.pop_back();
    }
    if (input != name) {
        return Result<void>::err(
            ErrorCode::CONFIRMATION_FAILED,
            "The typed name does not match the target's name",
            "Operation cancelled for safety. The target is '" + name + "'.");
    }
    return Result<void>::success();
}

Result<void> ConfirmationManager::requireSerialConfirmation(const DeviceInfo& device,
                                                              int requiredSuffixLength) {
    std::cout << "\n=== DEVICE CONFIRMATION REQUIRED ===\n";
    std::cout << "Device: " << device.path << "\n";
    std::cout << "Model:  " << device.model << "\n";
    std::cout << "Serial: " << (device.serial.empty() ? "<NOT ESTABLISHED>" : device.serial) << "\n";
    std::cout << "Capacity: " << (device.capacityBytes / (1024*1024*1024)) << " GB\n";
    std::cout << "\nTHIS OPERATION IS IRREVERSIBLE.\n";

    // Refuse before asking, rather than after.
    //
    // This confirmation exists to prove the operator selected the disk they
    // meant, and it does that by requiring a value only the target device can
    // supply. If no serial was established, the prompt cannot do its job: there
    // is nothing meaningful to type. The previous code computed
    // serial.substr(serial.size() - 6) unconditionally, which for a short or
    // empty serial underflows the length and throws, and which for a serial of
    // exactly the prompted length would reduce to "type the whole serial",
    // trivially readable off the screen above the prompt.
    //
    // So: an unestablished serial blocks the destructive path. The operator has
    // to establish the identity another way, and --force does not help here,
    // because the check it bypasses is not the one that would otherwise stand in
    // the way of a missing serial.
    if (device.serial.empty()) {
        return Result<void>::err(
            ErrorCode::CONFIRMATION_FAILED,
            "No device serial was established for " + device.path +
                ", so the target cannot be confirmed by serial suffix. This check is "
                "what proves the selected disk is the intended disk, so it is not "
                "skipped when the serial is missing.",
            "This is a block device, so it is confirmed by its serial. Read the "
            "serial from the drive label, or use a device whose identity this tool "
            "can read. --force does not bypass this check, because the check is "
            "what proves the intended disk was selected. If the target is a file "
            "or an image rather than a device, it is confirmed by its name "
            "instead, with --expect-name.");
    }
    if (requiredSuffixLength <= 0 ||
        device.serial.size() < static_cast<size_t>(requiredSuffixLength)) {
        return Result<void>::err(
            ErrorCode::CONFIRMATION_FAILED,
            "The device serial is " + std::to_string(device.serial.size()) +
                " characters, which is too short to confirm by its last " +
                std::to_string(requiredSuffixLength) + " characters",
            "Use --serial-suffix <n> with a smaller n, or establish a longer serial");
    }

    std::cout << "Enter the last " << requiredSuffixLength
              << " characters of the serial number to confirm:\n";
    std::cout << "> ";

    std::string input;
    if (!std::getline(std::cin, input)) {
        return Result<void>::err(ErrorCode::CONFIRMATION_FAILED,
                                 "No confirmation was entered",
                                 "Operation cancelled for safety");
    }
    // Trailing whitespace from a copy-paste is not part of the serial.
    while (!input.empty() && (input.back() == '\r' || input.back() == ' ')) {
        input.pop_back();
    }

    const std::string expected =
        device.serial.substr(device.serial.size() - static_cast<size_t>(requiredSuffixLength));
    if (input != expected) {
        return Result<void>::err(ErrorCode::CONFIRMATION_FAILED,
                                 "Serial suffix does not match",
                                 "Operation cancelled for safety");
    }

    return Result<void>::success();
}

} // namespace ledgerase