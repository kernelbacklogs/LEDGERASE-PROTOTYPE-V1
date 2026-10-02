#include "ledgerase/platform/linux.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <blkid.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <cctype>

namespace ledgerase::platform::linux {

bool deviceContains(const std::string& parent, const std::string& child) {
    if (parent.empty() || child.empty()) {
        return false;
    }
    if (parent == child) {
        return true;
    }
    if (child.size() <= parent.size() ||
        child.compare(0, parent.size(), parent) != 0) {
        return false;
    }

    // The kernel picks one partition-naming convention per device, and which
    // one depends on whether the device name already ends in a digit. Both must
    // be honoured, because only one of them applies to any given disk:
    //
    //   name ends in a digit  ->  nvme0n1  partitions are nvme0n1p1
    //   name ends otherwise   ->  sda      partitions are sda1
    //
    // Honouring only the 'p' form is what made /dev/sda invisible to the safety
    // layer: a mounted, root or boot /dev/sda1 was not recognised as living on
    // /dev/sda, so the target could be destroyed while live.
    //
    // Getting the other direction wrong is just as dangerous. A naive "suffix is
    // digits" test would accept /dev/nvme0n10 as a partition of /dev/nvme0n1;
    // it is a separate disk. The trailing-digit check is what separates them.
    const char next = child[parent.size()];
    const bool parentEndsInDigit =
        parent.back() >= '0' && parent.back() <= '9';

    if (parentEndsInDigit) {
        // p-form: at least 'p' followed by at least one digit.
        if (next != 'p' || child.size() < parent.size() + 2) {
            return false;
        }
        for (std::size_t i = parent.size() + 1; i < child.size(); ++i) {
            if (child[i] < '0' || child[i] > '9') return false;
        }
        return true;
    }

    // digit form: the separator is the first character of the suffix, which
    // must itself be a digit. This rejects /dev/sdaa for /dev/sda while
    // accepting /dev/sda1, /dev/hda2 and /dev/vdb3.
    if (next < '0' || next > '9') {
        return false;
    }
    for (std::size_t i = parent.size(); i < child.size(); ++i) {
        if (child[i] < '0' || child[i] > '9') return false;
    }
    return true;
}


Result<int> openDevice(const std::string& path, bool readOnly) {
    int flags = readOnly ? O_RDONLY : O_RDWR;
    flags |= O_CLOEXEC | O_NONBLOCK;
    int fd = ::open(path.c_str(), flags);
    if (fd < 0) {
        return Result<int>::err(SanitizerError::fromErrno(errno, "Failed to open device " + path));
    }
    return Result<int>::ok(fd);
}

void closeDevice(int fd) {
    if (fd >= 0) {
        ::close(fd);
    }
}

Result<uint64_t> getBlockDeviceSize(int fd) {
    uint64_t size = 0;
    if (ioctl(fd, BLKGETSIZE64, &size) == 0) {
        return Result<uint64_t>::ok(size);
    }

    const int saved = errno;

    // Not a block device. A regular file is accepted deliberately: this project
    // is required to be able to sanitize disk images (tests/*.img, and whatever
    // directory the operator points it at), and a host overwrite of an image
    // file is the same operation as a host overwrite of a device. Refusing here
    // would make image-based testing impossible.
    //
    // The size is still established rather than assumed, which is the property
    // that matters: an overwrite of the wrong length is how a disk ends up
    // partly erased and reported as clean.
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        return Result<uint64_t>::ok(static_cast<uint64_t>(st.st_size));
    }

    return Result<uint64_t>::err(
        ErrorCode::IO_ERROR,
        std::string("Failed to get device size: ") + std::strerror(saved),
        "The target is neither a block device nor a regular file, so its size "
        "cannot be established. Refusing to run an overwrite whose length would "
        "be a guess.");
}

Result<uint32_t> getLogicalBlockSize(int fd) {
    uint32_t size = 0;
    if (ioctl(fd, BLKSSZGET, &size) < 0) {
        return Result<uint32_t>::err(SanitizerError::fromErrno(errno, "Failed to get logical block size"));
    }
    return Result<uint32_t>::ok(size);
}

Result<uint32_t> getPhysicalBlockSize(int fd) {
    uint32_t size = 0;
    if (ioctl(fd, BLKPBSZGET, &size) < 0) {
        return Result<uint32_t>::err(SanitizerError::fromErrno(errno, "Failed to get physical block size"));
    }
    return Result<uint32_t>::ok(size);
}

Result<bool> isRotational(int fd) {
    int rotational = 0;
    if (ioctl(fd, BLKROTATIONAL, &rotational) < 0) {
        return Result<bool>::err(SanitizerError::fromErrno(errno, "Failed to get rotational status"));
    }
    return Result<bool>::ok(rotational != 0);
}

Result<bool> isReadOnly(int fd) {
    int readonly = 0;
    if (ioctl(fd, BLKROGET, &readonly) < 0) {
        return Result<bool>::err(SanitizerError::fromErrno(errno, "Failed to get read-only status"));
    }
    return Result<bool>::ok(readonly != 0);
}

std::string ReadOnlyStatus::diagnostic() const {
    if (established) {
        return readOnly ? "the device reports itself read-only"
                        : "the device reports itself writable";
    }
    // Every reason is named, not just the first. An operator reading this needs
    // to know that two independent attempts were made and why each failed,
    // otherwise "cannot open" sends them to fix the wrong thing.
    std::string out = "the read-only state could not be established";
    if (!openError.empty()) {
        out += "; opening the device node failed: " + openError;
    }
    if (!ioctlError.empty()) {
        out += "; BLKROGET failed: " + ioctlError;
    }
    if (!sysfsError.empty()) {
        out += "; sysfs read-only attribute unavailable: " + sysfsError;
    }
    return out;
}

ReadOnlyStatus deviceReadOnlyStatus(const std::string& devicePath,
                                    const std::string& sysfsBase) {
    ReadOnlyStatus status;

    // Source 1: the authoritative one, identical to `blockdev --getro`.
    //
    // The open is done here rather than through openDevice() so that errno is
    // read immediately after the syscall that set it. Calling openDevice() and
    // then reading errno looked equivalent and was not: openDevice() builds a
    // SanitizerError from errno, and the string handling inside that overwrote
    // it, so the recorded code was whatever the error formatting left behind -
    // frequently 0. A diagnostic that reports "0: Success" for a permission
    // failure is worse than no diagnostic, because it looks authoritative.
    const int fd = ::open(devicePath.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        const int openErrno = errno;
        status.openError = "open(" + devicePath + ", O_RDONLY) failed: " +
                           std::to_string(openErrno) + ": " +
                           std::strerror(openErrno);
    } else {
        int readonly = 0;
        if (ioctl(fd, BLKROGET, &readonly) == 0) {
            status.established = true;
            status.readOnly = readonly != 0;
            status.source = ReadOnlySource::BLKROGET_IOCTL;
            ::close(fd);
            return status;
        }
        // The descriptor opened but the query did not. That is a different
        // failure from "cannot open", and it is kept as its own field so the two
        // are never reported as one.
        const int ioctlErrno = errno;
        status.ioctlError = "BLKROGET failed: " +
                            std::to_string(ioctlErrno) + ": " +
                            std::strerror(ioctlErrno);
        ::close(fd);
    }

    // A disk image is not a block device. BLKROGET returned ENOTTY and there is
    // no sysfs entry, so neither block source can answer - and the right answer
    // is not "unknown", it is a different question: can this file be written.
    {
        struct stat st {};
        if (::stat(devicePath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            const auto writable = canOpenForWrite(devicePath);
            // A file that cannot be written is a definite, actionable fact, not
            // an unknown. Reporting it as "read-only" for a regular file is the
            // only sense "read-only" has for one, and it blocks the run the same
            // way an unknown would - while telling the operator what is actually
            // wrong, and letting the Permissions Check carry the errno.
            status.established = true;
            status.source = ReadOnlySource::REGULAR_FILE;
            status.readOnly = !writable.ok() || !writable.value();
            if (!writable.ok()) {
                status.openError = writable.error().what();
            }
            return status;
        }
    }

    // Source 2: the one that works without permission to open the device.
    //
    // This is not a weaker guess. /sys/block/<name>/ro is the same attribute the
    // kernel uses to implement the block device's read-only state, it is what
    // lsblk reports as RO=, and it is mode 0444, so it answers the question for
    // an unprivileged operator on a device node they cannot open. That is
    // exactly the case the ioctl path got wrong.
    const std::string sysfsPath = findSysfsPath(devicePath, sysfsBase);
    if (sysfsPath.empty()) {
        status.sysfsError = "no sysfs entry for " + devicePath + " under " +
                            sysfsBase + " (the device may not be a block device)";
    } else {
        const auto ro = readSysfsBool(sysfsPath, "ro");
        if (ro.ok()) {
            status.established = true;
            status.readOnly = ro.value();
            status.source = ReadOnlySource::SYSFS;
            return status;
        }
        status.sysfsError = sysfsPath + "/ro: " + ro.error().what();
    }

    // Neither source answered. `established` stays false and the caller fails
    // closed. Nothing here defaults to writable.
    return status;
}

Result<bool> canOpenForWrite(const std::string& path) {
    // faccessat(AT_EACCESS) asks the kernel the question the operator actually
    // has - can *this* process open this for writing - and applies the same
    // rules open(2) would, including ACLs and capabilities, which a mode-bit
    // test cannot see.
    if (::faccessat(AT_FDCWD, path.c_str(), W_OK, AT_EACCESS) == 0) {
        return Result<bool>::ok(true);
    }
    const int accessErrno = errno;

    // The permission model can still disagree with reality - a device cgroup, a
    // mount namespace, a udev rule. The only authority for "can I open this for
    // writing" is opening it, so when the model says no, confirm by trying. The
    // descriptor is closed again immediately: this establishes the fact, it does
    // not hold the device open.
    const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        ::close(fd);
        return Result<bool>::ok(true);
    }
    // Report the errno from the open, not from faccessat: the open is the
    // operation that decides the question.
    // The numeric errno is put in the message, not only the text. fromErrno
    // classifies the error and attaches a recommended action, but the message it
    // builds is the context string alone - so without this the safety report
    // says "Permission denied" and never "13", which is what the operator needs
    // to match it against dmesg or a strace.
    return Result<bool>::err(SanitizerError::fromErrno(
        errno, "Cannot open " + path + " for writing: " + std::to_string(errno) +
                   ": " + std::strerror(errno) + " (faccessat reported " +
                   std::to_string(accessErrno) + ": " +
                   std::strerror(accessErrno) + ")"));
}

bool descriptorIsWritable(int fd) {
    if (fd < 0) {
        return false;
    }
    // fcntl(F_GETFL) reports the access mode the descriptor was actually opened
    // with, which is the ground truth for this descriptor and needs no second
    // open.
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0) {
        return false;
    }
    const int accMode = flags & O_ACCMODE;
    return accMode == O_WRONLY || accMode == O_RDWR;
}

std::string trimDeviceString(const char* raw, std::size_t length) {
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length && raw[i] != '\0'; ++i) {
        out.push_back(raw[i]);
    }
    while (!out.empty() && (out.back() == ' ' || out.back() == '\0')) {
        out.pop_back();
    }
    return out;
}

namespace detail {
// Decodes the octal escapes the kernel writes into mountinfo fields.
//
// The kernel escapes four characters as \040 (space), \011 (tab), \012 (newline)
// and \134 (backslash). This is not cosmetic here. The *source* field is the
// device, and a device reached through a label or UUID routinely contains a
// space:
//
//     /dev/disk/by-label/My\040Backup\040Disk  /srv ext4 ...
// left undecoded, that string matches no real /dev node, so a genuinely mounted
// device can be reported as not mounted - which is precisely the mistake that
// lets the safety layer wave through a target that is in active use.
//
// Returns the decoded string.
std::string decodeMountInfoEscapes(const std::string& field) {
    std::string out;
    out.reserve(field.size());
    for (std::size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 3 < field.size() &&
            field[i + 1] >= '0' && field[i + 1] <= '3' &&
            field[i + 2] >= '0' && field[i + 2] <= '7' &&
            field[i + 3] >= '0' && field[i + 3] <= '7') {
            const int value = (field[i + 1] - '0') * 64 +
                              (field[i + 2] - '0') * 8 +
                              (field[i + 3] - '0');
            out.push_back(static_cast<char>(value));
            i += 3;
        } else {
            out.push_back(field[i]);
        }
    }
    return out;
}

} // namespace detail

namespace {

// ATA IDENTIFY DEVICE, via HDIO_GET_IDENTITY.
//
// On byte order: the ATA string fields are stored with the two bytes of each
// 16-bit word reversed, but the kernel already undoes that before the data
// reaches user space. ata_get_identity() in drivers/ata/libata-scsi.c copies
// the raw words to the caller and then overwrites the three string fields with
// the output of ata_id_string(), which emits the high byte of each word first
// "regardless of platform". The bytes in struct hd_driveid are therefore
// already in display order and must NOT be byte-pair swapped again here; doing
// so would double-swap every model, serial and firmware string into garbage.
//
// The kernel also does not trim. Trimming is ata_id_c_string(), a different
// helper used inside libata, so the trim above is required rather than
// cosmetic.
Result<DeviceIdentity> readAtaIdentity(int fd) {
    struct hd_driveid id;
    if (ioctl(fd, HDIO_GET_IDENTITY, &id) < 0) {
        return Result<DeviceIdentity>::err(
            SanitizerError::fromErrno(errno, "ATA IDENTIFY DEVICE failed"));
    }
    DeviceIdentity identity;
    // struct hd_driveid declares these as unsigned char[], unlike the NVMe
    // Identify Controller which uses char[]. The bytes are ASCII either way.
    identity.model = trimDeviceString(reinterpret_cast<const char*>(id.model), sizeof(id.model));
    identity.serial = trimDeviceString(reinterpret_cast<const char*>(id.serial_no), sizeof(id.serial_no));
    identity.firmware = trimDeviceString(reinterpret_cast<const char*>(id.fw_rev), sizeof(id.fw_rev));
    identity.source = "ATA IDENTIFY DEVICE (HDIO_GET_IDENTITY)";
    return Result<DeviceIdentity>::ok(std::move(identity));
}

// NVMe Identify Controller. The MN, SN and FR fields are plain ASCII in
// specification order with no byte swapping, so they are trimmed the same way.
Result<DeviceIdentity> readNvmeIdentity(int fd) {
    auto ctrlResult = nvmeIdentifyController(fd);
    if (ctrlResult.isError()) {
        return Result<DeviceIdentity>::err(ctrlResult.error());
    }
    const auto& ctrl = ctrlResult.value();
    DeviceIdentity identity;
    identity.model = trimDeviceString(ctrl.mn, sizeof(ctrl.mn));
    identity.serial = trimDeviceString(ctrl.sn, sizeof(ctrl.sn));
    identity.firmware = trimDeviceString(ctrl.fr, sizeof(ctrl.fr));
    identity.source = "NVMe Identify Controller";
    return Result<DeviceIdentity>::ok(std::move(identity));
}

} // namespace

Result<DeviceIdentity> readDeviceIdentity(int fd, TransportType transport) {
    // Dispatch on the transport the device actually reported.
    //
    // HDIO_GET_IDENTITY is an ATA interface. On an NVMe namespace the ioctl
    // addresses an entirely different command set, so the previous ATA-only
    // implementation could never return a model, serial or firmware for NVMe
    // media. That is not cosmetic: the destructive-path confirmation requires
    // the operator to type the last characters of the device serial, so an
    // empty serial silently removes the one check that proves the operator
    // selected the right disk.
    switch (transport) {
        case TransportType::NVME:
            return readNvmeIdentity(fd);

        case TransportType::SATA:
        case TransportType::SCSI:
        case TransportType::MMC:
            return readAtaIdentity(fd);

        case TransportType::USB:
            // A USB mass-storage device may be any of three things: a bridge
            // that passes ATA through, a bridge that passes NVMe through, or a
            // flash device that implements neither. Neither ATA nor NVMe can be
            // assumed, so both are attempted and the first that answers wins.
            // A bridge that silently mishandles the passthrough is not
            // detectable here; the capability detector probes for that
            // separately and fails closed to UNKNOWN.
            {
                auto ata = readAtaIdentity(fd);
                if (ata.ok()) return ata;
                auto nvme = readNvmeIdentity(fd);
                if (nvme.ok()) return nvme;
                return Result<DeviceIdentity>::err(
                    ErrorCode::DEVICE_NOT_FOUND,
                    std::string("This USB device did not answer either an ATA or "
                                "an NVMe identity request (") + ata.error().what() +
                        "; " + nvme.error().what() + ")",
                    "Model, serial and firmware are unavailable for this device "
                    "and must be read from its label. The serial confirmation step "
                    "cannot run without a serial, so the target must be confirmed "
                    "by hand before any destructive action.");
            }

        case TransportType::UNKNOWN:
        case TransportType::VIRTIO:
        case TransportType::NVME_OVER_FABRICS:
        default: {
            auto ata = readAtaIdentity(fd);
            if (ata.ok()) return ata;
            return readNvmeIdentity(fd);
        }
    }
}


Result<std::string> getDeviceModel(int fd, TransportType transport) {
    auto identity = readDeviceIdentity(fd, transport);
    if (identity.isError()) return Result<std::string>::err(identity.error());
    return Result<std::string>::ok(identity.value().model);
}

Result<std::string> getDeviceSerial(int fd, TransportType transport) {
    auto identity = readDeviceIdentity(fd, transport);
    if (identity.isError()) return Result<std::string>::err(identity.error());
    return Result<std::string>::ok(identity.value().serial);
}

Result<std::string> getDeviceFirmware(int fd, TransportType transport) {
    auto identity = readDeviceIdentity(fd, transport);
    if (identity.isError()) return Result<std::string>::err(identity.error());
    return Result<std::string>::ok(identity.value().firmware);
}

Result<NvmeIdentifyController> nvmeIdentifyController(int fd) {
    NvmeIdentifyController ctrl = {};
    struct nvme_admin_cmd cmd = {};
    cmd.opcode = NVME_ADMIN_IDENTIFY;
    cmd.nsid = 0;
    cmd.addr = reinterpret_cast<uint64_t>(&ctrl);
    cmd.data_len = sizeof(ctrl);
    cmd.cdw10 = 1;

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        return Result<NvmeIdentifyController>::err(SanitizerError::fromErrno(errno, "NVMe identify controller failed"));
    }
    return Result<NvmeIdentifyController>::ok(ctrl);
}

Result<NvmeIdentifyNamespace> nvmeIdentifyNamespace(int fd, uint32_t nsid) {
    NvmeIdentifyNamespace ns = {};
    struct nvme_admin_cmd cmd = {};
    cmd.opcode = NVME_ADMIN_IDENTIFY;
    cmd.nsid = nsid;
    cmd.addr = reinterpret_cast<uint64_t>(&ns);
    cmd.data_len = sizeof(ns);
    cmd.cdw10 = 0;

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        return Result<NvmeIdentifyNamespace>::err(SanitizerError::fromErrno(errno, "NVMe identify namespace failed"));
    }
    return Result<NvmeIdentifyNamespace>::ok(ns);
}

Result<uint32_t> nvmeIdentifyNamespaceForDevice(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        return Result<uint32_t>::err(
            SanitizerError::fromErrno(errno, "Cannot stat the NVMe namespace device"));
    }
    // The real /sys deliberately: this queries an open device fd, so the
    // major:minor it reports is the one the running kernel knows about.
    const std::string link = "/sys/dev/block/" + std::to_string(major(st.st_rdev)) +
                             ":" + std::to_string(minor(st.st_rdev));
    const auto nsid = readSysfsUint32(link, "nsid");
    if (nsid.isError()) {
        return Result<uint32_t>::err(
            ErrorCode::DEVICE_NOT_FOUND,
            "Cannot read the NVMe namespace id from " + link + "/nsid",
            "Without it a sanitize command cannot be addressed to the correct "
            "namespace, so no device-level sanitize is attempted");
    }
    return Result<uint32_t>::ok(nsid.value());
}

Result<NvmeSanitizeCapabilities> nvmeGetSanitizeCapabilities(int fd) {
    NvmeSanitizeCapabilities caps = {};
    auto ctrlResult = nvmeIdentifyController(fd);
    if (ctrlResult.isError()) {
        return Result<NvmeSanitizeCapabilities>::err(ctrlResult.error());
    }

    const auto& ctrl = ctrlResult.value();
    caps.supported = (ctrl.oacs & NVME_OACS_SANITIZE) != 0;
    if (caps.supported) {
        caps.blockErase = (ctrl.sanicap & NVME_SANICAP_BLOCK_ERASE) != 0;
        caps.cryptoErase = (ctrl.sanicap & NVME_SANICAP_CRYPTO_ERASE) != 0;
        caps.overwrite = (ctrl.sanicap & NVME_SANICAP_OVERWRITE) != 0;
        caps.maxSanitizeActions = (ctrl.sanicap & NVME_SANICAP_MAX_ACTIONS_MASK)
                                  >> NVME_SANICAP_MAX_ACTIONS_SHIFT;
    }
    return Result<NvmeSanitizeCapabilities>::ok(caps);
}

Result<std::vector<uint8_t>> nvmeGetSupportedSanitizeActions(int fd) {
    auto capsResult = nvmeGetSanitizeCapabilities(fd);
    if (capsResult.isError()) {
        return Result<std::vector<uint8_t>>::err(capsResult.error());
    }

    const auto& caps = capsResult.value();
    std::vector<uint8_t> actions;
    if (caps.blockErase) actions.push_back(0x01);
    if (caps.cryptoErase) actions.push_back(0x02);
    if (caps.overwrite) actions.push_back(0x03);
    return Result<std::vector<uint8_t>>::ok(actions);
}

Result<void> nvmeSanitize(int fd, uint32_t nsid, uint8_t action, uint8_t overwritePassCount) {
    if (action != SANITIZE_BLOCK_ERASE &&
        action != SANITIZE_CRYPTO_ERASE &&
        action != SANITIZE_OVERWRITE) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                "Invalid NVMe sanitize action code");
    }

    // OWPASS is a 4-bit field, so a pass count that does not fit is a caller
    // error rather than something to silently truncate: 16 passes and 0 passes
    // are both different operations from the 15 the controller can be told to
    // perform. Refused here, before any command is issued.
    if (action == SANITIZE_OVERWRITE &&
        (overwritePassCount < SANITIZE_OWPASS_MIN ||
         overwritePassCount > SANITIZE_OWPASS_MASK)) {
        return Result<void>::err(
            ErrorCode::INVALID_ARGUMENT,
            "NVMe sanitize overwrite pass count must be between 1 and " +
                std::to_string(static_cast<unsigned>(SANITIZE_OWPASS_MAX)) +
                " (the OWPASS field is 4 bits), got " +
                std::to_string(static_cast<unsigned>(overwritePassCount)),
            "Retry with a pass count the controller can be instructed to perform");
    }

    struct nvme_admin_cmd cmd = {};
    cmd.opcode = NVME_ADMIN_SANITIZE;
    cmd.nsid = nsid;

    uint32_t cdw10 = static_cast<uint32_t>(action) & SANITIZE_SANACT_MASK;
    if (action == SANITIZE_OVERWRITE) {
        // AUSE (bit 3): permit the sanitize to exit and return to normal
        // operation if it is interrupted, instead of leaving the namespace in
        // the Sanitize-In-Progress state. OWPASS (bits 7:4): pass count.
        cdw10 |= SANITIZE_AUSE_BIT;
        cdw10 |= (static_cast<uint32_t>(overwritePassCount) & SANITIZE_OWPASS_MASK)
                 << SANITIZE_OWPASS_SHIFT;
    }

    cmd.cdw10 = cdw10;

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        return Result<void>::err(SanitizerError::fromErrno(errno, "NVMe sanitize command failed"));
    }
    return Result<void>::success();
}

Result<NvmeSanitizeStatus> nvmeSanitizeStatus(int fd, uint32_t nsid) {
    // Get Log Page (admin opcode 0x02), LID 0x81 = Sanitize Status.
    //
    // The controller returns the 512-byte Sanitize Status log page in the data
    // buffer. SPPROG occupies bytes 0-1 and SSTATUS bytes 2-3, both
    // little-endian.
    constexpr uint32_t LOG_PAGE_DATA_LEN = 512;
    constexpr uint32_t LOG_PAGE_DWORDS = LOG_PAGE_DATA_LEN / 4;

    std::vector<uint8_t> buf(LOG_PAGE_DATA_LEN, 0x00);

    struct nvme_admin_cmd cmd = {};
    cmd.opcode = NVME_ADMIN_GET_LOG_PAGE;
    cmd.nsid = nsid;
    cmd.addr = reinterpret_cast<uint64_t>(buf.data());
    cmd.data_len = LOG_PAGE_DATA_LEN;

    // A log page is transferred in one contiguous buffer, so all of it is
    // requested through NUMDL: 128 dwords, encoded zero-based as 127. NUMDU is
    // zero because nothing is transferred in a second buffer.
    //
    // The previous layout put the dword count at cdw10 bits 15:8 and the LID at
    // cdw11 bits 15:8. Neither field lives there, so the controller was asked
    // for LID 0 with an unstated length: the ioctl would fail with EINVAL, or a
    // lenient controller would return some other page whose bytes were then
    // decoded as a sanitize state.
    const uint32_t numdl = LOG_PAGE_DWORDS - 1;   // 512 bytes = 128 dwords
    const uint32_t numdu = 0;                     // no upper (contiguous) buffer
    const uint32_t lsi  = 0;                      // Log Specific Identifier

    cmd.cdw10 = (static_cast<uint32_t>(NVME_LID_SANITIZE_STATUS) & 0xFF) |
                (numdl << GLPL_NUMDL_SHIFT);
    cmd.cdw11 = (numdu & GLPL_NUMDU_MASK) | (lsi << GLPL_LSI_SHIFT);
    cmd.cdw12 = 0;
    cmd.cdw13 = 0;
    cmd.cdw14 = 0;
    cmd.cdw15 = 0;

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        return Result<NvmeSanitizeStatus>::err(
            SanitizerError::fromErrno(errno, "NVMe get log page (sanitize status) failed"));
    }

    const uint16_t spprog = static_cast<uint16_t>(buf[0]) |
                           (static_cast<uint16_t>(buf[1]) << 8);
    const uint16_t sstatus = static_cast<uint16_t>(buf[2]) |
                             (static_cast<uint16_t>(buf[3]) << 8);

    NvmeSanitizeStatus status;
    switch (sstatus) {
        case SANITIZE_STATUS_NOT_STARTED:   status.state = NvmeSanitizeState::NOT_STARTED;   break;
        case SANITIZE_STATUS_IN_PROGRESS:   status.state = NvmeSanitizeState::IN_PROGRESS;   break;
        case SANITIZE_STATUS_COMPLETED:     status.state = NvmeSanitizeState::COMPLETED;     break;
        case SANITIZE_STATUS_FAILED:        status.state = NvmeSanitizeState::FAILED;        break;
        default:                            status.state = NvmeSanitizeState::UNKNOWN;        break;
    }

    if (spprog != SANITIZE_PROGRESS_NONE) {
        status.progressValid = true;
        status.progressPercent = spprog;
    }

    return Result<NvmeSanitizeStatus>::ok(status);
}

// ATA IDENTIFY DEVICE word 82 (hd_driveid::command_set_1), bit 1:
// "Security feature set supported". This bit is reliable via HDIO_GET_IDENTITY.
constexpr unsigned short ATA_IDWORD82_SECURITY_FEATURE_SET = (1u << 1);

Result<bool> ataSecuritySupported(int fd) {
    struct hd_driveid id;
    if (ioctl(fd, HDIO_GET_IDENTITY, &id) < 0) {
        return Result<bool>::err(SanitizerError::fromErrno(errno, "Failed to get ATA identity"));
    }
    return Result<bool>::ok((id.command_set_1 & ATA_IDWORD82_SECURITY_FEATURE_SET) != 0);
}

Result<bool> ataSecurityEnabled(int fd [[maybe_unused]]) {
    // Security state (enabled) is reported by the SECURITY CHECK POWER MODE
    // command, which requires an ATA PASS-THROUGH (SG_IO) CDB. The Linux
    // HDIO_* interface exposes no equivalent, so the state cannot be
    // established here. Reporting UNKNOWN is deliberate: UNKNOWN is preferred
    // over a guessed value (CLAUDE.md s42), and a guessed "enabled/frozen"
    // state would cause an unsafe erase attempt. This is this project's
    // evidence policy, not a rule quoted from NIST SP 800-88 Rev. 2, which
    // states no such general principle.
    return Result<bool>::err(ErrorCode::CAPABILITY_UNKNOWN,
                             "ATA security state requires SG_IO ATA PASS-THROUGH (SECURITY CHECK POWER MODE)",
                             "Install libscsi / provide SG_IO headers, or boot from another device to clear the frozen state");
}

Result<bool> ataSecurityFrozen(int fd [[maybe_unused]]) {
    // As with ataSecurityEnabled, the frozen state requires SECURITY FREEZE
    // LOCK / CHECK POWER MODE via ATA PASS-THROUGH. Unavailable here.
    return Result<bool>::err(ErrorCode::CAPABILITY_UNKNOWN,
                             "ATA security frozen state requires SG_IO ATA PASS-THROUGH",
                             "Power-cycling the drive is the standard remedy for a frozen security state");
}

Result<bool> ataEnhancedEraseSupported(int fd [[maybe_unused]]) {
    // Enhanced Secure Erase (ACS-3+) is not advertised in IDENTIFY DEVICE
    // word 82/83. Detecting it requires reading the device's supported
    // features set, which needs an ATA PASS-THROUGH IDENTIFY command.
    // Until that is available, report UNKNOWN rather than assuming support.
    return Result<bool>::err(ErrorCode::CAPABILITY_UNKNOWN,
                             "ATA Enhanced Secure Erase support is not advertised in IDENTIFY DEVICE",
                             "Requires SG_IO ATA PASS-THROUGH IDENTIFY to enumerate the device features set");
}

namespace {

// True when the ATA Security Feature Set commands this tool needs can actually
// be issued.
//
// HDIO_DRIVE_CMD cannot carry them. Per <linux/hdreg.h> the buffer it takes is
// a 4-byte taskfile header (HDIO_DRIVE_CMD_HDR_SIZE == 4 * sizeof(__u8)):
// command, features, sector count, sector number. SECURITY ERASE PREPARE
// (0xF3) and SECURITY ERASE UNIT (0xF4) are non-data commands whose entire
// argument is the security identifier spread across the 28-bit taskfile
// (LBA low/mid/high, count and device registers) plus the CONTROL byte in the
// features register. There is no data-out phase to place a 32-byte password
// into, and 4 taskfile bytes cannot express a 7-byte identifier. A 33-byte
// {password[32]; control} struct therefore does not transmit a password at all:
// the kernel reads the first four password bytes as taskfile registers.
//
// The correct transport is SG_IO with an ATA PASS-THROUGH(16) CDB, which
// expresses the full taskfile. Until that exists here, the honest answer is
// that the mechanism is unavailable to this build, not that the drive lacks it.
bool ataSecurityEraseTransportAvailable() { return false; }

} // namespace

Result<bool> ataSecurityEraseSupportedInThisBuild() {
    if (ataSecurityEraseTransportAvailable()) {
        return Result<bool>::ok(true);
    }
    return Result<bool>::err(
        ErrorCode::NOT_IMPLEMENTED,
        "ATA Secure Erase cannot be issued by this build: HDIO_DRIVE_CMD carries "
        "only a 4-byte taskfile header, which cannot express the 32-byte security "
        "identifier that SECURITY ERASE PREPARE (0xF3) / SECURITY ERASE UNIT (0xF4) "
        "require in the taskfile registers",
        "Issue these commands through SG_IO ATA PASS-THROUGH(16) (sg_sata_pass_through "
        "or libata SG_IO CDB 0x85/0x0c), or use a tool that does");
}

Result<void> ataSecurityErasePrepare(int fd [[maybe_unused]],
                                      const std::string& password [[maybe_unused]]) {
    // Deliberately unimplemented. Issuing SECURITY ERASE PREPARE with a
    // malformed taskfile risks leaving the drive's security state frozen, which
    // would need a power cycle to clear and could block any future erase. That
    // is a worse outcome than refusing, so this fails closed.
    return Result<void>::err(
        ErrorCode::NOT_IMPLEMENTED,
        "ATA SECURITY ERASE PREPARE (0xF3) requires SG_IO ATA PASS-THROUGH, which "
        "is not available in this build",
        "Use a tool with SG_IO ATA pass-through support, or sanitize by host overwrite "
        "(CLEAR only)");
}

Result<void> ataSecurityEraseUnit(int fd [[maybe_unused]],
                                  const std::string& password [[maybe_unused]],
                                  bool enhanced [[maybe_unused]]) {
    return Result<void>::err(
        ErrorCode::NOT_IMPLEMENTED,
        "ATA SECURITY ERASE UNIT (0xF4) requires SG_IO ATA PASS-THROUGH, which is "
        "not available in this build",
        "Use a tool with SG_IO ATA pass-through support, or sanitize by host overwrite "
        "(CLEAR only)");
}

Result<void> ataSanitize(int fd [[maybe_unused]], uint8_t action [[maybe_unused]],
                         uint16_t overwritePassCount [[maybe_unused]]) {
    // The ATA SANITIZE DEVICE feature set (ACS-3/ACS-4) is issued with a
    // 28-bit LBA/SATA-style register file plus a feature-extension command,
    // which the Linux HDIO_DRIVE_CMD interface cannot express: it carries
    // only a 4-byte taskfile. The operation therefore requires an
    // ATA PASS-THROUGH CDB via SG_IO.
    //
    // Deliberately unimplemented. Issuing a malformed command here would be
    // dangerous, so this fails closed rather than guessing.
    return Result<void>::err(ErrorCode::NOT_IMPLEMENTED,
                             "ATA SANITIZE requires SG_IO ATA PASS-THROUGH, which is not available in this build",
                             "Use ATA Secure Erase, or build with libscri/SCSI support for the Sanitize feature set");
}

Result<uint16_t> ataSanitizeStatus(int fd [[maybe_unused]]) {
    // As with ataSanitize, the SANITIZE STATUS feature requires an SG_IO
    // ATA PASS-THROUGH CDB. Unavailable in this build.
    return Result<uint16_t>::err(ErrorCode::NOT_IMPLEMENTED,
                                 "ATA SANITIZE STATUS requires SG_IO ATA PASS-THROUGH, which is not available in this build",
                                 "Build with libscsi/SCSI support to query sanitize status");
}

namespace {

// Parses a /proc/self/mountinfo line.
//
// The layout is NOT fixed-width. Fields 1-6 are always present, then an
// arbitrary number of optional fields, then a literal "-", then the filesystem
// type and the mount source. Reading the source as "the 9th whitespace token"
// therefore returns the filesystem type whenever any optional field is present
// (e.g. "shared:1"), which silently misidentifies the root device.
//
// Returns false when the line is not a mountinfo record.
bool parseMountInfo(const std::string& line, std::string& mountPoint,
                    std::string& fsType, std::string& source) {
    std::istringstream iss(line);
    std::string token;

    // Fields 1-6: id, parent id, major:minor, root, mount point, options.
    for (int i = 0; i < 6; ++i) {
        if (!(iss >> token)) {
            return false;
        }
        if (i == 4) {
            mountPoint = token;
        }
    }

    // Optional fields until the "-" separator.
    while (iss >> token) {
        if (token == "-") {
            break;
        }
    }
    if (token != "-") {
        return false;
    }

    if (!(iss >> fsType)) {
        return false;
    }
    if (!(iss >> source)) {
        return false;
    }
    mountPoint = detail::decodeMountInfoEscapes(mountPoint);
    source = detail::decodeMountInfoEscapes(source);
    return true;
}

} // namespace


// ---------------------------------------------------------------------------
// USB bridge probing
// ---------------------------------------------------------------------------

std::string usbBridgeVerdictToString(UsbBridgeVerdict verdict) {
    switch (verdict) {
        case UsbBridgeVerdict::PASSTHROUGH_PRESENT:    return "present";
        case UsbBridgeVerdict::PASSTHROUGH_VERIFIED:   return "verified";
        case UsbBridgeVerdict::PASSTHROUGH_ABSENT:     return "absent";
        case UsbBridgeVerdict::PASSTHROUGH_UNRELIABLE: break;
    }
    return "unreliable";
}

namespace {

// Resolves /sys/block/<name> to the directory the kernel actually points it at.
// The unresolved path's parent is literally "block", so the bus cannot be
// identified from it.
std::string resolveSysfsBlockPath(const std::string& devicePath) {
    const std::string name = std::filesystem::path(devicePath).filename().string();
    if (name.empty()) {
        return {};
    }
    std::error_code ec;
    const auto resolved = std::filesystem::canonical("/sys/block/" + name, ec);
    if (ec) {
        return {};
    }
    return resolved.string();
}

} // namespace

bool findUsbAncestor(const std::string& resolvedSysfsPath, std::string& usbNodeOut) {
    if (resolvedSysfsPath.empty()) {
        return false;
    }

    std::error_code ec;
    const auto deviceLink = std::filesystem::canonical(
        std::filesystem::path(resolvedSysfsPath) / "device", ec);
    if (ec) {
        return false;
    }

    // Bounded walk. Typical layout for a pen drive:
    //
    //   /sys/block/sda -> .../usb1/1-2/1-2:1.0/host2/target2:0:0/2:0:0:0/block/sda
    //   /sys/block/sda/device -> .../2:0:0:0        (the SCSI target)
    //   .../1-2                                      (the USB device)
    //
    // The bound is there so a cyclic or unexpectedly deep tree cannot hang
    // device discovery.
    std::filesystem::path current = deviceLink;
    for (int depth = 0; depth < 6; ++depth) {
        if (std::filesystem::exists(current / "idVendor", ec) &&
            std::filesystem::exists(current / "idProduct", ec)) {
            usbNodeOut = current.string();
            return true;
        }
        const std::filesystem::path parent = current.parent_path();
        if (parent == current || parent.empty()) {
            break;
        }
        current = parent;
    }
    return false;
}

bool findUsbDeviceNode(const std::string& devicePath, std::string& usbNodeOut) {
    return findUsbAncestor(resolveSysfsBlockPath(devicePath), usbNodeOut);
}

namespace {

std::string readSysfsStringOrEmpty(const std::string& dir, const char* attribute) {
    const auto value = readSysfsAttribute(dir, attribute);
    return value.ok() ? value.value() : std::string();
}

} // namespace

Result<UsbBridgeProbe> probeUsbBridge(const std::string& devicePath) {
    UsbBridgeProbe probe;

    if (!findUsbDeviceNode(devicePath, probe.usbDeviceNode)) {
        probe.verdict = UsbBridgeVerdict::PASSTHROUGH_ABSENT;
        probe.detail =
            "No USB device node was found above this block device. Either it is "
            "not a USB mass-storage device, or the USB device publishes neither "
            "idVendor nor idProduct, in which case this tool cannot tell what it "
            "is talking to.";
        return Result<UsbBridgeProbe>::err(
            ErrorCode::DEVICE_NOT_FOUND, probe.detail,
            "Device-level sanitization mechanisms cannot be assessed on this path. "
            "Only a host-side overwrite is available, which is CLEAR only.");
    }

    probe.vendorId = readSysfsStringOrEmpty(probe.usbDeviceNode, "idVendor");
    probe.productId = readSysfsStringOrEmpty(probe.usbDeviceNode, "idProduct");
    probe.productName = readSysfsStringOrEmpty(probe.usbDeviceNode, "product");

    // The probe is read-only. It opens the device O_RDONLY and issues only
    // identity requests. No security, sanitize or write command is sent, because
    // a probe must be safe to run against any device an operator points it at,
    // including a disk that is about to be used for something else.
    auto fdResult = openDevice(devicePath, /*readOnly=*/true);
    if (fdResult.isError()) {
        probe.verdict = UsbBridgeVerdict::PASSTHROUGH_UNRELIABLE;
        probe.detail =
            "The USB device was identified (idVendor " + probe.vendorId +
            ", idProduct " + probe.productId + ") but the block device could not be "
            "opened: " + fdResult.error().what();
        return Result<UsbBridgeProbe>::ok(probe);
    }
    const int fd = fdResult.value();

    // Two independent command sets, because a bridge may implement either, both
    // or neither. Answering neither is the common case for flash media presented
    // over USB, where the device implements the SCSI command set only.
    auto ata = readAtaIdentity(fd);
    auto nvme = readNvmeIdentity(fd);

    closeDevice(fd);

    if (ata.ok() && nvme.ok()) {
        probe.verdict = UsbBridgeVerdict::PASSTHROUGH_VERIFIED;
        probe.detail =
            "The bridge passed both an ATA IDENTIFY DEVICE and an NVMe Identify "
            "Controller request through unchanged. A device-level command has a "
            "route to the media, but this probe cannot establish that a security "
            "or sanitize command would be honoured rather than dropped, so the "
            "capability is still reported as UNKNOWN rather than SUPPORTED.";
    } else if (ata.ok() || nvme.ok()) {
        probe.verdict = UsbBridgeVerdict::PASSTHROUGH_PRESENT;
        probe.detail =
            std::string("The bridge passed an ") +
            (ata.ok() ? "ATA IDENTIFY DEVICE" : "NVMe Identify Controller") +
            " request through. It did not answer the other, so it implements one "
            "command set and not the other. A device-level command may or may not "
            "reach the media; the capability is reported as UNKNOWN.";
    } else {
        probe.verdict = UsbBridgeVerdict::PASSTHROUGH_ABSENT;
        probe.commandsSilentlyDropped = false;
        probe.detail =
            std::string("The bridge answered neither an ATA IDENTIFY DEVICE nor "
                        "an NVMe Identify Controller request (") + ata.error().what() +
            "; " + nvme.error().what() +
            "). It exposes the SCSI command set only, so no device-level "
            "sanitization mechanism is reachable through it.";
    }

    return Result<UsbBridgeProbe>::ok(probe);
}

namespace {

bool isDigitByte(char c) { return c >= '0' && c <= '9'; }

// The one partition case a name can decide on its own: a 'p' followed by digits.
// A partition is never a parent, so "X" with a trailing "p<digits>" is
// unambiguously a partition of X-without-the-p.
bool nameIsPPrefixedPartition(const std::string& name) {
    for (std::size_t i = 1; i + 1 < name.size(); ++i) {
        if (name[i] == 'p' && isDigitByte(name[i + 1]) && isDigitByte(name[i - 1])) {
            return true;
        }
    }
    return false;
}

} // namespace

bool looksLikePartition(const std::string& devicePath, const std::string& sysfsBase) {
    const std::string name = std::filesystem::path(devicePath).filename().string();
    if (name.size() < 2) {
        return false;
    }

    std::error_code ec;
    const std::string sysfsPath = sysfsBase + "/block/" + name;

    // 1. The authoritative attribute. Present on a partition, absent on a disk.
    if (std::filesystem::exists(sysfsPath + "/partition", ec)) {
        return true;
    }
    if (std::filesystem::exists(sysfsPath, ec)) {
        // The device is in sysfs and has no "partition" attribute, so it is a
        // whole disk. No need to guess.
        return false;
    }

    // 2. The device is not in sysfs (absent, or an image file). Fall back to the
    //    name, and only for the case a name can decide.
    return nameIsPPrefixedPartition(name);
}

std::string containingWholeDisk(const std::string& devicePath,
                                const std::string& sysfsBase) {
    const std::string name = std::filesystem::path(devicePath).filename().string();
    if (name.empty() || !looksLikePartition(devicePath, sysfsBase)) {
        return {};
    }
    const std::string sysfsPath = findSysfsPath(devicePath, sysfsBase);
    if (sysfsPath.empty()) {
        // Not resolvable, but the name said it is a partition. Strip the
        // p-suffix if there is one; a bare digit suffix is not decidable, so
        // the caller is told nothing rather than given a guess.
        for (std::size_t i = name.size(); i > 0; --i) {
            if (name[i - 1] == 'p' && nameIsPPrefixedPartition(name)) {
                return "/dev/" + name.substr(0, i - 1);
            }
        }
        return {};
    }
    std::error_code canonicalEc;
    const auto resolved = std::filesystem::canonical(sysfsPath, canonicalEc);
    if (canonicalEc) {
        return {};
    }
    // /sys/block/<disk>/<partition> for a partition; /sys/block/<disk> for a
    // whole disk, whose parent directory is literally named "block".
    const std::filesystem::path parent = resolved.parent_path();
    if (parent.filename() == "block") {
        return {};
    }
    return "/dev/" + parent.filename().string();
}

std::vector<std::string> resolveToPhysicalDevices(const std::string& devicePath) {
    std::vector<std::string> leaves;
    if (devicePath.empty() || devicePath.front() != '/') {
        return leaves;
    }

    // Bounded walk. A layered stack (dm-crypt over an LVM LV over an md array
    // over a partition) is a handful of levels deep; the bound is there so a
    // malformed or cyclic sysfs tree cannot hang the safety layer, which runs
    // before every destructive operation.
    constexpr int kMaxDepth = 8;
    struct Pending {
        std::string name;
        int depth;
    };
    std::vector<Pending> queue;
    queue.push_back({std::filesystem::path(devicePath).filename().string(), 0});

    while (!queue.empty()) {
        const Pending current = queue.back();
        queue.pop_back();
        if (current.name.empty() || current.depth > kMaxDepth) {
            continue;
        }

        const std::string sysfsBlock = "/sys/block/" + current.name;
        const std::string slavesDir = sysfsBlock + "/slaves";
        std::error_code ec;
        if (!std::filesystem::is_directory(sysfsBlock, ec)) {
            // Not a block device this kernel knows about. Reporting it as a leaf
            // would let an invented name flow into the system-disk decision, so
            // it contributes nothing and the caller sees an empty result.
            continue;
        }
        if (!std::filesystem::is_directory(slavesDir, ec)) {
            // No slaves: this is already a leaf, which for a /sys/block entry
            // means a whole disk, a partition, or a virtual device with no
            // backing hardware.
            if (std::find(leaves.begin(), leaves.end(), "/dev/" + current.name) ==
                leaves.end()) {
                leaves.push_back("/dev/" + current.name);
            }
            continue;
        }

        for (const auto& entry : std::filesystem::directory_iterator(slavesDir, ec)) {
            queue.push_back({entry.path().filename().string(), current.depth + 1});
        }
    }

    return leaves;
}

namespace {

// True when `target` holds `systemDevice`, either literally or through a
// device-mapper / LVM / md layer.
//
// The unmapped comparison alone is not enough. On a system whose root lives in
// an LVM logical volume, /proc/self/mountinfo reports "/dev/mapper/vg-root" (or
// /dev/dm-0) and the running filesystem is on the *physical disk underneath*.
// Comparing names only would report the physical disk as neither the system nor
// the boot disk, which is exactly the case where the safety layer must refuse.
bool containsEitherWay(const std::string& target, const std::string& systemDevice) {
    if (target.empty() || systemDevice.empty()) {
        return false;
    }
    if (deviceContains(target, systemDevice)) {
        return true;
    }
    for (const auto& physical : resolveToPhysicalDevices(systemDevice)) {
        if (deviceContains(target, physical)) {
            return true;
        }
    }
    return false;
}

} // namespace

std::vector<std::string> getMountPoints(const std::string& devicePath) {
    std::vector<std::string> mountPoints;
    std::ifstream mounts("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mounts, line)) {
        std::string mountPoint, fsType, source;
        if (!parseMountInfo(line, mountPoint, fsType, source)) {
            continue;
        }
        // deviceContains() matches the device itself and its partitions, so a
        // check against /dev/sda also covers /dev/sda1.
        if (deviceContains(devicePath, source)) {
            mountPoints.push_back(mountPoint);
        }
    }
    return mountPoints;
}

bool isMounted(const std::string& devicePath) {
    return !getMountPoints(devicePath).empty();
}

bool isSystemDisk(const std::string& devicePath) {
    // A disk is a system disk if the running root filesystem lives on it.
    return containsEitherWay(devicePath, getRootDevice());
}

bool isBootDisk(const std::string& devicePath) {
    return containsEitherWay(devicePath, getBootDevice());
}

std::string getRootDevice() {
    std::ifstream mounts("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mounts, line)) {
        std::string mountPoint, fsType, source;
        if (!parseMountInfo(line, mountPoint, fsType, source)) {
            continue;
        }
        if (mountPoint == "/" && !source.empty() && source.front() == '/') {
            return source;
        }
    }
    return "";
}

std::string getBootDevice() {
    std::ifstream cmdline("/proc/cmdline");
    std::string line;
    if (std::getline(cmdline, line)) {
        std::istringstream iss(line);
        std::string token;
        while (iss >> token) {
            if (token.find("root=") == 0) {
                const std::string root = token.substr(5);

                // A UUID=, LABEL= or PARTUUID= reference must be resolved to a
                // device node. /proc/self/mountinfo already reports the
                // *resolved* source for "/", so prefer that over shelling out to
                // blkid: it needs no subprocess, and it removes the path from any
                // shell context. PARTUUID= names a partition table entry rather
                // than a filesystem, and resolving it the same way is correct
                // because the running root is that entry's mounted filesystem.
                if (root.rfind("UUID=", 0) == 0 ||
                    root.rfind("LABEL=", 0) == 0 ||
                    root.rfind("PARTUUID=", 0) == 0) {
                    const std::string resolved = getRootDevice();
                    if (!resolved.empty()) {
                        return resolved;
                    }
                }
                return root;
            }
        }
    }
    return "";
}

// The filesystem a path lives on, as the kernel reports it.
//
// From /proc/self/mountinfo rather than from libblkid, because the question is
// "what filesystem is this *file* on" and libblkid probes a block device's
// superblock, which a file does not have. mountinfo is the kernel's own answer
// and needs no privileges.
//
// The longest matching mount point wins, because a mount is nested inside
// another: /home can be an ext4 mount inside an overlayfs root, and asking
// which filesystem a file is on has to mean the one that actually holds it.
// An empty string means the kernel reported nothing, which is UNKNOWN rather
// than a default.
std::string filesystemTypeOf(const std::string& path) {
    if (path.empty()) {
        return {};
    }
    // Resolved to an absolute path first. A relative path names a different
    // file depending on the working directory, and matching it against
    // mountinfo's absolute mount points would either fail or - worse - match
    // the wrong mount and report a filesystem the file is not on.
    std::string absolute = path;
    if (absolute.front() != '/') {
        char* resolved = ::realpath(absolute.c_str(), nullptr);
        if (resolved == nullptr) {
            return {};
        }
        absolute = resolved;
        std::free(resolved);
    }
    std::ifstream mounts("/proc/self/mountinfo");
    std::string line;
    std::string bestMount;
    std::string bestType;
    while (std::getline(mounts, line)) {
        std::string mountPoint, fsType, source;
        if (!parseMountInfo(line, mountPoint, fsType, source)) {
            continue;
        }
        // Compared against the resolved path, not the caller's. Mount points
        // are absolute, so a relative argument matches nothing but "/", and
        // "/" matching means the answer becomes the root filesystem - which is
        // exactly the wrong answer, produced without an error. That is what
        // happened here for a while: a relative path under /dev/shm reported
        // btrfs, because "/dev/shm" could not match "./docs/file".
        const bool inside = mountPoint == "/"
                                ? true
                                : (absolute.size() > mountPoint.size() &&
                                   absolute.compare(0, mountPoint.size(),
                                                   mountPoint) == 0 &&
                                   absolute[mountPoint.size()] == '/');
        if (!inside) {
            continue;
        }
        if (mountPoint.size() >= bestMount.size()) {
            bestMount = mountPoint;
            bestType = fsType;
        }
    }
    return bestType;
}

std::vector<std::string> getActiveSwapDevices() {
    std::vector<std::string> swapDevices;
    std::ifstream swaps("/proc/swaps");
    std::string line;
    std::getline(swaps, line);
    while (std::getline(swaps, line)) {
        std::istringstream iss(line);
        std::string device, type, size, used, priority;
        if (iss >> device >> type >> size >> used >> priority) {
            swapDevices.push_back(device);
        }
    }
    return swapDevices;
}

namespace {

// Reads /proc/<pid>/comm, which is the kernel's own 16-byte command name and
// is present even when the process has no command line left to read. Best
// effort: an empty string means "the kernel would not say", which is rendered
// as a pid rather than as a blank that looks like a name.
std::string processCommand(uint32_t pid) {
    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    std::string name;
    std::getline(comm, name);
    while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) {
        name.pop_back();
    }
    return name;
}

// True when `line` is a /proc/<pid>/maps entry naming `path`. The maps format
// is "start-end perms offset dev inode path"; the path is the last field and is
// omitted entirely for anonymous mappings, which is why this is a prefix match
// on a parsed remainder rather than a field split.
bool mapLineNamesPath(const std::string& line, const std::string& path) {
    // Skip four fields (range, perms, offset, dev) and the inode number.
    std::size_t at = 0;
    int fields = 0;
    while (fields < 5) {
        while (at < line.size() && line[at] == ' ') ++at;
        while (at < line.size() && line[at] != ' ') ++at;
        ++fields;
        if (at >= line.size()) return false;
    }
    while (at < line.size() && line[at] == ' ') ++at;
    // Deleted-but-open files appear as "<path> (deleted)".
    std::string named = line.substr(at);
    const std::string suffix = " (deleted)";
    if (named.size() >= suffix.size() &&
        named.compare(named.size() - suffix.size(), suffix.size(), suffix) == 0) {
        named.resize(named.size() - suffix.size());
    }
    return named == path;
}

} // namespace

FileUse findFileUse(uint64_t deviceNumber, uint64_t inodeNumber,
                    const std::string& pathForMappingCheck) {
    FileUse use;
    use.inode = inodeNumber;

    // /proc/<pid>/maps names the path the kernel knows the mapping by, which is
    // not always the path the caller has. For a running executable the caller
    // typically holds "/proc/<pid>/exe" while the mapping line names the real
    // binary on disk, so comparing the two strings finds nothing. Resolving the
    // caller's path once, up front, makes the comparison work on the real path
    // as well as the one that was passed in.
    std::vector<std::string> mappingCandidates;
    if (!pathForMappingCheck.empty()) {
        mappingCandidates.push_back(pathForMappingCheck);
        std::error_code realEc;
        const std::filesystem::path real =
            std::filesystem::read_symlink(pathForMappingCheck, realEc);
        if (!realEc && !real.empty()) {
            const std::string realPath = real.string();
            if (realPath != pathForMappingCheck) {
                mappingCandidates.push_back(realPath);
            }
        }
    }

    std::error_code ec;
    std::filesystem::directory_iterator proc("/proc", ec);
    if (ec) {
        // An unreadable /proc is not evidence that nothing holds the file. The
        // caller is given scanCompleted = false so a scan that could not run is
        // never reported as a clean result.
        return use;
    }
    bool anyProcessRead = false;

    for (const auto& entry : proc) {
        const std::string name = entry.path().filename().string();
        if (name.empty() || !std::isdigit(static_cast<unsigned char>(name[0]))) {
            continue;   // not a pid directory
        }
        const uint32_t pid = static_cast<uint32_t>(std::stoul(name));
        // Our own descriptors are open on the file by definition: the caller
        // opened it to ask. Counting ourselves would make every file look
        // busy and the check would be useless.
        if (pid == static_cast<uint32_t>(::getpid())) {
            continue;
        }

        // Open descriptors.
        std::error_code fdEc;
        std::filesystem::directory_iterator fds(entry.path() / "fd", fdEc);
        if (!fdEc) {
            anyProcessRead = true;
            for (const auto& fdEntry : fds) {
                std::error_code linkEc;
                // readlink, not stat: the descriptor is a path to the file the
                // process has, and resolving it to a stat of our own could fail
                // on a file we have no permission to stat. The device/inode
                // comparison below is what makes the match exact.
                const std::string target =
                    std::filesystem::read_symlink(fdEntry.path(), linkEc);
                if (linkEc) continue;
                struct stat st {};
                if (::stat(target.c_str(), &st) != 0) continue;
                if (static_cast<uint64_t>(st.st_ino) != inodeNumber) continue;
                if (static_cast<uint64_t>(st.st_dev) != deviceNumber) continue;
                if (!use.openByAnyProcess) {
                    use.openByAnyProcess = true;
                    use.pid = pid;
                    use.command = processCommand(pid);
                }
            }
        }

        // Mapped into the address space. A mapped executable is a stronger
        // signal than an open descriptor: the program is running from these
        // pages, so overwriting them changes a running process.
        if (!mappingCandidates.empty()) {
            std::ifstream maps((entry.path() / "maps").string());
            if (maps.is_open()) {
                anyProcessRead = true;
                std::string line;
                while (std::getline(maps, line)) {
                    bool names = false;
                    for (const std::string& candidate : mappingCandidates) {
                        if (mapLineNamesPath(line, candidate)) {
                            names = true;
                            break;
                        }
                    }
                    if (!names) continue;
                    if (!use.mappedAsExecutable) {
                        use.mappedAsExecutable = true;
                        use.mappedByCommand = processCommand(pid);
                        if (!use.openByAnyProcess) {
                            use.openByAnyProcess = true;
                            use.pid = pid;
                            use.command = use.mappedByCommand;
                        }
                    }
                    break;
                }
            }
        }
    }

    use.scanCompleted = anyProcessRead;
    return use;
}

bool isOnReadOnlyMount(const std::string& path) {
    // Ask the kernel about the path itself rather than resolving the mount point
    // and reading the mount table: statvfs answers for the filesystem the path
    // is on, which is the question, and it cannot be fooled by a mount table
    // entry that names a different device than the one actually mounted.
    struct statvfs vfs {};
    if (::statvfs(path.c_str(), &vfs) != 0) {
        return false;   // cannot tell; the open will fail with the real reason
    }
    return (vfs.f_flag & ST_RDONLY) != 0;
}

bool isDeviceMapperInUse(const std::string& devicePath) {
    std::string dmPath = "/sys/block/" + std::filesystem::path(devicePath).filename().string() + "/dm";
    return std::filesystem::exists(dmPath);
}

// The device path must never reach a shell: popen() runs it through /bin/sh,
// so any metacharacter in the path would be interpreted. Both checks below
// read sysfs directly instead.
//
// LVM: an active logical volume holds a dm-N device whose slaves include the
// target. /sys/block/dm-N/slaves/<name> enumerates them.
// RAID: an assembled array lists its member devices in the md sysfs tree,
// and a target that is an md member is reported through
// /sys/block/<name>/md/level.
bool isLvmInUse(const std::string& devicePath) {
    const std::string devName = std::filesystem::path(devicePath).filename().string();
    if (devName.empty()) {
        return false;
    }

    const std::string slavesDir = "/sys/block/" + devName + "/slaves";
    std::error_code ec;
    if (std::filesystem::is_directory(slavesDir, ec)) {
        for (const auto& entry : std::filesystem::directory_iterator(slavesDir, ec)) {
            const std::string slave = entry.path().filename().string();
            if (deviceContains(devicePath, "/dev/" + slave)) {
                return true;
            }
        }
    }

    // Reverse direction: a physical device consumed by a dm device.
    for (const auto& entry : std::filesystem::directory_iterator("/sys/block", ec)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind("dm-", 0) != 0) {
            continue;
        }
        const std::string dmSlaves = entry.path().string() + "/slaves";
        std::error_code ec2;
        if (!std::filesystem::is_directory(dmSlaves, ec2)) {
            continue;
        }
        for (const auto& s : std::filesystem::directory_iterator(dmSlaves, ec2)) {
            if (s.path().filename().string() == devName) {
                return true;
            }
        }
    }

    return false;
}

bool isRaidInUse(const std::string& devicePath) {
    const std::string devName = std::filesystem::path(devicePath).filename().string();
    if (devName.empty()) {
        return false;
    }

    // The target is itself an md array, or is a member of one.
    std::error_code ec;
    if (std::filesystem::exists("/sys/block/" + devName + "/md/level", ec)) {
        return true;
    }
    return std::filesystem::exists("/sys/block/" + devName + "/md", ec) &&
           std::filesystem::is_directory("/sys/block/" + devName + "/md", ec);
}

namespace {

// Filesystem metadata via libblkid.
//
// This deliberately does not shell out to the blkid(8) command. popen() runs
// its argument through /bin/sh, so interpolating a partition path would place
// it in a shell context where metacharacters are interpreted. libblkid is a
// direct library call and keeps the path as opaque data.
struct PartitionFsInfo {
    std::string type;
    std::string label;
    std::string uuid;
};

PartitionFsInfo probeFilesystem(const std::string& devicePath) {
    PartitionFsInfo info;
    if (devicePath.empty() || devicePath.front() != '/') {
        return info;
    }

    // Probing needs a descriptor; O_RDONLY is sufficient and does not require
    // write access to the partition.
    const int fd = ::open(devicePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return info;
    }

    blkid_probe pr = blkid_new_probe();
    if (pr == nullptr) {
        ::close(fd);
        return info;
    }

    blkid_probe_enable_superblocks(pr, 1);
    blkid_probe_enable_partitions(pr, 0);

    // blkid_probe_lookup_value() performs the superblock probe on demand, so
    // setting the device is all that is required beforehand.
    if (blkid_probe_set_device(pr, fd, 0, 0) < 0) {
        blkid_free_probe(pr);
        ::close(fd);
        return info;
    }

    auto lookup = [&pr](const char* name) -> std::string {
        const char* data = nullptr;
        size_t len = 0;
        if (blkid_probe_lookup_value(pr, name, &data, &len) == 0 && data != nullptr) {
            return std::string(data, len);
        }
        return {};
    };

    info.type = lookup("TYPE");
    info.label = lookup("LABEL");
    info.uuid = lookup("UUID");

    blkid_free_probe(pr);
    ::close(fd);
    return info;
}

} // namespace

Result<std::vector<PartitionInfo>> readPartitions(const std::string& devicePath) {
    std::vector<PartitionInfo> partitions;
    std::string sysfsPath = findSysfsPath(devicePath);
    if (sysfsPath.empty()) {
        return Result<std::vector<PartitionInfo>>::ok(partitions);
    }

    // Every filesystem call here uses the error_code overloads. The throwing
    // ones were a real defect on this path: a USB device unplugged while the
    // scan is in flight makes the iterator throw filesystem_error, which
    // unwound past the Result and terminated the process - on the code path
    // that decides whether a device is partitioned, i.e. whether the plan
    // carries a partition risk. A device that vanishes mid-inspection should
    // report DEVICE_REMOVED, not abort.
    std::string partitionDir = sysfsPath + "/partition";
    std::error_code ec;
    if (!std::filesystem::exists(partitionDir, ec) || ec) {
        // Absent, or the directory could not be read. Both mean "no partition
        // table we can see", which is what an empty result already means.
        return Result<std::vector<PartitionInfo>>::ok(partitions);
    }

    std::filesystem::directory_iterator it(partitionDir, ec);
    const std::filesystem::directory_iterator end;
    for (; it != end && !ec; it.increment(ec)) {
        const auto& entry = *it;
        std::error_code dirEc;
        if (!entry.is_directory(dirEc) || dirEc) continue;
        std::string partName = entry.path().filename().string();
        if (partName.find("partition") != 0) continue;

        PartitionInfo part;
        part.path = "/dev/" + partName;

        auto startResult = readSysfsUint64(entry.path().string(), "start");
        if (startResult.ok()) part.startSector = startResult.value();

        auto sizeResult = readSysfsUint64(entry.path().string(), "size");
        if (sizeResult.ok()) part.sizeSectors = sizeResult.value();

        auto blockSizeResult = readSysfsUint64(entry.path().string(), "block_size");
        if (blockSizeResult.ok()) part.sizeBytes = part.sizeSectors * blockSizeResult.value();

        const PartitionFsInfo fs = probeFilesystem(part.path);
        part.filesystemType = fs.type;
        part.label = fs.label;
        part.uuid = fs.uuid;

        part.mounted = isMounted(part.path);
        if (part.mounted) {
            auto mountPoints = getMountPoints(part.path);
            if (!mountPoints.empty()) part.mountPoint = mountPoints[0];
        }

        part.isBoot = part.mountPoint == "/boot" || part.mountPoint == "/boot/efi";
        part.isSystem = part.mountPoint == "/";

        partitions.push_back(part);
    }
    return Result<std::vector<PartitionInfo>>::ok(partitions);
}

Result<std::vector<FilesystemInfo>> readFilesystems(const std::string& devicePath) {
    std::vector<FilesystemInfo> filesystems;
    auto partitionsResult = readPartitions(devicePath);
    if (partitionsResult.isError()) {
        return Result<std::vector<FilesystemInfo>>::err(partitionsResult.error());
    }

    for (const auto& part : partitionsResult.value()) {
        if (part.filesystemType.empty()) continue;

        FilesystemInfo fs;
        fs.type = part.filesystemType;
        fs.label = part.label;
        fs.uuid = part.uuid;
        fs.mountPoint = part.mountPoint;

        if (part.mounted) {
            struct statfs st;
            if (statfs(part.mountPoint.c_str(), &st) == 0) {
                fs.totalBytes = static_cast<uint64_t>(st.f_blocks) * st.f_bsize;
                fs.freeBytes = static_cast<uint64_t>(st.f_bavail) * st.f_bsize;
            }
        }
        filesystems.push_back(fs);
    }
    return Result<std::vector<FilesystemInfo>>::ok(filesystems);
}

Result<std::string> readSysfsAttribute(const std::string& sysfsPath, const std::string& attribute) {
    std::string fullPath = sysfsPath + "/" + attribute;
    std::ifstream file(fullPath);
    if (!file) {
        return Result<std::string>::err(ErrorCode::DEVICE_NOT_FOUND, "Sysfs attribute not found: " + fullPath);
    }
    std::string value;
    std::getline(file, value);
    return Result<std::string>::ok(value);
}

Result<uint64_t> readSysfsUint64(const std::string& sysfsPath, const std::string& attribute) {
    auto strResult = readSysfsAttribute(sysfsPath, attribute);
    if (strResult.isError()) {
        return Result<uint64_t>::err(strResult.error());
    }
    try {
        return Result<uint64_t>::ok(std::stoull(strResult.value()));
    } catch (...) {
        return Result<uint64_t>::err(ErrorCode::INVALID_ARGUMENT, "Failed to parse uint64 from " + attribute);
    }
}

Result<uint32_t> readSysfsUint32(const std::string& sysfsPath, const std::string& attribute) {
    auto strResult = readSysfsAttribute(sysfsPath, attribute);
    if (strResult.isError()) {
        return Result<uint32_t>::err(strResult.error());
    }
    try {
        return Result<uint32_t>::ok(static_cast<uint32_t>(std::stoul(strResult.value())));
    } catch (...) {
        return Result<uint32_t>::err(ErrorCode::INVALID_ARGUMENT, "Failed to parse uint32 from " + attribute);
    }
}

Result<bool> readSysfsBool(const std::string& sysfsPath, const std::string& attribute) {
    auto strResult = readSysfsAttribute(sysfsPath, attribute);
    if (strResult.isError()) {
        return Result<bool>::err(strResult.error());
    }
    std::string val = strResult.value();
    std::transform(val.begin(), val.end(), val.begin(), ::tolower);
    return Result<bool>::ok(val == "1" || val == "true" || val == "yes");
}

std::string findSysfsPath(const std::string& devicePath, const std::string& sysfsBase) {
    std::string devName = std::filesystem::path(devicePath).filename().string();
    std::string sysfsPath = sysfsBase + "/block/" + devName;
    if (std::filesystem::exists(sysfsPath)) {
        return sysfsPath;
    }

    std::string devPath = "/dev/" + devName;
    if (std::filesystem::exists(devPath)) {
        struct stat st;
        if (stat(devPath.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) {
            std::string linkPath = sysfsBase + "/dev/block/" + std::to_string(major(st.st_rdev)) +
                               ":" + std::to_string(minor(st.st_rdev));
            if (std::filesystem::exists(linkPath)) {
                auto canonical = std::filesystem::canonical(linkPath);
                return canonical.string();
            }
        }
    }
    return "";
}

} // namespace ledgerase::platform::linux