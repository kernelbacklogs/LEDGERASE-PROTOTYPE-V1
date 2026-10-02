#include "ledgerase/capability.hpp"
#include "ledgerase/device.hpp"
#include "ledgerase/platform/linux.hpp"
#include <fcntl.h>
#include <unistd.h>

namespace ledgerase {

class CapabilityDetector::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

CapabilityDetector::CapabilityDetector() : pImpl_(std::make_unique<Impl>()) {}
CapabilityDetector::~CapabilityDetector() = default;

Result<CapabilityInfo> CapabilityDetector::detectCapabilities(const DeviceInfo& device) {
    CapabilityInfo caps;

    // Recorded first, because it decides how every row below is presented. A
    // file has no command set at all, which is a different statement from "the
    // command set could not be read".
    caps.targetKind = classifyTarget(device.path);

    // Host-side techniques are established before the bus is identified.
    //
    // A host overwrite writes the logical block address space of a writable
    // block device; nothing about that depends on which bus the device sits on.
    // Without this, a device whose bus this tool cannot classify would be
    // reported as having no usable technique at all, presenting a gap in our
    // knowledge as a property of the drive. The identified transports below
    // build their own CapabilityInfo and set the same values for the same
    // reason.
    //
    // Everything DEVICE-reported is a different matter: an unrecognised bus
    // yields UNKNOWN, which is the honest answer.
    caps.overwriteHost = CapabilityStatus::SUPPORTED;
    caps.cryptoEraseHost = CapabilityStatus::UNSUPPORTED;

    if (device.transport == TransportType::NVME) {
        return detectNvmeCapabilities(device);
    } else if (device.transport == TransportType::USB) {
        // USB gets its own path. A bridge between the host and the media is not
        // a transparent wire, so the ATA code path would assert capabilities the
        // host has no way to reach.
        return detectUsbCapabilities(device);
    } else if (device.transport == TransportType::SATA ||
               device.transport == TransportType::SCSI) {
        return detectAtaCapabilities(device);
    }

    // An image file has no bus to identify. "Capability is unknown" is the right
    // answer for a device whose interface could not be read; for a file it is a
    // restatement of the fact that it is a file, and it lowers the recorded
    // outcome for nothing.
    if (!DeviceManager::isDiskImage(device.path)) {
        caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN,
                             "transport: " + transportToString(device.transport));
    }
    return Result<CapabilityInfo>::ok(caps);
}

Result<CapabilityInfo> CapabilityDetector::detectNvmeCapabilities(const DeviceInfo& device) {
    CapabilityInfo caps;

    // Host overwrite is a host-side technique over the logical block address
    // space, not a device-reported capability. It is available whenever the
    // device is a writable block device, independent of whether privileged
    // device queries succeed, so it is set before any device access.
    caps.overwriteHost = CapabilityStatus::SUPPORTED;
    caps.cryptoEraseHost = CapabilityStatus::UNSUPPORTED;

    auto fdResult = openDevice(device.path, true);
    if (fdResult.isError()) {
        caps.limitations.add(LimitationId::PROBE_FAILED,
                             fdResult.error().what());
        caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
        return Result<CapabilityInfo>::ok(caps);
    }
    int fd = fdResult.value();

    auto ctrlResult = platform::linux::nvmeIdentifyController(fd);
    if (ctrlResult.ok()) {
        const auto& ctrl = ctrlResult.value();
        // Trim rather than constructing std::string(char*, n): the Identify
        // Controller string fields are space-padded to their full width, so an
        // untrimmed read reports the model with trailing spaces, which then
        // propagate into the certificate and the evidence hash.
        caps.nvmeControllerModel = platform::linux::trimDeviceString(ctrl.mn, sizeof(ctrl.mn));
        caps.nvmeFirmware = platform::linux::trimDeviceString(ctrl.fr, sizeof(ctrl.fr));

        // The namespace this device node addresses. It was hardcoded to 1, so a
        // sanitize or status read on a multi-namespace controller would have
        // targeted namespace 1 regardless of which namespace was opened.
        auto nsResult = platform::linux::nvmeIdentifyNamespaceForDevice(fd);
        if (nsResult.ok()) {
            caps.nvmeNamespaceId = nsResult.value();
        } else {
            caps.limitations.add(LimitationId::PROBE_FAILED,
                                 "NVMe namespace id: " +
                                     std::string(nsResult.error().what()));
            caps.limitations.add(LimitationId::NVME_NAMESPACE_ASSUMED);
        }

        caps.nvmeSanitizeSupported = (ctrl.oacs & platform::linux::NVME_OACS_SANITIZE) != 0;

        if (caps.nvmeSanitizeSupported) {
            caps.nvmeBlockErase = (ctrl.sanicap & platform::linux::NVME_SANICAP_BLOCK_ERASE) != 0
                                      ? CapabilityStatus::SUPPORTED : CapabilityStatus::UNSUPPORTED;
            caps.nvmeCryptoErase = (ctrl.sanicap & platform::linux::NVME_SANICAP_CRYPTO_ERASE) != 0
                                      ? CapabilityStatus::SUPPORTED : CapabilityStatus::UNSUPPORTED;
            caps.nvmeOverwrite = (ctrl.sanicap & platform::linux::NVME_SANICAP_OVERWRITE) != 0
                                      ? CapabilityStatus::SUPPORTED : CapabilityStatus::UNSUPPORTED;

            const uint32_t maxActions =
                (ctrl.sanicap & platform::linux::NVME_SANICAP_MAX_ACTIONS_MASK)
                >> platform::linux::NVME_SANICAP_MAX_ACTIONS_SHIFT;
            caps.nvmeMaxSanitizeActions = maxActions;

            if (caps.nvmeBlockErase == CapabilityStatus::SUPPORTED)
                caps.supportedSanitizeActions.push_back("Block Erase");
            if (caps.nvmeCryptoErase == CapabilityStatus::SUPPORTED)
                caps.supportedSanitizeActions.push_back("Crypto Erase");
            if (caps.nvmeOverwrite == CapabilityStatus::SUPPORTED)
                caps.supportedSanitizeActions.push_back("Overwrite");
        } else {
            caps.nvmeBlockErase = CapabilityStatus::UNSUPPORTED;
            caps.nvmeCryptoErase = CapabilityStatus::UNSUPPORTED;
            caps.nvmeOverwrite = CapabilityStatus::UNSUPPORTED;
            caps.limitations.add(LimitationId::NVME_NO_SANITIZE);
        }
    } else {
        caps.limitations.add(LimitationId::PROBE_FAILED,
                             "NVMe identify controller: " +
                                 std::string(ctrlResult.error().what()));
    }

    auto actionsResult = platform::linux::nvmeGetSupportedSanitizeActions(fd);
    if (actionsResult.ok()) {
        for (auto action : actionsResult.value()) {
            switch (action) {
                case 0x01: caps.supportedSanitizeActions.push_back("Block Erase"); break;
                case 0x02: caps.supportedSanitizeActions.push_back("Crypto Erase"); break;
                case 0x03: caps.supportedSanitizeActions.push_back("Overwrite"); break;
            }
        }
    }

    closeDevice(fd);
    return Result<CapabilityInfo>::ok(caps);
}

// USB mass storage.
//
// A USB bridge is a command processor sitting between the host and the media,
// not a transparent wire. It is free to accept a command and do nothing with it,
// or to reinterpret it. Many bridges pass ATA and NVMe through; many more
// answer an identity request and then silently drop a security command.
//
// So nothing device-level is asserted on this path without a probe, and even a
// successful probe leaves the capability at UNKNOWN: the probe can show that a
// route to the media exists and is answering, but it cannot show that a
// security or sanitize command will be honoured. The distinction that matters
// for an assessor is therefore preserved rather than collapsed: the device
// mechanisms are UNKNOWN, the reason is recorded, and host overwrite remains
// available at CLEAR.
Result<CapabilityInfo> CapabilityDetector::detectUsbCapabilities(const DeviceInfo& device) {
    CapabilityInfo caps;

    // A host overwrite writes the logical block address space of a writable
    // block device. That is true of a USB device exactly as it is of a SATA one,
    // and it is the only mechanism this tool can rely on here.
    caps.overwriteHost = CapabilityStatus::SUPPORTED;
    caps.cryptoEraseHost = CapabilityStatus::UNSUPPORTED;

    auto probe = platform::linux::probeUsbBridge(device.path);
    if (probe.isError()) {
        caps.limitations.add(LimitationId::USB_BRIDGE_UNIDENTIFIED,
                             probe.error().what());
        caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
        return Result<CapabilityInfo>::ok(caps);
    }

    const auto& verdict = probe.value();

    // The probe verdict and the USB device identity used to be two separate
    // free-text strings describing one observation. The switch below records
    // the verdict once; the identity is carried as its detail so a reader can
    // see which device was actually interrogated.
    std::string bridgeIdentity;
    if (!verdict.vendorId.empty() || !verdict.productId.empty()) {
        bridgeIdentity = "idVendor " + verdict.vendorId + ", idProduct " +
                         verdict.productId;
        if (!verdict.productName.empty()) {
            bridgeIdentity += " (" + verdict.productName + ")";
        }
    }

    switch (verdict.verdict) {
        case platform::linux::UsbBridgeVerdict::PASSTHROUGH_VERIFIED:
        case platform::linux::UsbBridgeVerdict::PASSTHROUGH_PRESENT:
            // The route exists. Whether the bridge honours a security command is
            // still not established, and asserting SUPPORTED on the strength of
            // an identity request is exactly the guess this tool refuses to make.
            caps.ataSecureErase = CapabilityStatus::UNKNOWN;
            caps.ataEnhancedSecureErase = CapabilityStatus::UNKNOWN;
            caps.ataSanitizeBlockErase = CapabilityStatus::UNKNOWN;
            caps.ataSanitizeCryptoErase = CapabilityStatus::UNKNOWN;
            caps.ataSanitizeOverwrite = CapabilityStatus::UNKNOWN;
            caps.limitations.add(LimitationId::USB_BRIDGE_PROBE_PRESENT,
                                 bridgeIdentity);
            break;

        case platform::linux::UsbBridgeVerdict::PASSTHROUGH_ABSENT:
        default:
            // No command-set passthrough at all. The device-level mechanisms are
            // genuinely not reachable, which is a stronger statement than
            // UNKNOWN and is reported as such with the observation that supports
            // it.
            caps.ataSecureErase = CapabilityStatus::UNSUPPORTED;
            caps.ataEnhancedSecureErase = CapabilityStatus::UNSUPPORTED;
            caps.ataSanitizeBlockErase = CapabilityStatus::UNSUPPORTED;
            caps.ataSanitizeCryptoErase = CapabilityStatus::UNSUPPORTED;
            caps.ataSanitizeOverwrite = CapabilityStatus::UNSUPPORTED;
            caps.limitations.add(LimitationId::NO_DEVICE_LEVEL_MECHANISM,
                                 "no device-level erase is reachable through "
                                 "this bridge");
            break;
    }

    caps.limitations.add(LimitationId::USB_BRIDGE_OPAQUE);

    return Result<CapabilityInfo>::ok(caps);
}

Result<CapabilityInfo> CapabilityDetector::detectAtaCapabilities(const DeviceInfo& device) {
    CapabilityInfo caps;

    caps.overwriteHost = CapabilityStatus::SUPPORTED;
    caps.cryptoEraseHost = CapabilityStatus::UNSUPPORTED;

    auto fdResult = openDevice(device.path, true);
    if (fdResult.isError()) {
        caps.limitations.add(LimitationId::PROBE_FAILED,
                             fdResult.error().what());
        caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
        return Result<CapabilityInfo>::ok(caps);
    }
    int fd = fdResult.value();

    // A capability is only SUPPORTED when the device positively reports it AND
    // this build can actually issue the command. A failed query yields UNKNOWN,
    // never UNSUPPORTED: "we could not ask" is not the same as "the device does
    // not have it", and conflating the two would make the policy engine refuse
    // valid methods. Conversely, a device-reported capability whose transport is
    // unavailable to this build is also UNKNOWN, for the same reason in the
    // other direction: selecting a method that can only fail at execution time
    // is how a "capability" turns into a broken sanitization.
    auto eraseTransport = platform::linux::ataSecurityEraseSupportedInThisBuild();
    if (!eraseTransport.ok()) {
        caps.ataSecureErase = CapabilityStatus::UNKNOWN;
        caps.ataEnhancedSecureErase = CapabilityStatus::UNKNOWN;
        caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
    } else {
        auto secSupported = platform::linux::ataSecuritySupported(fd);
        if (secSupported.ok()) {
            caps.ataSecureErase = secSupported.value() ? CapabilityStatus::SUPPORTED
                                                      : CapabilityStatus::UNSUPPORTED;
        } else {
            caps.ataSecureErase = CapabilityStatus::UNKNOWN;
            caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
        }

        auto enhancedResult = platform::linux::ataEnhancedEraseSupported(fd);
        if (enhancedResult.ok()) {
            caps.ataEnhancedSecureErase = enhancedResult.value() ? CapabilityStatus::SUPPORTED
                                                                : CapabilityStatus::UNSUPPORTED;
        } else {
            caps.ataEnhancedSecureErase = CapabilityStatus::UNKNOWN;
            caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
        }
    }

    // ATA Sanitize (ACS-3/ACS-4) requires an SG_IO ATA PASS-THROUGH CDB, which
    // this build cannot issue. All three Sanitize actions therefore stay
    // UNKNOWN. They are deliberately not asserted UNSUPPORTED either: absence
    // of SG_IO is a limitation of this tool, not a property of the drive.
    auto sanitizeResult = platform::linux::ataSanitizeStatus(fd);
    if (sanitizeResult.ok()) {
        caps.ataSanitizeBlockErase = CapabilityStatus::SUPPORTED;
        caps.ataSanitizeCryptoErase = CapabilityStatus::SUPPORTED;
        caps.ataSanitizeOverwrite = CapabilityStatus::SUPPORTED;
    } else {
        caps.ataSanitizeBlockErase = CapabilityStatus::UNKNOWN;
        caps.ataSanitizeCryptoErase = CapabilityStatus::UNKNOWN;
        caps.ataSanitizeOverwrite = CapabilityStatus::UNKNOWN;
        caps.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
    }

    closeDevice(fd);
    return Result<CapabilityInfo>::ok(caps);
}

Result<int> CapabilityDetector::openDevice(const std::string& devicePath, bool readOnly) {
    return platform::linux::openDevice(devicePath, readOnly);
}

void CapabilityDetector::closeDevice(int fd) {
    platform::linux::closeDevice(fd);
}

Result<platform::linux::NvmeIdentifyController> nvmeIdentifyController(int fd) {
    return platform::linux::nvmeIdentifyController(fd);
}

Result<platform::linux::NvmeIdentifyNamespace> nvmeIdentifyNamespace(int fd, uint32_t nsid) {
    return platform::linux::nvmeIdentifyNamespace(fd, nsid);
}

Result<platform::linux::NvmeSanitizeCapabilities> nvmeGetSanitizeCapabilities(int fd) {
    return platform::linux::nvmeGetSanitizeCapabilities(fd);
}

Result<std::vector<uint8_t>> nvmeGetSupportedSanitizeActions(int fd) {
    return platform::linux::nvmeGetSupportedSanitizeActions(fd);
}

} // namespace ledgerase