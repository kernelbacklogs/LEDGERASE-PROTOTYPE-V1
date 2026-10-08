#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include <memory>
#include <string>
#include <vector>

namespace ledgerase {

class CapabilityDetector {
public:
    CapabilityDetector();
    ~CapabilityDetector();

    Result<CapabilityInfo> detectCapabilities(const DeviceInfo& device);
    Result<CapabilityInfo> detectNvmeCapabilities(const DeviceInfo& device);
    Result<CapabilityInfo> detectAtaCapabilities(const DeviceInfo& device);

    // USB mass storage, kept separate from ATA because the bridge chip between
    // host and media decides which commands actually arrive. Probes the bridge
    // and reports device-level mechanisms as UNKNOWN unless the absence of a
    // route is positively established.
    Result<CapabilityInfo> detectUsbCapabilities(const DeviceInfo& device);

    Result<bool> checkNvmeSanitizeSupport(int fd);
    Result<std::vector<std::string>> getNvmeSanitizeActions(int fd);
    Result<bool> checkAtaSecuritySupport(int fd);
    Result<bool> checkAtaSanitizeSupport(int fd);

    static Result<int> openDevice(const std::string& devicePath, bool readOnly = true);
    static void closeDevice(int fd);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace ledgerase