#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/device.hpp"
#include "ledgerase/capability.hpp"
#include "ledgerase/sanitization.hpp"
#include <string>
#include <vector>
#include <memory>

namespace ledgerase {

enum class MockDeviceType {
    HDD,
    SATA_SSD,
    NVME_SSD,
    UNSUPPORTED,
    FAILED,
    UNKNOWN_CAPABILITIES,
    // A USB mass-storage device whose bridge passes commands through to the
    // media. Exercises the path where a device-level mechanism is genuinely
    // available and the tool has to decide whether to use it.
    USB_BRIDGE_PASSTHROUGH,
    // A USB mass-storage device whose bridge accepts host commands and does
    // nothing with them. This is the dangerous case the capability probe exists
    // for: a device that looks like a SATA disk to a naive tool and reports
    // success while nothing is erased.
    USB_BRIDGE_DROPS_COMMANDS
};

// What the simulated bridge does with a command.
enum class MockBridgeBehaviour {
    // Passes the command through; the simulated media behaves like real media.
    PASSTHROUGH,
    // Accepts the command and silently discards it, reporting success. Nothing
    // is written to the simulated media.
    SILENTLY_DROPS
};

struct MockDeviceConfig {
    MockDeviceType type = MockDeviceType::NVME_SSD;
    std::string path = "/dev/nvme0n1";
    std::string model = "Mock NVMe SSD";
    std::string vendor = "MockVendor";
    std::string serial = "MOCK123456789";
    std::string firmware = "1.0.0";
    uint64_t capacityBytes = 512ULL * 1024 * 1024 * 1024;
    uint32_t logicalBlockSize = 512;
    uint32_t physicalBlockSize = 4096;
    // Interface reported by inspectDevice(). Set explicitly by each factory:
    // it must not be inferred from the injected-behaviour type, or a device
    // configured to fail becomes unrepresentable and the planner refuses it
    // before the failure can ever be demonstrated.
    TransportType transport = TransportType::UNKNOWN;
    bool rotational = false;
    bool removable = false;
    bool readOnly = false;
    bool mounted = false;
    bool systemDisk = false;
    bool bootDisk = false;
    std::vector<PartitionInfo> partitions;
    std::vector<FilesystemInfo> filesystems;
    CapabilityInfo capabilities;
    JobState simulateFailureAt = JobState::UNKNOWN;
    std::string failureMessage = "Simulated failure";
    int failureCode = static_cast<int>(ErrorCode::OPERATION_FAILED);

    // USB-specific. Ignored by every other device type.
    MockBridgeBehaviour bridgeBehaviour = MockBridgeBehaviour::PASSTHROUGH;
    std::string usbDeviceNode;      // synthetic sysfs path of the USB device
    std::string usbVendorId = "0781";
    std::string usbProductId = "5567";
    std::string usbProductName = "DataTraveler 3.0";
};

class MockBackend {
public:
    MockBackend();
    ~MockBackend();

    void addDevice(const MockDeviceConfig& config);
    void clearDevices();
    std::vector<MockDeviceConfig> getDevices() const;

    Result<std::vector<DeviceInfo>> discoverDevices();
    Result<DeviceInfo> inspectDevice(const std::string& devicePath);
    Result<CapabilityInfo> detectCapabilities(const DeviceInfo& device);
    Result<std::unique_ptr<ISanitizationMethod>> createMethod(
        SanitizationMethod method,
        const DeviceInfo& device,
        const CapabilityInfo& capabilities,
        const SanitizationPlan& plan);

    void setSimulationMode(bool enabled);
    bool isSimulationMode() const;

    static MockDeviceConfig createMockHdd();
    static MockDeviceConfig createMockSataSsd();
    static MockDeviceConfig createMockNvmeSsd();
    static MockDeviceConfig createMockUnsupported();
    static MockDeviceConfig createMockFailed();
    static MockDeviceConfig createMockUnknownCapabilities();

    // USB mass storage. Two profiles, because the interesting question is not
    // "can this tool talk to USB" but "what does it do when a bridge lies".
    static MockDeviceConfig createMockUsbBridgePassthrough();
    static MockDeviceConfig createMockUsbBridgeDropsCommands();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class MockNvmeSanitizeMethod : public ISanitizationMethod {
public:
    MockNvmeSanitizeMethod(const MockDeviceConfig& config,
                           SanitizationMethod method);
    ~MockNvmeSanitizeMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;
    bool isSimulated() const override { return true; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class MockAtaSanitizeMethod : public ISanitizationMethod {
public:
    MockAtaSanitizeMethod(const MockDeviceConfig& config,
                          SanitizationMethod method);
    ~MockAtaSanitizeMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;
    bool isSimulated() const override { return true; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// A USB mass-storage device driven through a simulated bridge.
//
// The point of this method is that it can be told to *lie*: to accept every
// command, report success, and write nothing. That is what real bridge chips
// do, and it is the case a tool must catch. A mock that failed loudly when
// configured to drop commands would test nothing, because a loud failure is
// never the behaviour being defended against.
class MockUsbOverwriteMethod : public ISanitizationMethod {
public:
    MockUsbOverwriteMethod(const MockDeviceConfig& config, SanitizationMethod method);
    ~MockUsbOverwriteMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;
    bool isSimulated() const override { return true; }

    // Whether the simulated media actually received the write. The verifier
    // reads this instead of assuming the write happened, which is the behaviour
    // being tested.
    bool mediaWasWritten() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class MockOverwriteMethod : public ISanitizationMethod {
public:
    MockOverwriteMethod(const MockDeviceConfig& config);
    ~MockOverwriteMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;
    bool isSimulated() const override { return true; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace ledgerase