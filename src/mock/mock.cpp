#include "mock.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <mutex>

namespace ledgerase {

class MockBackend::Impl {
public:
    std::vector<MockDeviceConfig> devices;
    bool simulationMode = true;
    std::mutex mutex;
};

MockBackend::MockBackend() : pImpl_(std::make_unique<Impl>()) {}
MockBackend::~MockBackend() = default;

void MockBackend::addDevice(const MockDeviceConfig& config) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->devices.push_back(config);
}

void MockBackend::clearDevices() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->devices.clear();
}

std::vector<MockDeviceConfig> MockBackend::getDevices() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->devices;
}

Result<std::vector<DeviceInfo>> MockBackend::discoverDevices() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<DeviceInfo> devices;

    for (const auto& config : pImpl_->devices) {
        DeviceInfo info;
        info.path = config.path;
        info.model = config.model;
        info.vendor = config.vendor;
        info.serial = config.serial;
        info.firmware = config.firmware;
        info.capacityBytes = config.capacityBytes;
        info.logicalBlockSize = config.logicalBlockSize;
        info.physicalBlockSize = config.physicalBlockSize;
        info.transport = config.transport;
        info.mediaType = config.type == MockDeviceType::HDD ? MediaType::HDD : MediaType::SSD;
        info.rotational = config.rotational;
        info.removable = config.removable;
        info.readOnly = config.readOnly;
        info.mounted = config.mounted;
        info.systemDisk = config.systemDisk;
        info.bootDisk = config.bootDisk;
        info.partitions = config.partitions;
        info.filesystems = config.filesystems;
        info.usbDeviceNode = config.usbDeviceNode;
        if (config.type == MockDeviceType::USB_BRIDGE_PASSTHROUGH ||
            config.type == MockDeviceType::USB_BRIDGE_DROPS_COMMANDS) {
            // A USB pen drive. The bridge commonly reports rotational=1 whatever
            // the media is, so removable is what identifies it.
            info.mediaType = MediaType::REMOVABLE;
            info.identitySource = "USB device descriptors";
        }
        info.discoveryTime = std::chrono::system_clock::now();
        devices.push_back(info);
    }

    return Result<std::vector<DeviceInfo>>::ok(devices);
}

Result<DeviceInfo> MockBackend::inspectDevice(const std::string& devicePath) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    for (const auto& config : pImpl_->devices) {
        if (config.path == devicePath) {
            DeviceInfo info;
            info.path = config.path;
            info.model = config.model;
            info.vendor = config.vendor;
            info.serial = config.serial;
            info.firmware = config.firmware;
            info.capacityBytes = config.capacityBytes;
            info.logicalBlockSize = config.logicalBlockSize;
            info.physicalBlockSize = config.physicalBlockSize;
            info.transport = config.transport;
            info.mediaType = config.type == MockDeviceType::HDD ? MediaType::HDD : MediaType::SSD;
            info.rotational = config.rotational;
            info.removable = config.removable;
            info.readOnly = config.readOnly;
            info.mounted = config.mounted;
            info.systemDisk = config.systemDisk;
            info.bootDisk = config.bootDisk;
            info.partitions = config.partitions;
            info.filesystems = config.filesystems;
            info.usbDeviceNode = config.usbDeviceNode;
            if (config.type == MockDeviceType::USB_BRIDGE_PASSTHROUGH ||
                config.type == MockDeviceType::USB_BRIDGE_DROPS_COMMANDS) {
                info.mediaType = MediaType::REMOVABLE;
                info.identitySource = "USB device descriptors";
            }
            info.discoveryTime = std::chrono::system_clock::now();
            return Result<DeviceInfo>::ok(info);
        }
    }

    return Result<DeviceInfo>::err(ErrorCode::DEVICE_NOT_FOUND, "Mock device not found: " + devicePath);
}

Result<CapabilityInfo> MockBackend::detectCapabilities(const DeviceInfo& device) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    for (const auto& config : pImpl_->devices) {
        if (config.path == device.path) {
            CapabilityInfo caps = config.capabilities;

            // Mirror what CapabilityDetector::detectUsbCapabilities() concludes
            // for each bridge behaviour, so a mock run exercises the same
            // decision the real detector makes.
            if (config.type == MockDeviceType::USB_BRIDGE_PASSTHROUGH) {
                caps.overwriteHost = CapabilityStatus::SUPPORTED;
                caps.cryptoEraseHost = CapabilityStatus::UNSUPPORTED;
                caps.ataSecureErase = CapabilityStatus::UNKNOWN;
                caps.ataEnhancedSecureErase = CapabilityStatus::UNKNOWN;
                caps.ataSanitizeBlockErase = CapabilityStatus::UNKNOWN;
                caps.ataSanitizeCryptoErase = CapabilityStatus::UNKNOWN;
                caps.ataSanitizeOverwrite = CapabilityStatus::UNKNOWN;
                caps.limitations.add(LimitationId::USB_BRIDGE_PROBE_PRESENT);
                caps.limitations.add(LimitationId::USB_BRIDGE_PROBE_PRESENT);
            } else if (config.type == MockDeviceType::USB_BRIDGE_DROPS_COMMANDS) {
                caps.overwriteHost = CapabilityStatus::SUPPORTED;
                caps.cryptoEraseHost = CapabilityStatus::UNSUPPORTED;
                caps.ataSecureErase = CapabilityStatus::UNSUPPORTED;
                caps.ataEnhancedSecureErase = CapabilityStatus::UNSUPPORTED;
                caps.ataSanitizeBlockErase = CapabilityStatus::UNSUPPORTED;
                caps.ataSanitizeCryptoErase = CapabilityStatus::UNSUPPORTED;
                caps.ataSanitizeOverwrite = CapabilityStatus::UNSUPPORTED;
                caps.limitations.add(LimitationId::USB_BRIDGE_PROBE_ABSENT);
                caps.limitations.add(
                    LimitationId::NO_DEVICE_LEVEL_MECHANISM,
                    "no device-level erase is reachable through this bridge");
            }
            if (config.type == MockDeviceType::USB_BRIDGE_PASSTHROUGH ||
                config.type == MockDeviceType::USB_BRIDGE_DROPS_COMMANDS) {
                caps.limitations.add(LimitationId::USB_BRIDGE_OPAQUE);
            }
            return Result<CapabilityInfo>::ok(caps);
        }
    }

    CapabilityInfo caps;
    caps.limitations.add(LimitationId::PROBE_FAILED);
    return Result<CapabilityInfo>::ok(caps);
}

Result<std::unique_ptr<ISanitizationMethod>> MockBackend::createMethod(
    SanitizationMethod method,
    const DeviceInfo& device,
    const CapabilityInfo& capabilities,
    const SanitizationPlan& plan) {

    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    MockDeviceConfig config;
    for (const auto& d : pImpl_->devices) {
        if (d.path == device.path) {
            config = d;
            break;
        }
    }

    if (config.type == MockDeviceType::UNSUPPORTED) {
        // A device that reports no usable sanitization mechanism must be
        // represented as unsupported, not quietly turned into a host overwrite.
        return Result<std::unique_ptr<ISanitizationMethod>>::ok(
            std::make_unique<UnsupportedMethod>(device, capabilities, plan));
    }

    if (config.type == MockDeviceType::NVME_SSD ||
        config.type == MockDeviceType::FAILED ||
        config.type == MockDeviceType::UNKNOWN_CAPABILITIES) {
        // The failing and unknown-capability devices are NVMe shapes with
        // injected behaviour; they must run through the NVMe mock so the
        // failure injection in MockNvmeSanitizeMethod is actually reached.
        return Result<std::unique_ptr<ISanitizationMethod>>::ok(
            std::make_unique<MockNvmeSanitizeMethod>(config, method));
    }

    if (config.type == MockDeviceType::USB_BRIDGE_PASSTHROUGH ||
        config.type == MockDeviceType::USB_BRIDGE_DROPS_COMMANDS) {
        // A bridge that drops commands must still report success, exactly as the
        // real hardware would. The failure has to be found by the read-back
        // verification, not by the command result, or the test would prove
        // nothing.
        return Result<std::unique_ptr<ISanitizationMethod>>::ok(
            std::make_unique<MockUsbOverwriteMethod>(config, method));
    }

    if (config.type == MockDeviceType::HDD || config.type == MockDeviceType::SATA_SSD) {
        return Result<std::unique_ptr<ISanitizationMethod>>::ok(
            std::make_unique<MockAtaSanitizeMethod>(config, method));
    }

    return Result<std::unique_ptr<ISanitizationMethod>>::ok(
        std::make_unique<MockOverwriteMethod>(config));
}

void MockBackend::setSimulationMode(bool enabled) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->simulationMode = enabled;
}

bool MockBackend::isSimulationMode() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->simulationMode;
}

MockDeviceConfig MockBackend::createMockHdd() {
    MockDeviceConfig config;
    config.type = MockDeviceType::HDD;
    config.transport = TransportType::SATA;
    config.path = "/dev/sdb";
    config.model = "Mock HDD 1TB";
    config.vendor = "MockVendor";
    config.serial = "MOCKHDD123456";
    config.firmware = "1.00";
    config.capacityBytes = 1000ULL * 1024 * 1024 * 1024;
    config.logicalBlockSize = 512;
    config.physicalBlockSize = 4096;
    config.rotational = true;
    config.removable = false;
    config.readOnly = false;

    config.capabilities.ataSecureErase = CapabilityStatus::SUPPORTED;
    config.capabilities.ataEnhancedSecureErase = CapabilityStatus::SUPPORTED;
    config.capabilities.ataSanitizeBlockErase = CapabilityStatus::SUPPORTED;
    config.capabilities.ataSanitizeOverwrite = CapabilityStatus::SUPPORTED;
    config.capabilities.overwriteHost = CapabilityStatus::SUPPORTED;
    config.capabilities.supportedSanitizeActions = {"Secure Erase", "Enhanced Secure Erase", "Block Erase", "Overwrite"};

    return config;
}

MockDeviceConfig MockBackend::createMockSataSsd() {
    MockDeviceConfig config;
    config.type = MockDeviceType::SATA_SSD;
    config.transport = TransportType::SATA;
    config.path = "/dev/sdc";
    config.model = "Mock SATA SSD 512GB";
    config.vendor = "MockVendor";
    config.serial = "MOCKSATA123456";
    config.firmware = "2.00";
    config.capacityBytes = 512ULL * 1024 * 1024 * 1024;
    config.logicalBlockSize = 512;
    config.physicalBlockSize = 4096;
    config.rotational = false;
    config.removable = false;
    config.readOnly = false;

    config.capabilities.ataSecureErase = CapabilityStatus::SUPPORTED;
    config.capabilities.ataEnhancedSecureErase = CapabilityStatus::SUPPORTED;
    config.capabilities.ataSanitizeBlockErase = CapabilityStatus::SUPPORTED;
    config.capabilities.ataSanitizeCryptoErase = CapabilityStatus::UNSUPPORTED;
    config.capabilities.ataSanitizeOverwrite = CapabilityStatus::SUPPORTED;
    config.capabilities.overwriteHost = CapabilityStatus::SUPPORTED;
    config.capabilities.supportedSanitizeActions = {"Secure Erase", "Enhanced Secure Erase", "Block Erase", "Overwrite"};
    config.capabilities.limitations.add(LimitationId::HOST_SCOPE_ONLY);

    return config;
}

MockDeviceConfig MockBackend::createMockNvmeSsd() {
    MockDeviceConfig config;
    config.type = MockDeviceType::NVME_SSD;
    config.transport = TransportType::NVME;
    config.path = "/dev/nvme0n1";
    config.model = "Mock NVMe SSD 1TB";
    config.vendor = "MockVendor";
    config.serial = "MOCKNVME123456";
    config.firmware = "3.00";
    config.capacityBytes = 1000ULL * 1024 * 1024 * 1024;
    config.logicalBlockSize = 512;
    config.physicalBlockSize = 4096;
    config.rotational = false;
    config.removable = false;
    config.readOnly = false;

    config.capabilities.nvmeBlockErase = CapabilityStatus::SUPPORTED;
    config.capabilities.nvmeCryptoErase = CapabilityStatus::SUPPORTED;
    config.capabilities.nvmeOverwrite = CapabilityStatus::SUPPORTED;
    config.capabilities.nvmeSanitizeSupported = true;
    config.capabilities.nvmeControllerModel = "Mock NVMe Controller";
    config.capabilities.nvmeFirmware = "3.00";
    config.capabilities.nvmeNamespaceId = 1;
    config.capabilities.supportedSanitizeActions = {"Block Erase", "Crypto Erase", "Overwrite"};
    config.capabilities.overwriteHost = CapabilityStatus::SUPPORTED;
    config.capabilities.limitations.add(LimitationId::HOST_SCOPE_ONLY);

    return config;
}

MockDeviceConfig MockBackend::createMockUnsupported() {
    MockDeviceConfig config;
    config.type = MockDeviceType::UNSUPPORTED;
    config.transport = TransportType::UNKNOWN;
    config.path = "/dev/sdd";
    config.model = "Mock Unsupported Device";
    config.vendor = "MockVendor";
    config.serial = "MOCKUNSUP12345";
    config.firmware = "1.00";
    config.capacityBytes = 256ULL * 1024 * 1024 * 1024;
    config.logicalBlockSize = 512;
    config.physicalBlockSize = 512;
    config.rotational = true;

    config.capabilities.ataSecureErase = CapabilityStatus::UNSUPPORTED;
    config.capabilities.ataEnhancedSecureErase = CapabilityStatus::UNSUPPORTED;
    config.capabilities.ataSanitizeBlockErase = CapabilityStatus::UNSUPPORTED;
    config.capabilities.overwriteHost = CapabilityStatus::SUPPORTED;
    config.capabilities.limitations.add(LimitationId::NO_DEVICE_LEVEL_MECHANISM);
    config.capabilities.limitations.add(LimitationId::NO_DEVICE_LEVEL_MECHANISM);

    return config;
}

MockDeviceConfig MockBackend::createMockUsbBridgePassthrough() {
    MockDeviceConfig config;
    config.type = MockDeviceType::USB_BRIDGE_PASSTHROUGH;
    config.transport = TransportType::USB;
    // Deliberately a /dev/sdX path. That is exactly the naming convention the
    // containment bug was blind to, so a mock USB device exercises the safety
    // layer the way real removable media does.
    config.path = "/dev/sdf";
    config.model = "Mock USB Flash 64GB";
    config.vendor = "MockVendor";
    config.serial = "MOCKUSB123456";
    config.firmware = "1.00";
    config.capacityBytes = 64ULL * 1024 * 1024 * 1024;
    config.logicalBlockSize = 512;
    config.physicalBlockSize = 4096;
    // The bridge lies about this regardless of the media inside it.
    config.rotational = true;
    config.removable = true;
    config.readOnly = false;
    config.bridgeBehaviour = MockBridgeBehaviour::PASSTHROUGH;
    config.usbDeviceNode = "/sys/devices/pci0000:00/usb1/1-2";
    config.capabilities.supportedSanitizeActions = {};
    config.capabilities.limitations.add(LimitationId::USB_BRIDGE_PROBE_PRESENT);
    return config;
}

MockDeviceConfig MockBackend::createMockUsbBridgeDropsCommands() {
    MockDeviceConfig config = createMockUsbBridgePassthrough();
    config.type = MockDeviceType::USB_BRIDGE_DROPS_COMMANDS;
    config.path = "/dev/sdg";
    config.model = "Mock USB Flash (bridge drops commands)";
    config.serial = "MOCKUSBDROP001";
    config.capacityBytes = 32ULL * 1024 * 1024 * 1024;
    config.bridgeBehaviour = MockBridgeBehaviour::SILENTLY_DROPS;
    config.usbDeviceNode = "/sys/devices/pci0000:00/usb1/1-3";
    config.capabilities.limitations.add(LimitationId::USB_BRIDGE_OPAQUE);
    return config;
}

MockDeviceConfig MockBackend::createMockFailed() {
    MockDeviceConfig config = createMockNvmeSsd();
    config.type = MockDeviceType::FAILED;
    config.transport = TransportType::NVME;
    config.path = "/dev/nvme1n1";
    config.model = "Mock Failing NVMe";
    config.serial = "MOCKFAIL123456";
    config.capabilities.nvmeBlockErase = CapabilityStatus::SUPPORTED;
    config.capabilities.nvmeCryptoErase = CapabilityStatus::SUPPORTED;
    config.simulateFailureAt = JobState::EXECUTING;
    config.failureMessage = "Simulated device failure during sanitize";
    config.failureCode = static_cast<int>(ErrorCode::OPERATION_FAILED);
    return config;
}

MockDeviceConfig MockBackend::createMockUnknownCapabilities() {
    MockDeviceConfig config = createMockNvmeSsd();
    config.type = MockDeviceType::UNKNOWN_CAPABILITIES;
    config.transport = TransportType::NVME;
    config.path = "/dev/nvme2n1";
    config.model = "Mock Unknown NVMe";
    config.serial = "MOCKUNKN123456";
    config.capabilities.nvmeBlockErase = CapabilityStatus::UNKNOWN;
    config.capabilities.nvmeCryptoErase = CapabilityStatus::UNKNOWN;
    config.capabilities.nvmeOverwrite = CapabilityStatus::UNKNOWN;
    config.capabilities.nvmeSanitizeSupported = false;
    config.capabilities.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
    config.capabilities.limitations.add(LimitationId::CAPABILITY_UNKNOWN);
    return config;
}

class MockNvmeSanitizeMethod::Impl {
public:
    Impl(const MockDeviceConfig& cfg, SanitizationMethod m)
        : config(cfg), method(m), jobId("mock-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count())) {}

    MockDeviceConfig config;
    SanitizationMethod method;
    std::string jobId;
    JobStatus status;
    bool cancelled = false;
    int progress = 0;
};

MockNvmeSanitizeMethod::MockNvmeSanitizeMethod(const MockDeviceConfig& config, SanitizationMethod method)
    : pImpl_(std::make_unique<Impl>(config, method)) {}

MockNvmeSanitizeMethod::~MockNvmeSanitizeMethod() = default;

Result<void> MockNvmeSanitizeMethod::execute() {
    auto& impl = *pImpl_;

    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.config.path;
    impl.status.startTime = std::chrono::system_clock::now();
    impl.status.currentOperation = "Mock NVMe " + methodToString(impl.method);
    impl.status.totalBytes = impl.config.capacityBytes;
    impl.progress = 0;

    if (impl.config.type == MockDeviceType::FAILED && impl.config.simulateFailureAt == JobState::EXECUTING) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = impl.config.failureMessage;
        impl.status.errorCode = impl.config.failureCode;
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::OPERATION_FAILED, impl.config.failureMessage);
    }

    impl.status.state = JobState::MONITORING;

    for (int i = 0; i <= 100 && !impl.cancelled; i += 10) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        impl.progress = i;
        impl.status.progressValid = true;
        impl.status.progressPercent = i;
        impl.status.bytesProcessed = (impl.config.capacityBytes * i) / 100;
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - impl.status.startTime);
    }

    if (impl.cancelled) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = "Operation cancelled";
        impl.status.errorCode = static_cast<int>(ErrorCode::CANCELLED);
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::CANCELLED, "Operation cancelled");
    }

    if (impl.config.type == MockDeviceType::FAILED && impl.config.simulateFailureAt == JobState::MONITORING) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = impl.config.failureMessage;
        impl.status.errorCode = impl.config.failureCode;
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::OPERATION_FAILED, impl.config.failureMessage);
    }

    impl.status.state = JobState::COMPLETED;
    impl.status.currentOperation = "Completed successfully";
    impl.status.progressValid = true;
    impl.status.progressPercent = 100;
    impl.status.bytesProcessed = impl.config.capacityBytes;
    impl.status.endTime = std::chrono::system_clock::now();
    impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
        impl.status.endTime - impl.status.startTime);

    return Result<void>::success();
}

Result<void> MockNvmeSanitizeMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> MockNvmeSanitizeMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> MockNvmeSanitizeMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    if (pImpl_->status.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "mock_nvme_status",
            "Mock NVMe sanitize status",
            true,
            "Simulated device reported successful completion",
            {LimitationId::HOST_SCOPE_ONLY}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "mock_nvme_status",
            "Mock NVMe sanitize status",
            false,
            pImpl_->status.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
    }

    report.scope.push_back("Mock NVMe Sanitize command completion");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);

    return Result<VerificationReport>::ok(report);
}

std::string MockNvmeSanitizeMethod::describe() const {
    return "Mock NVMe Sanitize (" + methodToString(pImpl_->method) + ")";
}

LimitationSet MockNvmeSanitizeMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::DEVICE_SELF_REPORT);
    return out;
}

SanitizationMethod MockNvmeSanitizeMethod::methodType() const {
    return pImpl_->method;
}

bool MockNvmeSanitizeMethod::supportsCancel() const {
    return true;
}

bool MockNvmeSanitizeMethod::supportsProgress() const {
    return true;
}

class MockAtaSanitizeMethod::Impl {
public:
    Impl(const MockDeviceConfig& cfg, SanitizationMethod m)
        : config(cfg), method(m), jobId("mock-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count())) {}

    MockDeviceConfig config;
    SanitizationMethod method;
    std::string jobId;
    JobStatus status;
    bool cancelled = false;
};

MockAtaSanitizeMethod::MockAtaSanitizeMethod(const MockDeviceConfig& config, SanitizationMethod method)
    : pImpl_(std::make_unique<Impl>(config, method)) {}

MockAtaSanitizeMethod::~MockAtaSanitizeMethod() = default;

Result<void> MockAtaSanitizeMethod::execute() {
    auto& impl = *pImpl_;

    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.config.path;
    impl.status.startTime = std::chrono::system_clock::now();
    impl.status.currentOperation = "Mock ATA " + methodToString(impl.method);
    impl.status.totalBytes = impl.config.capacityBytes;

    if (impl.config.type == MockDeviceType::FAILED && impl.config.simulateFailureAt == JobState::EXECUTING) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = impl.config.failureMessage;
        impl.status.errorCode = impl.config.failureCode;
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::OPERATION_FAILED, impl.config.failureMessage);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    if (impl.cancelled) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = "Operation cancelled";
        impl.status.errorCode = static_cast<int>(ErrorCode::CANCELLED);
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::CANCELLED, "Operation cancelled");
    }

    impl.status.state = JobState::COMPLETED;
    impl.status.currentOperation = "Completed successfully";
    impl.status.progressValid = true;
    impl.status.progressPercent = 100;
    impl.status.bytesProcessed = impl.config.capacityBytes;
    impl.status.endTime = std::chrono::system_clock::now();
    impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
        impl.status.endTime - impl.status.startTime);

    return Result<void>::success();
}

Result<void> MockAtaSanitizeMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> MockAtaSanitizeMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> MockAtaSanitizeMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    if (pImpl_->status.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "mock_ata_status",
            "Mock ATA sanitize status",
            true,
            "Simulated device reported successful completion",
            {LimitationId::HOST_SCOPE_ONLY}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "mock_ata_status",
            "Mock ATA sanitize status",
            false,
            pImpl_->status.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
    }

    report.scope.push_back("Mock ATA command completion");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);

    return Result<VerificationReport>::ok(report);
}

std::string MockAtaSanitizeMethod::describe() const {
    return "Mock ATA Sanitize (" + methodToString(pImpl_->method) + ")";
}

LimitationSet MockAtaSanitizeMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::DEVICE_SELF_REPORT);
    return out;
}

SanitizationMethod MockAtaSanitizeMethod::methodType() const {
    return pImpl_->method;
}

bool MockAtaSanitizeMethod::supportsCancel() const {
    return true;
}

bool MockAtaSanitizeMethod::supportsProgress() const {
    return false;
}

class MockOverwriteMethod::Impl {
public:
    Impl(const MockDeviceConfig& cfg)
        : config(cfg), jobId("mock-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count())) {}

    MockDeviceConfig config;
    std::string jobId;
    JobStatus status;
    bool cancelled = false;
};

MockOverwriteMethod::MockOverwriteMethod(const MockDeviceConfig& config)
    : pImpl_(std::make_unique<Impl>(config)) {}

MockOverwriteMethod::~MockOverwriteMethod() = default;

Result<void> MockOverwriteMethod::execute() {
    auto& impl = *pImpl_;

    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.config.path;
    impl.status.startTime = std::chrono::system_clock::now();
    impl.status.currentOperation = "Mock Host Overwrite";
    impl.status.totalBytes = impl.config.capacityBytes;

    for (int i = 0; i <= 100 && !impl.cancelled; i += 20) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        impl.status.progressValid = true;
        impl.status.progressPercent = i;
        impl.status.bytesProcessed = (impl.config.capacityBytes * i) / 100;
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - impl.status.startTime);
    }

    if (impl.cancelled) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = "Operation cancelled";
        impl.status.errorCode = static_cast<int>(ErrorCode::CANCELLED);
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::CANCELLED, "Operation cancelled");
    }

    impl.status.state = JobState::COMPLETED;
    impl.status.currentOperation = "Completed successfully";
    impl.status.progressValid = true;
    impl.status.progressPercent = 100;
    impl.status.bytesProcessed = impl.config.capacityBytes;
    impl.status.endTime = std::chrono::system_clock::now();
    impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
        impl.status.endTime - impl.status.startTime);

    return Result<void>::success();
}

Result<void> MockOverwriteMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> MockOverwriteMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> MockOverwriteMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    if (pImpl_->status.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "mock_host_overwrite",
            "Mock host overwrite completion",
            true,
            "Simulated host overwrite completed with sync",
            {LimitationId::HOST_SCOPE_ONLY}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "mock_host_overwrite",
            "Mock host overwrite completion",
            false,
            pImpl_->status.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
    }

    report.scope.push_back("Mock host-level write to all logical sectors");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);

    return Result<VerificationReport>::ok(report);
}

std::string MockOverwriteMethod::describe() const {
    return "Mock Host Overwrite (single pass, zero fill)";
}

LimitationSet MockOverwriteMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::CLEAR_ONLY);
    return out;
}

SanitizationMethod MockOverwriteMethod::methodType() const {
    return SanitizationMethod::OVERWRITE_HOST;
}

bool MockOverwriteMethod::supportsCancel() const {
    return true;
}

bool MockOverwriteMethod::supportsProgress() const {
    return true;
}

class MockUsbOverwriteMethod::Impl {
public:
    Impl(const MockDeviceConfig& cfg, SanitizationMethod m)
        : config(cfg), method(m),
          jobId("mock-" + std::to_string(std::chrono::system_clock::now()
                                             .time_since_epoch().count())) {}

    MockDeviceConfig config;
    SanitizationMethod method;
    std::string jobId;
    JobStatus status;
    bool cancelled = false;
    bool mediaWasWritten = false;
};

MockUsbOverwriteMethod::MockUsbOverwriteMethod(const MockDeviceConfig& config,
                                               SanitizationMethod method)
    : pImpl_(std::make_unique<Impl>(config, method)) {}

MockUsbOverwriteMethod::~MockUsbOverwriteMethod() = default;

bool MockUsbOverwriteMethod::mediaWasWritten() const {
    return pImpl_->mediaWasWritten;
}

Result<void> MockUsbOverwriteMethod::execute() {
    auto& impl = *pImpl_;

    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.config.path;
    impl.status.startTime = std::chrono::system_clock::now();
    impl.status.currentOperation = "Mock USB " + methodToString(impl.method);
    impl.status.totalBytes = impl.config.capacityBytes;

    for (int i = 0; i <= 100 && !impl.cancelled; i += 20) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        impl.status.progressValid = true;
        impl.status.progressPercent = static_cast<uint64_t>(i);
        impl.status.bytesProcessed = (impl.config.capacityBytes * i) / 100;
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - impl.status.startTime);
    }

    if (impl.cancelled) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = "Operation cancelled";
        impl.status.errorCode = static_cast<int>(ErrorCode::CANCELLED);
        impl.status.endTime = std::chrono::system_clock::now();
        return Result<void>::err(ErrorCode::CANCELLED, "Operation cancelled");
    }

    // The bridge's behaviour is applied here and nowhere else. A bridge that
    // drops commands still returns success: the host is told the write happened,
    // and the media is untouched. Only a read-back can tell the difference.
    impl.mediaWasWritten =
        impl.config.bridgeBehaviour == MockBridgeBehaviour::PASSTHROUGH;

    impl.status.state = JobState::COMPLETED;
    impl.status.currentOperation = "Completed successfully";
    impl.status.progressValid = true;
    impl.status.progressPercent = 100;
    impl.status.bytesProcessed = impl.config.capacityBytes;
    impl.status.endTime = std::chrono::system_clock::now();
    impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
        impl.status.endTime - impl.status.startTime);

    return Result<void>::success();
}

Result<void> MockUsbOverwriteMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> MockUsbOverwriteMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> MockUsbOverwriteMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    // Stand-in for the real read-back. The real verifier opens the device and
    // inspects the media; here the simulated bridge's behaviour is what the
    // media would show.
    if (pImpl_->status.state != JobState::COMPLETED) {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "mock_usb_read_back",
            "Mock read-back of the overwrite pattern",
            false,
            pImpl_->status.errorMessage,
            {{LimitationId::VERIFICATION_FAILED, "the mock did not complete"}}
        });
        return Result<VerificationReport>::ok(report);
    }

    if (pImpl_->mediaWasWritten) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "mock_usb_read_back",
            "Mock read-back of the overwrite pattern",
            true,
            "All sampled sectors hold the overwrite pattern, as a passing bridge "
            "would produce",
            {LimitationId::HOST_SCOPE_ONLY, LimitationId::USB_BRIDGE_OPAQUE}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "mock_usb_read_back",
            "Mock read-back of the overwrite pattern",
            false,
            "The bridge reported a successful write but every sampled sector still "
            "holds its previous contents. The commands were accepted and discarded.",
            {{LimitationId::USB_BRIDGE_OPAQUE,
              "a bridge that accepts and drops commands looks like success on "
              "the write path alone"}}
        });
    }

    report.evidence.push_back({
        "host_write",
        "Host-level overwrite completion with flush",
        true,
        "The overwrite ran to completion and the writes were flushed to the device",
        {LimitationId::DEVICE_SELF_REPORT}
    });

    report.scope.push_back("Mock host-level write to all logical block addresses");
    report.scope.push_back("Mock read-back of sectors sampled across the address space");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::USB_BRIDGE_OPAQUE);
    report.limitations.add(LimitationId::SELF_VERIFIED);

    return Result<VerificationReport>::ok(report);
}

std::string MockUsbOverwriteMethod::describe() const {
    return "Mock USB " + methodToString(pImpl_->method) + " (bridge " +
           (pImpl_->config.bridgeBehaviour == MockBridgeBehaviour::PASSTHROUGH
                ? "passthrough"
                : "drops commands") +
           ")";
}

LimitationSet MockUsbOverwriteMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::USB_BRIDGE_OPAQUE);
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::CLEAR_ONLY);
    return out;
}

SanitizationMethod MockUsbOverwriteMethod::methodType() const {
    return pImpl_->method;
}

bool MockUsbOverwriteMethod::supportsCancel() const {
    return true;
}

bool MockUsbOverwriteMethod::supportsProgress() const {
    return true;
}

} // namespace ledgerase
