#include "ledgerase/sanitization.hpp"
#include "ledgerase/progress_reporter.hpp"
#include "ledgerase/policy.hpp"
#include "ledgerase/verification.hpp"
#include "ledgerase/platform/linux.hpp"
#include <chrono>
#include <thread>
#include <random>
#include <sstream>
#include <iomanip>
#include <functional>
#include <utility>
#include <algorithm>
#include <sys/stat.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace ledgerase {

namespace {
// Upper bound on how long we wait for a device-reported sanitize completion.
// A controller that never leaves the in-progress state must not hang the tool
// forever; exceeding this is reported as a failure, not as success.
constexpr std::chrono::seconds kNvmeSanitizeTimeout{24 * 60 * 60};

// Builds the SanitizerError for a failure path from whichever argument list
// Result<void>::err() was called with, so the fail() helpers below can accept
// both an existing error and an (code, message, action) triple.
template<typename... Args>
SanitizerError makeSanitizerError(Args&&... args) {
    return SanitizerError(std::forward<Args>(args)...);
}
} // namespace

class SanitizationExecutor::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    SanitizationMethodFactory factory;
};

SanitizationExecutor::SanitizationExecutor() : pImpl_(std::make_unique<Impl>()) {}
SanitizationExecutor::~SanitizationExecutor() = default;

std::string SanitizationExecutor::generateJobId() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y%m%dT%H%M%SZ");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    ss << "-" << dis(gen);

    return ss.str();
}

Result<std::unique_ptr<ISanitizationMethod>> SanitizationExecutor::createMethod(
    SanitizationMethod method,
    const DeviceInfo& device,
    const CapabilityInfo& capabilities,
    const SanitizationPlan& plan) {

    // A simulation factory replaces the real-hardware methods entirely. This
    // is the only place a method is constructed, so a mock plan can never be
    // handed to a method that would open a real device.
    if (pImpl_->factory) {
        return pImpl_->factory(method, device, capabilities, plan);
    }

    switch (method) {
        case SanitizationMethod::NVME_BLOCK_ERASE:
        case SanitizationMethod::NVME_CRYPTO_ERASE:
        case SanitizationMethod::NVME_OVERWRITE:
            return Result<std::unique_ptr<ISanitizationMethod>>::ok(
                std::make_unique<NvmeSanitizeMethod>(device, capabilities, plan));

        case SanitizationMethod::ATA_SECURE_ERASE:
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE:
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            return Result<std::unique_ptr<ISanitizationMethod>>::ok(
                std::make_unique<AtaSanitizeMethod>(device, capabilities, plan));

        case SanitizationMethod::OVERWRITE_HOST:
            return Result<std::unique_ptr<ISanitizationMethod>>::ok(
                std::make_unique<OverwriteMethod>(device, capabilities, plan));

        case SanitizationMethod::CRYPTO_ERASE_HOST:
            return Result<std::unique_ptr<ISanitizationMethod>>::ok(
                std::make_unique<CryptoEraseMethod>(device, capabilities, plan));

        default:
            return Result<std::unique_ptr<ISanitizationMethod>>::ok(
                std::make_unique<UnsupportedMethod>(device, capabilities, plan));
    }
}

Result<void> SanitizationExecutor::execute(const SanitizationPlan& plan,
                                           std::function<void(const JobStatus&)> progressCallback) {
    if (plan.dryRun) {
        return Result<void>::err(ErrorCode::DRY_RUN_ONLY,
                                "Dry run mode - no destructive actions performed",
                                "Remove --dry-run flag to execute");
    }

    // Delegates to executeWithMonitoring so that the progress callback, state
    // machine and dry-run handling have exactly one implementation.
    auto result = executeWithMonitoring(plan, std::move(progressCallback));
    if (result.isError()) {
        return Result<void>::err(result.error());
    }

    // A FAILED terminal state is an error even though executeWithMonitoring
    // reports it as a successful Result<JobStatus> carrying the failure.
    if (result.value().state != JobState::COMPLETED) {
        return Result<void>::err(ErrorCode::OPERATION_FAILED,
                                result.value().errorMessage.empty()
                                    ? std::string("Sanitization did not complete")
                                    : result.value().errorMessage);
    }

    return Result<void>::success();
}

void SanitizationExecutor::setMethodFactory(SanitizationMethodFactory factory) {
    pImpl_->factory = std::move(factory);
}

bool SanitizationExecutor::hasMethodFactory() const {
    return static_cast<bool>(pImpl_->factory);
}

Result<JobStatus> SanitizationExecutor::runMethod(
    ISanitizationMethod& method,
    const SanitizationPlan& plan,
    std::function<void(const JobStatus&)> progressCallback,
    VerificationReport* outMethodVerification) {

    const auto started = std::chrono::system_clock::now();

    // Asked after execution, never before: a method's verification describes
    // what the method did, so querying it first would return evidence about an
    // operation that has not happened yet.
    auto askMethod = [&method, outMethodVerification] {
        if (outMethodVerification == nullptr) {
            return;
        }
        auto own = method.verify();
        if (own.ok()) {
            *outMethodVerification = own.value();
        }
    };

    auto execResult = method.execute();
    askMethod();
    if (execResult.isError()) {
        // The failure is authoritative. Do not consult method.status() here:
        // a method that aborted before initialising its own status would
        // otherwise overwrite FAILED with a default-constructed UNKNOWN,
        // silently discarding the error code and message.
        JobStatus failed;
        failed.jobId = plan.jobId;
        failed.state = JobState::FAILED;
        failed.devicePath = plan.device.path;
        failed.errorMessage = execResult.error().what();
        failed.errorCode = static_cast<int>(execResult.error().code());
        failed.endTime = std::chrono::system_clock::now();
        failed.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            failed.endTime - started);
        failed.simulated = method.isSimulated();

        if (progressCallback) {
            progressCallback(failed);
        }
        return Result<JobStatus>::ok(failed);
    }

    // Re-asked on the success path: the method's status may have been updated
    // after execute() returned, and the verification is expected to describe the
    // final state.
    askMethod();

    JobStatus finalStatus;
    finalStatus.jobId = plan.jobId;
    finalStatus.state = JobState::COMPLETED;
    finalStatus.devicePath = plan.device.path;
    finalStatus.currentOperation = "Completed";

    auto statusResult = method.status();
    if (statusResult.ok()) {
        finalStatus = statusResult.value();
        finalStatus.jobId = plan.jobId;

        // A method that reports success but leaves its state unset must not be
        // reported as COMPLETED on the strength of the default alone.
        if (finalStatus.state == JobState::UNKNOWN) {
            finalStatus.state = JobState::COMPLETED;
            finalStatus.errorMessage = "Method reported success without a terminal state";
        }
    } else {
        finalStatus.state = JobState::FAILED;
        finalStatus.errorMessage =
            std::string("Method completed but did not report a status: ") +
            statusResult.error().what();
        finalStatus.errorCode = static_cast<int>(statusResult.error().code());
    }

    // Fill in anything the method left unset so no field is ever indeterminate
    // or misleading in a certificate.
    if (finalStatus.devicePath.empty()) {
        finalStatus.devicePath = plan.device.path;
    }
    if (finalStatus.startTime == std::chrono::system_clock::time_point{}) {
        finalStatus.startTime = started;
    }
    if (finalStatus.endTime == std::chrono::system_clock::time_point{}) {
        finalStatus.endTime = std::chrono::system_clock::now();
    }
    if (finalStatus.elapsedTime.count() < 0) {
        finalStatus.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            finalStatus.endTime - finalStatus.startTime);
    }
    finalStatus.simulated = method.isSimulated();

    if (progressCallback) {
        progressCallback(finalStatus);
    }

    return Result<JobStatus>::ok(finalStatus);
}

Result<JobStatus> SanitizationExecutor::executeWithMonitoring(const SanitizationPlan& plan,
                                                               std::function<void(const JobStatus&)> progressCallback,
                                                               VerificationReport* outMethodVerification) {
    if (outMethodVerification != nullptr) {
        *outMethodVerification = VerificationReport();
    }
    if (plan.dryRun) {
        JobStatus status;
        status.jobId = plan.jobId;
        status.state = JobState::PLANNING;
        status.devicePath = plan.device.path;
        status.currentOperation = "Dry run - plan generated";
        status.simulated = hasMethodFactory();
        return Result<JobStatus>::ok(status);
    }

    auto methodResult = createMethod(plan.selectedMethod, plan.device, plan.capabilities, plan);
    if (methodResult.isError()) {
        JobStatus status;
        status.jobId = plan.jobId;
        status.state = JobState::FAILED;
        status.errorMessage = methodResult.error().what();
        status.errorCode = static_cast<int>(methodResult.error().code());
        status.devicePath = plan.device.path;
        if (progressCallback) {
            progressCallback(status);
        }
        return Result<JobStatus>::err(methodResult.error());
    }

    auto method = std::move(methodResult.value());
    return runMethod(*method, plan, std::move(progressCallback), outMethodVerification);
}

class NvmeSanitizeMethod::Impl {
public:
    Impl(const DeviceInfo& dev, const CapabilityInfo& caps, const SanitizationPlan& pl)
        : device(dev), capabilities(caps), plan(pl), jobId(pl.jobId) {}

    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationPlan plan;
    std::string jobId;
    JobStatus status;
    int fd = -1;
    uint8_t sanitizeAction = 0;
    bool cancelled = false;
};

NvmeSanitizeMethod::NvmeSanitizeMethod(const DeviceInfo& device,
                                        const CapabilityInfo& capabilities,
                                        const SanitizationPlan& plan)
    : pImpl_(std::make_unique<Impl>(device, capabilities, plan)) {}

NvmeSanitizeMethod::~NvmeSanitizeMethod() {
    if (pImpl_->fd >= 0) {
        platform::linux::closeDevice(pImpl_->fd);
    }
}

Result<void> NvmeSanitizeMethod::execute() {
    auto& impl = *pImpl_;

    // Single exit point for failure: records the state, error and duration,
    // releases the device, and returns the error to the caller.
    auto fail = [&impl](auto&&... args) {
        const SanitizerError error = makeSanitizerError(std::forward<decltype(args)>(args)...);
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = error.what();
        impl.status.errorCode = static_cast<int>(error.code());
        if (impl.fd >= 0) {
            platform::linux::closeDevice(impl.fd);
            impl.fd = -1;
        }
        impl.status.endTime = std::chrono::system_clock::now();
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            impl.status.endTime - impl.status.startTime);
        return Result<void>::err(error);
    };


    // Identity is recorded before any syscall so a status is always populated,
    // even on the earliest failure path.
    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.device.path;
    impl.status.startTime = std::chrono::system_clock::now();

    auto fdResult = platform::linux::openDevice(impl.device.path, false);
    if (fdResult.isError()) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = fdResult.error().what();
        impl.status.errorCode = static_cast<int>(fdResult.error().code());
        impl.status.currentOperation = "Failed to open device";
        impl.status.endTime = std::chrono::system_clock::now();
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            impl.status.endTime - impl.status.startTime);
        return fail(fdResult.error());
    }
    impl.fd = fdResult.value();

    impl.status.currentOperation = "Starting NVMe sanitize";

    switch (impl.plan.selectedMethod) {
        case SanitizationMethod::NVME_BLOCK_ERASE:
            impl.sanitizeAction = 0x01;
            impl.status.currentOperation = "NVMe Block Erase";
            break;
        case SanitizationMethod::NVME_CRYPTO_ERASE:
            impl.sanitizeAction = 0x02;
            impl.status.currentOperation = "NVMe Crypto Erase";
            break;
        case SanitizationMethod::NVME_OVERWRITE:
            impl.sanitizeAction = 0x03;
            impl.status.currentOperation = "NVMe Overwrite";
            break;
        default:
            platform::linux::closeDevice(impl.fd);
            return fail(ErrorCode::UNSUPPORTED_OPERATION,
                                    "Invalid NVMe sanitize method");
    }

    // The Sanitize command carries the namespace id it applies to, and namespace
    // 0 is not a valid target. If the id could not be established, refuse rather
    // than issue a command aimed at namespace 0 - or, worse, at a hardcoded 1
    // that happens to be a different namespace on a multi-namespace controller.
    if (impl.capabilities.nvmeNamespaceId == 0) {
        return fail(ErrorCode::CAPABILITY_UNKNOWN,
                    "The NVMe namespace id for " + impl.device.path +
                        " could not be established, so the Sanitize command cannot be "
                        "addressed to the intended namespace",
                    "Run 'capabilities <device>' to see the reported namespace id. "
                    "A sanitize aimed at the wrong namespace would erase something "
                    "other than the target.");
    }

    auto execResult = platform::linux::nvmeSanitize(impl.fd, impl.capabilities.nvmeNamespaceId,
                                                   impl.sanitizeAction,
                                                   impl.plan.overwritePassCount);
    if (execResult.isError()) {
        platform::linux::closeDevice(impl.fd);
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = execResult.error().what();
        impl.status.errorCode = static_cast<int>(execResult.error().code());
        impl.status.endTime = std::chrono::system_clock::now();
        return fail(execResult.error());
    }

    impl.status.state = JobState::MONITORING;

    while (!impl.cancelled) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        auto statusResult = platform::linux::nvmeSanitizeStatus(impl.fd, impl.capabilities.nvmeNamespaceId);
        if (statusResult.isError()) {
            impl.status.state = JobState::FAILED;
            impl.status.errorMessage =
                std::string("Failed to read sanitize status: ") + statusResult.error().what();
            impl.status.errorCode = static_cast<int>(statusResult.error().code());
            break;
        }

        const auto& sanStatus = statusResult.value();

        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - impl.status.startTime);

        // Only report progress when the controller actually reports it.
        // SPPROG == 0xFFFF means "progress not available" and must not be
        // rendered as 100% or 0%.
        if (sanStatus.progressValid) {
            impl.status.progressValid = true;
            impl.status.progressPercent = sanStatus.progressPercent;
        } else {
            impl.status.progressValid = false;
        }

        switch (sanStatus.state) {
            case platform::linux::NvmeSanitizeState::COMPLETED:
                impl.status.state = JobState::COMPLETED;
                impl.status.currentOperation = "Completed successfully";
                impl.status.progressValid = true;
                impl.status.progressPercent = 100;
                impl.status.endTime = std::chrono::system_clock::now();
                break;

            case platform::linux::NvmeSanitizeState::FAILED:
                impl.status.state = JobState::FAILED;
                impl.status.errorMessage = "Sanitize operation failed (device reported failure in Sanitize Status log)";
                impl.status.errorCode = static_cast<int>(ErrorCode::OPERATION_FAILED);
                impl.status.endTime = std::chrono::system_clock::now();
                break;

            case platform::linux::NvmeSanitizeState::IN_PROGRESS:
                impl.status.state = JobState::MONITORING;
                break;

            case platform::linux::NvmeSanitizeState::NOT_STARTED:
                // The controller reports that no sanitize is in progress while
                // the command has been accepted but not yet begun. Keep
                // polling rather than assuming completion.
                impl.status.state = JobState::MONITORING;
                break;

            case platform::linux::NvmeSanitizeState::UNKNOWN:
            default:
                impl.status.state = JobState::MONITORING;
                break;
        }

        if (impl.status.state == JobState::COMPLETED ||
            impl.status.state == JobState::FAILED) {
            break;
        }

        if (impl.cancelled) {
            impl.status.state = JobState::FAILED;
            impl.status.errorMessage = "Operation cancelled";
            impl.status.errorCode = static_cast<int>(ErrorCode::CANCELLED);
            impl.status.endTime = std::chrono::system_clock::now();
            break;
        }

        if (impl.status.elapsedTime > kNvmeSanitizeTimeout) {
            impl.status.state = JobState::FAILED;
            impl.status.errorMessage = "Timed out waiting for device-reported sanitize completion";
            impl.status.errorCode = static_cast<int>(ErrorCode::OPERATION_TIMEOUT);
            impl.status.endTime = std::chrono::system_clock::now();
            break;
        }
    }

    platform::linux::closeDevice(impl.fd);
    impl.fd = -1;

    if (impl.status.state == JobState::FAILED) {
        return fail(ErrorCode::OPERATION_FAILED, impl.status.errorMessage);
    }

    return Result<void>::success();
}

Result<void> NvmeSanitizeMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> NvmeSanitizeMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> NvmeSanitizeMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    auto& status = pImpl_->status;
    if (status.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "device_status",
            "Device-reported sanitize completion status",
            true,
            "Sanitize status indicates successful completion",
            {LimitationId::HOST_SCOPE_ONLY}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "device_status",
            "Device-reported sanitize completion status",
            false,
            status.errorMessage.empty() ? "Operation did not complete successfully" : status.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
    }

    report.scope.push_back("Device-reported sanitize command completion");
    report.scope.push_back("NVMe Sanitize Status log");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);

    return Result<VerificationReport>::ok(report);
}

std::string NvmeSanitizeMethod::describe() const {
    return "NVMe Sanitize (" + methodToString(pImpl_->plan.selectedMethod) + ")";
}

LimitationSet NvmeSanitizeMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::DEVICE_SELF_REPORT);
    return out;
}

SanitizationMethod NvmeSanitizeMethod::methodType() const {
    return pImpl_->plan.selectedMethod;
}

bool NvmeSanitizeMethod::supportsCancel() const {
    return false;
}

bool NvmeSanitizeMethod::supportsProgress() const {
    return true;
}

class AtaSanitizeMethod::Impl {
public:
    Impl(const DeviceInfo& dev, const CapabilityInfo& caps, const SanitizationPlan& pl)
        : device(dev), capabilities(caps), plan(pl), jobId(pl.jobId) {}

    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationPlan plan;
    std::string jobId;
    JobStatus status;
    int fd = -1;
    uint8_t sanitizeAction = 0;
    bool cancelled = false;
};

AtaSanitizeMethod::AtaSanitizeMethod(const DeviceInfo& device,
                                      const CapabilityInfo& capabilities,
                                      const SanitizationPlan& plan)
    : pImpl_(std::make_unique<Impl>(device, capabilities, plan)) {}

AtaSanitizeMethod::~AtaSanitizeMethod() {
    if (pImpl_->fd >= 0) {
        platform::linux::closeDevice(pImpl_->fd);
    }
}

Result<void> AtaSanitizeMethod::execute() {
    auto& impl = *pImpl_;

    // Single exit point for failure: records the state, error and duration,
    // releases the device, and returns the error to the caller.
    auto fail = [&impl](auto&&... args) {
        const SanitizerError error = makeSanitizerError(std::forward<decltype(args)>(args)...);
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = error.what();
        impl.status.errorCode = static_cast<int>(error.code());
        if (impl.fd >= 0) {
            platform::linux::closeDevice(impl.fd);
            impl.fd = -1;
        }
        impl.status.endTime = std::chrono::system_clock::now();
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            impl.status.endTime - impl.status.startTime);
        return Result<void>::err(error);
    };


    // Identity is recorded before any syscall so a status is always populated,
    // even on the earliest failure path.
    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.device.path;
    impl.status.startTime = std::chrono::system_clock::now();

    auto fdResult = platform::linux::openDevice(impl.device.path, false);
    if (fdResult.isError()) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = fdResult.error().what();
        impl.status.errorCode = static_cast<int>(fdResult.error().code());
        impl.status.currentOperation = "Failed to open device";
        impl.status.endTime = std::chrono::system_clock::now();
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            impl.status.endTime - impl.status.startTime);
        return fail(fdResult.error());
    }
    impl.fd = fdResult.value();


    switch (impl.plan.selectedMethod) {
        case SanitizationMethod::ATA_SECURE_ERASE: {
            impl.status.currentOperation = "ATA Secure Erase";
            auto frozenResult = platform::linux::ataSecurityFrozen(impl.fd);
            if (frozenResult.ok() && frozenResult.value()) {
                return fail(ErrorCode::INVALID_DEVICE_STATE,
                                        "Security is frozen - cannot perform secure erase",
                                        "Power cycle the device to unfreeze security");
            }
            auto prepResult = platform::linux::ataSecurityErasePrepare(impl.fd, "NULL");
            if (prepResult.isError()) {
                return fail(prepResult.error());
            }
            auto eraseResult = platform::linux::ataSecurityEraseUnit(impl.fd, "NULL", false);
            if (eraseResult.isError()) {
                return fail(eraseResult.error());
            }
            break;
        }
        case SanitizationMethod::ATA_ENHANCED_SECURE_ERASE: {
            impl.status.currentOperation = "ATA Enhanced Secure Erase";
            auto frozenResult = platform::linux::ataSecurityFrozen(impl.fd);
            if (frozenResult.ok() && frozenResult.value()) {
                return fail(ErrorCode::INVALID_DEVICE_STATE,
                                        "Security is frozen - cannot perform secure erase",
                                        "Power cycle the device to unfreeze security");
            }
            auto prepResult = platform::linux::ataSecurityErasePrepare(impl.fd, "NULL");
            if (prepResult.isError()) {
                return fail(prepResult.error());
            }
            auto eraseResult = platform::linux::ataSecurityEraseUnit(impl.fd, "NULL", true);
            if (eraseResult.isError()) {
                return fail(eraseResult.error());
            }
            break;
        }
        case SanitizationMethod::ATA_SANITIZE_BLOCK_ERASE:
            impl.sanitizeAction = 0x01;
            impl.status.currentOperation = "ATA Sanitize Block Erase";
            break;
        case SanitizationMethod::ATA_SANITIZE_CRYPTO_ERASE:
            impl.sanitizeAction = 0x02;
            impl.status.currentOperation = "ATA Sanitize Crypto Erase";
            break;
        case SanitizationMethod::ATA_SANITIZE_OVERWRITE:
            impl.sanitizeAction = 0x03;
            impl.status.currentOperation = "ATA Sanitize Overwrite";
            break;
        default:
            platform::linux::closeDevice(impl.fd);
            return fail(ErrorCode::UNSUPPORTED_OPERATION,
                                    "Invalid ATA sanitize method");
    }

    if (impl.sanitizeAction != 0) {
        auto sanitizeResult = platform::linux::ataSanitize(impl.fd, impl.sanitizeAction,
                                                           impl.plan.overwritePassCount);
        if (sanitizeResult.isError()) {
            platform::linux::closeDevice(impl.fd);
            impl.status.state = JobState::FAILED;
            impl.status.errorMessage = sanitizeResult.error().what();
            impl.status.errorCode = static_cast<int>(sanitizeResult.error().code());
            impl.status.endTime = std::chrono::system_clock::now();
            return fail(sanitizeResult.error());
        }

        impl.status.state = JobState::MONITORING;

        while (!impl.cancelled) {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            auto statusResult = platform::linux::ataSanitizeStatus(impl.fd);
            if (statusResult.isError()) {
                impl.status.state = JobState::FAILED;
                impl.status.errorMessage = "Failed to read sanitize status";
                impl.status.errorCode = static_cast<int>(statusResult.error().code());
                break;
            }

            uint16_t progress = statusResult.value();
            impl.status.progressPercent = progress;
            impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - impl.status.startTime);

            if (progress >= 100 || progress == 0xFFFF) {
                impl.status.state = JobState::COMPLETED;
                impl.status.currentOperation = "Completed successfully";
                impl.status.progressPercent = 100;
                impl.status.endTime = std::chrono::system_clock::now();
                break;
            }
        }
    } else {
        impl.status.state = JobState::COMPLETED;
        impl.status.currentOperation = "Completed successfully";
        impl.status.progressPercent = 100;
        impl.status.endTime = std::chrono::system_clock::now();
    }

    platform::linux::closeDevice(impl.fd);
    impl.fd = -1;

    if (impl.status.state == JobState::FAILED) {
        return fail(ErrorCode::OPERATION_FAILED, impl.status.errorMessage);
    }

    return Result<void>::success();
}

Result<void> AtaSanitizeMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> AtaSanitizeMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> AtaSanitizeMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    auto& status = pImpl_->status;
    if (status.state == JobState::COMPLETED) {
        report.result = VerificationResult::PASS;
        report.evidence.push_back({
            "device_status",
            "Device-reported ATA sanitize/secure erase completion",
            true,
            "ATA status indicates successful completion",
            {LimitationId::HOST_SCOPE_ONLY}
        });
    } else {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "device_status",
            "Device-reported ATA sanitize/secure erase completion",
            false,
            status.errorMessage.empty() ? "Operation did not complete successfully" : status.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
    }

    report.scope.push_back("Device-reported ATA command completion");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::DEVICE_SELF_REPORT);

    return Result<VerificationReport>::ok(report);
}

std::string AtaSanitizeMethod::describe() const {
    return "ATA Sanitize (" + methodToString(pImpl_->plan.selectedMethod) + ")";
}

LimitationSet AtaSanitizeMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::DEVICE_SELF_REPORT);
    out.add(LimitationId::PROBE_FAILED,
             "a security freeze may block the command until the device is power-cycled");
    return out;
}

SanitizationMethod AtaSanitizeMethod::methodType() const {
    return pImpl_->plan.selectedMethod;
}

bool AtaSanitizeMethod::supportsCancel() const {
    return false;
}

bool AtaSanitizeMethod::supportsProgress() const {
    return pImpl_->sanitizeAction != 0;
}

namespace {

// Renders a byte count in the largest unit that keeps it readable, for the
// read-back report. Rounding is stated, never hidden.
std::string formatBytes(uint64_t bytes) {
    static const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    if (unit == 0) {
        out << bytes << " B";
    } else {
        out << std::fixed << std::setprecision(1) << value << ' ' << kUnits[unit];
    }
    return out.str();
}

} // namespace

Result<ReadBackReport> readBackVerifyEverySector(const std::string& devicePath,
                                                 uint64_t capacityBytes,
                                                 uint32_t blockSize) {
    ReadBackReport report;
    report.attempted = true;
    report.exhaustive = true;

    if (devicePath.empty() || devicePath.front() != '/') {
        return Result<ReadBackReport>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Exhaustive read-back needs an absolute target path, got: " + devicePath,
            "Resolve the path to an absolute form first, so the result refers to "
            "one specific file");
    }
    if (blockSize == 0) {
        blockSize = 512;
    }
    if (capacityBytes == 0) {
        return Result<ReadBackReport>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Exhaustive read-back needs the target capacity to place any sector",
            "The target size could not be established, so nothing could be read.");
    }

    const auto opened = platform::linux::openDevice(devicePath, true);
    if (opened.isError()) {
        return Result<ReadBackReport>::err(
            opened.error().code(),
            "Cannot open the target for read-back: " +
                std::string(opened.error().what()),
            "Exhaustive read-back needs read access to the whole target.");
    }
    const int fd = opened.value();
    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        platform::linux::closeDevice(fd);
        return Result<ReadBackReport>::err(
            ErrorCode::IO_ERROR, "Cannot determine the target size");
    }
    const uint64_t size = static_cast<uint64_t>(st.st_size);
    const uint64_t totalSectors = size / blockSize;

    size_t checked = 0;
    size_t matching = 0;
    std::string firstMismatch;
    std::vector<uint8_t> buffer(blockSize);

    for (uint64_t sector = 0; sector < totalSectors; ++sector) {
        if (::lseek(fd, static_cast<off_t>(sector * blockSize), SEEK_SET) == -1) {
            if (firstMismatch.empty()) {
                firstMismatch = "seek to sector " + std::to_string(sector) +
                                " failed";
            }
            ++checked;
            continue;
        }
        size_t got = 0;
        while (got < blockSize) {
            const ssize_t n = ::read(fd, buffer.data() + got, blockSize - got);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (n == 0) {
                break;
            }
            got += static_cast<size_t>(n);
        }
        if (got < blockSize) {
            ++checked;
            if (firstMismatch.empty()) {
                firstMismatch = "short read at sector " + std::to_string(sector);
            }
            continue;
        }
        ++checked;
        const bool clean = std::all_of(
            buffer.begin(), buffer.end(),
            [](uint8_t b) { return b == kOverwritePatternByte; });
        if (clean) {
            ++matching;
        } else if (firstMismatch.empty()) {
            firstMismatch = "sector " + std::to_string(sector) +
                            " does not hold the overwrite pattern";
        }

        if (ProgressReporter* reporter = activeProgressReporter()) {
            // Every sector is a sample here, so the counter is the real one and
            // the bar shows true progress rather than the 64-point version.
            reporter->onProgress(ProgressPhase::VERIFY, sector + 1, totalSectors,
                                 1, 1, static_cast<unsigned>(sector + 1),
                                 static_cast<unsigned>(totalSectors));
        }
    }

    ::close(fd);

    report.samplesChecked = checked;
    report.samplesMatching = matching;
    report.coveredFraction = size > 0 ? 1.0 : 0.0;
    report.passed = checked > 0 && matching == checked;

    if (checked == 0) {
        report.detail = "No sector could be read, so the target could not be "
                        "checked by any means.";
    } else if (report.passed) {
        std::ostringstream out;
        out << "Every one of the " << checked
            << " sectors in the target holds the overwrite pattern. The whole "
            << formatBytes(size) << " of the target was read, so this is an "
            << "exhaustive check of the host-visible address space and not a "
            << "sample.";
        report.detail = out.str();
    } else {
        std::ostringstream out;
        out << (checked - matching) << " of " << checked
            << " sectors do not hold the overwrite pattern. First discrepancy: "
            << firstMismatch << ". Every sector was read.";
        report.detail = out.str();
    }

    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::SELF_VERIFIED);
    if (!report.passed) {
        report.limitations.add(LimitationId::VERIFICATION_FAILED);
    }

    return Result<ReadBackReport>::ok(std::move(report));
}

Result<ReadBackReport> readBackVerifyOverwrite(const std::string& devicePath,
                                              uint64_t capacityBytes,
                                              uint32_t blockSize,
                                              size_t samples) {
    ReadBackReport report;

    if (devicePath.empty() || devicePath.front() != '/') {
        // A relative path names a different file depending on the reader's
        // working directory, so a verdict produced from one would not be
        // reproducible. DeviceInspector normalises every path it records, so
        // reaching here means a caller passed a raw path straight through.
        return Result<ReadBackReport>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Read-back verification needs an absolute device path, got: " + devicePath,
            "Resolve the path to an absolute form first, so the result refers to "
            "one specific file");
    }
    if (blockSize == 0) {
        blockSize = 512;
    }
    if (samples == 0) {
        samples = kDefaultReadBackSamples;
    }
    if (capacityBytes == 0) {
        return Result<ReadBackReport>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Read-back verification needs the device capacity to place samples",
            "The device size could not be established, so no sample could be chosen");
    }

    report.attempted = true;

    // Read-only. This is verification, and verification must not be able to
    // change what it is verifying.
    const int fd = ::open(devicePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return Result<ReadBackReport>::err(
            ErrorCode::PERMISSION_DENIED,
            "Cannot open " + devicePath + " read-only for read-back verification: " +
                std::string(std::strerror(errno)),
            "Read-back verification requires read access to the device. Run with "
            "sufficient privileges, or record the verification as inconclusive.");
    }

    const uint64_t totalSectors = capacityBytes / blockSize;
    if (totalSectors == 0) {
        ::close(fd);
        return Result<ReadBackReport>::err(
            ErrorCode::INVALID_ARGUMENT,
            "The device reports a capacity smaller than one block",
            "No sector can be sampled");
    }

    const size_t wanted = std::min<size_t>(samples, static_cast<size_t>(totalSectors));
    // One sector per sample. Sized from the device's own logical block size
    // rather than a constant, so a 4K-sector device is read correctly.
    std::vector<uint8_t> buffer(blockSize);

    size_t matching = 0;
    size_t checked = 0;
    std::string firstMismatch;

    for (size_t i = 0; i < wanted; ++i) {
        // Evenly spaced across the whole device, including the first and last
        // sector, so a device that only wrote part of itself is likely to be
        // caught.
        const uint64_t sector =
            (wanted == 1) ? 0
                          : (totalSectors - 1) * static_cast<uint64_t>(i) /
                                static_cast<uint64_t>(wanted - 1);
        const off_t offset = static_cast<off_t>(sector * blockSize);

        if (::lseek(fd, offset, SEEK_SET) == static_cast<off_t>(-1)) {
            if (firstMismatch.empty()) {
                firstMismatch = "seek to sector " + std::to_string(sector) + " failed";
            }
            continue;
        }

        std::memset(buffer.data(), 0xFF, buffer.size());
        ssize_t got = 0;
        while (static_cast<size_t>(got) < buffer.size()) {
            const ssize_t n = ::read(fd, buffer.data() + got, buffer.size() - got);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break;
            got += n;
        }

        if (static_cast<size_t>(got) != buffer.size()) {
            ++checked;
            if (firstMismatch.empty()) {
                firstMismatch = "short read at sector " + std::to_string(sector);
            }
            continue;
        }

        ++checked;
        if (ProgressReporter* reporter = activeProgressReporter()) {
            reporter->onProgress(ProgressPhase::VERIFY, checked, wanted, 1, 1,
                                 checked, static_cast<unsigned>(wanted));
        }
        const bool allPattern = std::all_of(
            buffer.begin(), buffer.end(),
            [](uint8_t b) { return b == kOverwritePatternByte; });
        if (allPattern) {
            ++matching;
        } else if (firstMismatch.empty()) {
            firstMismatch = "sector " + std::to_string(sector) +
                            " does not hold the overwrite pattern";
        }
    }

    ::close(fd);

    report.samplesChecked = checked;
    report.samplesMatching = matching;
    report.coveredFraction =
        capacityBytes > 0
            ? static_cast<double>(matching) * static_cast<double>(blockSize) /
                  static_cast<double>(capacityBytes)
            : 0.0;
    report.passed = checked > 0 && matching == checked;

    if (checked == 0) {
        report.detail =
            "No sector could be read back, so the overwrite could not be confirmed "
            "by any means.";
    } else if (report.passed) {
        // The coverage figure matters as much as the result: 64 clean samples out
        // of a terabyte is a much weaker statement than 64 out of a floppy, and
        // rounding it to a whole percent would print both as "0%".
        std::ostringstream percent;
        percent << std::fixed << std::setprecision(4)
                << report.coveredFraction * 100.0 << "%";
        report.detail =
            "All " + std::to_string(checked) +
            " sampled sectors hold the overwrite pattern. The samples were spread "
            "evenly across the device and covered " +
            formatBytes(matching * static_cast<uint64_t>(blockSize)) + " of " +
            formatBytes(capacityBytes) + " (" + percent.str() + " of the device).";
    } else {
        const std::size_t mismatched = checked - matching;
        report.detail =
            std::to_string(mismatched) + " of " + std::to_string(checked) +
            " sampled sector" + (checked == 1 ? "" : "s") +
            (mismatched == 1 ? " does" : " do") +
            " not hold the overwrite pattern. First discrepancy: " +
            firstMismatch +
            ". Either the write did not reach every part of the device, or the "
            "device is not reporting the media it actually wrote.";
    }

    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::SAMPLED_READBACK);
    report.limitations.add(LimitationId::SAMPLED_READBACK);
    report.limitations.add(LimitationId::SELF_VERIFIED);

    return Result<ReadBackReport>::ok(std::move(report));
}

class OverwriteMethod::Impl {
public:
    Impl(const DeviceInfo& dev, const CapabilityInfo& caps, const SanitizationPlan& pl)
        : device(dev), capabilities(caps), plan(pl), jobId(pl.jobId) {}

    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationPlan plan;
    std::string jobId;
    JobStatus status;
    int fd = -1;
    bool cancelled = false;
};

OverwriteMethod::OverwriteMethod(const DeviceInfo& device,
                                  const CapabilityInfo& capabilities,
                                  const SanitizationPlan& plan)
    : pImpl_(std::make_unique<Impl>(device, capabilities, plan)) {}

OverwriteMethod::~OverwriteMethod() {
    if (pImpl_->fd >= 0) {
        platform::linux::closeDevice(pImpl_->fd);
    }
}

Result<void> OverwriteMethod::execute() {
    auto& impl = *pImpl_;

    // Single exit point for failure: records the state, error and duration,
    // releases the device, and returns the error to the caller.
    auto fail = [&impl](auto&&... args) {
        const SanitizerError error = makeSanitizerError(std::forward<decltype(args)>(args)...);
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = error.what();
        impl.status.errorCode = static_cast<int>(error.code());
        if (impl.fd >= 0) {
            platform::linux::closeDevice(impl.fd);
            impl.fd = -1;
        }
        impl.status.endTime = std::chrono::system_clock::now();
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            impl.status.endTime - impl.status.startTime);
        return Result<void>::err(error);
    };


    // Identity is recorded before any syscall so a status is always populated,
    // even on the earliest failure path.
    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.device.path;
    impl.status.startTime = std::chrono::system_clock::now();

    auto fdResult = platform::linux::openDevice(impl.device.path, false);
    if (fdResult.isError()) {
        impl.status.state = JobState::FAILED;
        impl.status.errorMessage = fdResult.error().what();
        impl.status.errorCode = static_cast<int>(fdResult.error().code());
        impl.status.currentOperation = "Failed to open device";
        impl.status.endTime = std::chrono::system_clock::now();
        impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
            impl.status.endTime - impl.status.startTime);
        return fail(fdResult.error());
    }
    impl.fd = fdResult.value();

    // The size to overwrite is re-read from the block device now, not taken from
    // the DeviceInfo captured during discovery.
    //
    // Using the recorded capacity is a silent under-wipe: if the drive was
    // re-enumerated, resized, or is larger than the inspection saw, the loop
    // below stops at the old size, leaves the tail untouched, and then reports
    // 100% complete. The recorded capacity is cross-checked against the live
    // one and a mismatch aborts the run rather than being resolved in favour of
    // the smaller number.
    auto sizeResult = platform::linux::getBlockDeviceSize(impl.fd);
    if (sizeResult.isError()) {
        return fail(sizeResult.error());
    }
    const uint64_t liveBytes = sizeResult.value();
    if (liveBytes == 0) {
        return fail(ErrorCode::INVALID_DEVICE_STATE,
                    "The device reports a capacity of zero bytes",
                    "Refusing to run an overwrite against a device of unknown size, "
                    "because a partial overwrite would be reported as complete");
    }
    if (impl.device.capacityBytes != 0 && liveBytes != impl.device.capacityBytes) {
        return fail(ErrorCode::INVALID_DEVICE_STATE,
                    "The device size changed between inspection (" +
                        std::to_string(impl.device.capacityBytes) +
                        " bytes) and execution (" + std::to_string(liveBytes) +
                        " bytes)",
                    "Re-inspect the device and plan again. Overwriting the smaller "
                    "of the two sizes would leave part of the media untouched while "
                    "reporting success.");
    }
    const uint64_t totalBytes = liveBytes;

    impl.status.totalBytes = totalBytes;

    constexpr size_t BUFFER_SIZE = 1024 * 1024;
    std::vector<uint8_t> buffer(BUFFER_SIZE, kOverwritePatternByte);

    // The pass count is the number of times the whole address space is written.
    //
    // It used to be recorded in the plan and printed in the certificate while a
    // single pass was performed, which meant the document stated something the
    // tool had not done - precisely the failure this whole project exists to
    // prevent. The value is now what actually happens.
    const unsigned passes = impl.plan.overwritePassCount;
    impl.status.currentOperation = "Host Overwrite (" + std::to_string(passes) +
                                   (passes == 1 ? " pass)" : " passes)");

    // Consecutive EAGAIN/EBUSY responses tolerated before giving up.
    //
    // The device is opened O_NONBLOCK (see platform::linux::openDevice), so a
    // write to a device that cannot take data *right now* returns EAGAIN rather
    // than blocking in the queue. That is the normal response from a nearly full
    // removable device or a busy controller, and treating it as fatal aborted a
    // perfectly recoverable overwrite with "Resource temporarily unavailable" -
    // an unactionable message, on the one code path that cannot be retried by
    // simply running the command again.
    int consecutiveBusy = 0;
    constexpr int kMaxBusyRetries = 200;   // ~20 s at 100 ms
    constexpr auto kBusyBackoff = std::chrono::milliseconds(100);

    for (unsigned pass = 1; pass <= passes && !impl.cancelled; ++pass) {
        if (pass > 1) {
            // Rewind and flush, so a later pass does not read the device's own
            // write cache back as "already done" and skip sectors.
            if (::lseek(impl.fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
                return fail(ErrorCode::IO_ERROR,
                            "Cannot rewind to the start of the device for overwrite pass " +
                                std::to_string(pass));
            }
            if (::fsync(impl.fd) < 0) {
                return fail(ErrorCode::IO_ERROR,
                            "Failed to flush before overwrite pass " + std::to_string(pass));
            }
            impl.status.currentOperation = "Host Overwrite, pass " + std::to_string(pass) +
                                           " of " + std::to_string(passes);
        }

        uint64_t written = 0;
        while (written < totalBytes && !impl.cancelled) {
            const size_t toWrite =
                std::min(BUFFER_SIZE, static_cast<size_t>(totalBytes - written));
            ssize_t result = ::write(impl.fd, buffer.data(), toWrite);
            if (result < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EBUSY) {
                    if (++consecutiveBusy <= kMaxBusyRetries) {
                        std::this_thread::sleep_for(kBusyBackoff);
                        continue;
                    }
                    const std::string message =
                        "The device stopped accepting data with " +
                        std::to_string(totalBytes - written) +
                        " bytes still to write, after " +
                        std::to_string(kMaxBusyRetries * kBusyBackoff.count() / 1000) +
                        " seconds of the device reporting itself busy. It is most likely "
                        "full, write-protected, or in a state it is not accepting writes in.";
                    impl.status.errorMessage = message;
                    impl.status.errorCode = static_cast<int>(ErrorCode::DEVICE_BUSY);
                    impl.status.endTime = std::chrono::system_clock::now();
                    return fail(ErrorCode::DEVICE_BUSY, message);
                }
                const std::string message =
                    "Write failed: " + std::string(strerror(errno));
                impl.status.errorMessage = message;
                impl.status.errorCode = static_cast<int>(ErrorCode::IO_ERROR);
                impl.status.endTime = std::chrono::system_clock::now();
                return fail(ErrorCode::IO_ERROR, message);
            }
            consecutiveBusy = 0;
            if (result == 0) {
                // A zero-length write with bytes outstanding means the device is
                // not accepting data. Continuing would spin until the timeout
                // and then report a failure having written nothing.
                const std::string message =
                    "The device accepted no data with " +
                    std::to_string(totalBytes - written) +
                    " bytes still to write. It may be write-protected, full, or failing.";
                impl.status.errorMessage = message;
                impl.status.errorCode = static_cast<int>(ErrorCode::IO_ERROR);
                impl.status.endTime = std::chrono::system_clock::now();
                return fail(ErrorCode::IO_ERROR, message);
            }

            written += static_cast<uint64_t>(result);
            // Progress is across the whole job, not the current pass, so a
            // multi-pass run does not appear to restart from zero.
            const uint64_t done =
                static_cast<uint64_t>(pass - 1) * totalBytes + written;
            impl.status.bytesProcessed = done;
            impl.status.progressValid = true;
            impl.status.progressPercent = (done * 100) / totalBytes;
            if (ProgressReporter* reporter = activeProgressReporter()) {
                reporter->onProgress(ProgressPhase::WRITE, done, totalBytes,
                                     pass, passes);
            }
            impl.status.elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - impl.status.startTime);
        }
    }

    if (fsync(impl.fd) < 0) {
        platform::linux::closeDevice(impl.fd);
        return fail(ErrorCode::IO_ERROR, "Failed to sync writes");
    }

    platform::linux::closeDevice(impl.fd);
    impl.fd = -1;

    impl.status.state = JobState::COMPLETED;
    // The pass count stays in the final status. Overwriting this with a bare
    // "Completed successfully" loses the one number that says how much work was
    // actually done, which is the number an assessor reads.
    impl.status.currentOperation =
        "Completed successfully (" + std::to_string(passes) +
        (passes == 1 ? " pass)" : " passes)");
    impl.status.progressValid = true;
    impl.status.progressPercent = 100;
    impl.status.endTime = std::chrono::system_clock::now();

    return Result<void>::success();
}

Result<void> OverwriteMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> OverwriteMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> OverwriteMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();

    const auto& status = pImpl_->status;
    if (status.state != JobState::COMPLETED) {
        report.result = VerificationResult::FAIL;
        report.evidence.push_back({
            "host_write",
            "Host-level overwrite completion",
            false,
            status.errorMessage.empty() ? "The overwrite did not complete"
                                        : status.errorMessage,
            {LimitationId::HOST_SCOPE_ONLY}
        });
        report.scope.push_back("Host-level write to all logical block addresses");
        report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
        return Result<VerificationReport>::ok(report);
    }

    // The read-back, not the write, is the evidence. See
    // addOverwriteReadBackEvidence() for why this lives here as well as in the
    // engine: the executor prefers the method's verification, so a method that
    // did not do this would shadow the engine's.
    addOverwriteReadBackEvidence(
        pImpl_->device, report,
        pImpl_->plan.verifyDepth == SanitizationPlan::VerifyDepth::FULL);

    report.evidence.push_back({
        "host_write",
        "Host-level overwrite completion with flush",
        true,
        "The overwrite ran to completion and the writes were flushed to the device",
        {LimitationId::DEVICE_SELF_REPORT}
    });

    report.scope.push_back("Host-level write to all logical block addresses");
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::HOST_SCOPE_ONLY);
    report.limitations.add(LimitationId::CLEAR_ONLY);
    if (pImpl_->device.transport == TransportType::USB) {
        report.limitations.add(LimitationId::USB_BRIDGE_OPAQUE);
    }
    report.limitations.add(LimitationId::SELF_VERIFIED);

    return Result<VerificationReport>::ok(report);
}

std::string OverwriteMethod::describe() const {
    return "Host Overwrite (single pass, zero fill)";
}

LimitationSet OverwriteMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::HOST_SCOPE_ONLY);
    out.add(LimitationId::CLEAR_ONLY);
    return out;
}

SanitizationMethod OverwriteMethod::methodType() const {
    return SanitizationMethod::OVERWRITE_HOST;
}

bool OverwriteMethod::supportsCancel() const {
    return true;
}

bool OverwriteMethod::supportsProgress() const {
    return true;
}

class CryptoEraseMethod::Impl {
public:
    Impl(const DeviceInfo& dev, const CapabilityInfo& caps, const SanitizationPlan& pl)
        : device(dev), capabilities(caps), plan(pl), jobId(pl.jobId) {}

    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationPlan plan;
    std::string jobId;
    JobStatus status;
    bool cancelled = false;
};

CryptoEraseMethod::CryptoEraseMethod(const DeviceInfo& device,
                                      const CapabilityInfo& capabilities,
                                      const SanitizationPlan& plan)
    : pImpl_(std::make_unique<Impl>(device, capabilities, plan)) {}

CryptoEraseMethod::~CryptoEraseMethod() = default;

Result<void> CryptoEraseMethod::execute() {
    auto& impl = *pImpl_;

    impl.status.jobId = impl.jobId;
    impl.status.state = JobState::EXECUTING;
    impl.status.devicePath = impl.device.path;
    impl.status.startTime = std::chrono::system_clock::now();
    impl.status.currentOperation = "Host Crypto Erase (not implemented)";

    impl.status.state = JobState::FAILED;
    impl.status.errorMessage = "Host crypto erase not implemented - requires encryption setup";
    impl.status.errorCode = static_cast<int>(ErrorCode::NOT_IMPLEMENTED);
    impl.status.endTime = std::chrono::system_clock::now();

    return Result<void>::err(ErrorCode::NOT_IMPLEMENTED,
                            "Host crypto erase requires pre-configured encryption (LUKS, etc.)");
}

Result<void> CryptoEraseMethod::cancel() {
    pImpl_->cancelled = true;
    return Result<void>::success();
}

Result<JobStatus> CryptoEraseMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> CryptoEraseMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();
    report.result = VerificationResult::INCONCLUSIVE;
    report.evidence.push_back({
        "host_crypto",
        "Host crypto erase not executed",
        false,
        "Operation not implemented",
        {LimitationId::CRYPTO_ERASE_NEEDS_FDE}
    });
    report.limitations.add(LimitationId::NOT_IMPLEMENTED);
    return Result<VerificationReport>::ok(report);
}

std::string CryptoEraseMethod::describe() const {
    return "Host Crypto Erase (requires pre-configured encryption)";
}

LimitationSet CryptoEraseMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::CRYPTO_ERASE_NEEDS_FDE);
    out.add(LimitationId::CRYPTO_ERASE_KEYS_ONLY);
    out.add(LimitationId::NOT_IMPLEMENTED);
    return out;
}

SanitizationMethod CryptoEraseMethod::methodType() const {
    return SanitizationMethod::CRYPTO_ERASE_HOST;
}

bool CryptoEraseMethod::supportsCancel() const {
    return false;
}

bool CryptoEraseMethod::supportsProgress() const {
    return false;
}

class UnsupportedMethod::Impl {
public:
    Impl(const DeviceInfo& dev, const CapabilityInfo& caps, const SanitizationPlan& pl)
        : device(dev), capabilities(caps), plan(pl), jobId(pl.jobId) {}

    DeviceInfo device;
    CapabilityInfo capabilities;
    SanitizationPlan plan;
    std::string jobId;
    JobStatus status;
};

UnsupportedMethod::UnsupportedMethod(const DeviceInfo& device,
                                      const CapabilityInfo& capabilities,
                                      const SanitizationPlan& plan)
    : pImpl_(std::make_unique<Impl>(device, capabilities, plan)) {}

UnsupportedMethod::~UnsupportedMethod() = default;

Result<void> UnsupportedMethod::execute() {
    pImpl_->status.jobId = pImpl_->jobId;
    pImpl_->status.state = JobState::FAILED;
    pImpl_->status.devicePath = pImpl_->device.path;
    pImpl_->status.errorMessage = "Selected sanitization method is not supported by this device";
    pImpl_->status.errorCode = static_cast<int>(ErrorCode::UNSUPPORTED_OPERATION);
    pImpl_->status.endTime = std::chrono::system_clock::now();
    return Result<void>::err(ErrorCode::UNSUPPORTED_OPERATION, pImpl_->status.errorMessage);
}

Result<void> UnsupportedMethod::cancel() {
    return Result<void>::success();
}

Result<JobStatus> UnsupportedMethod::status() const {
    return Result<JobStatus>::ok(pImpl_->status);
}

Result<VerificationReport> UnsupportedMethod::verify() {
    VerificationReport report;
    report.jobId = pImpl_->jobId;
    report.timestamp = std::chrono::system_clock::now();
    report.result = VerificationResult::FAIL;
    report.evidence.push_back({
        "unsupported",
        "Method not supported",
        false,
        "Cannot verify unsupported method",
        {LimitationId::NO_VERIFICATION}
    });
    return Result<VerificationReport>::ok(report);
}

std::string UnsupportedMethod::describe() const {
    return "Unsupported Method";
}

LimitationSet UnsupportedMethod::limitations() const {
LimitationSet out;
    out.add(LimitationId::NOT_IMPLEMENTED,
             "the device reports no usable sanitization method");
    return out;
}

SanitizationMethod UnsupportedMethod::methodType() const {
    return SanitizationMethod::UNSUPPORTED;
}

bool UnsupportedMethod::supportsCancel() const {
    return false;
}

bool UnsupportedMethod::supportsProgress() const {
    return false;
}

} // namespace ledgerase