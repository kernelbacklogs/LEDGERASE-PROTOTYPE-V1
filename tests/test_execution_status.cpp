// Regression tests for the execution status semantics.
//
// The bug these guard against: a method that failed before initialising its own
// status had its FAILED result overwritten by a default-constructed JobStatus,
// so the CLI printed "Sanitization Unknown" and exited 0 after a failure that
// never actually sanitized anything. Per CLAUDE.md s21 a failure must never be
// reported as success.

#include "ledgerase/sanitization.hpp"
#include "ledgerase/limitations.hpp"
#include "mock/mock.hpp"
#include "ledgerase/json_adapters.hpp"

#include <cstdio>
#include <memory>
#include <string>

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

// A method that fails the way a real one does when the device cannot be opened:
// it returns an error and leaves its own status at the default.
class FailWithoutStatus : public ledgerase::ISanitizationMethod {
public:
    ledgerase::Result<void> execute() override {
        return ledgerase::Result<void>::err(ledgerase::ErrorCode::PERMISSION_DENIED,
                                 "Failed to open device: Permission denied");
    }
    ledgerase::Result<void> cancel() override { return ledgerase::Result<void>::success(); }
    ledgerase::Result<ledgerase::JobStatus> status() const override {
        return ledgerase::Result<ledgerase::JobStatus>::ok(status_);
    }
    ledgerase::Result<ledgerase::VerificationReport> verify() override {
        return ledgerase::Result<ledgerase::VerificationReport>::ok({});
    }
    std::string describe() const override { return "failing method"; }
    ledgerase::LimitationSet limitations() const override { return {}; }
    ledgerase::SanitizationMethod methodType() const override {
        return ledgerase::SanitizationMethod::NVME_CRYPTO_ERASE;
    }
    bool supportsCancel() const override { return false; }
    bool supportsProgress() const override { return false; }

private:
    ledgerase::JobStatus status_;
};

// A method that claims success but never set a terminal state.
class SuccessWithoutState : public ledgerase::ISanitizationMethod {
public:
    ledgerase::Result<void> execute() override { return ledgerase::Result<void>::success(); }
    ledgerase::Result<void> cancel() override { return ledgerase::Result<void>::success(); }
    ledgerase::Result<ledgerase::JobStatus> status() const override {
        return ledgerase::Result<ledgerase::JobStatus>::ok(status_);
    }
    ledgerase::Result<ledgerase::VerificationReport> verify() override {
        return ledgerase::Result<ledgerase::VerificationReport>::ok({});
    }
    std::string describe() const override { return "unhelpful method"; }
    ledgerase::LimitationSet limitations() const override { return {}; }
    ledgerase::SanitizationMethod methodType() const override {
        return ledgerase::SanitizationMethod::NVME_BLOCK_ERASE;
    }
    bool supportsCancel() const override { return false; }
    bool supportsProgress() const override { return false; }

private:
    ledgerase::JobStatus status_;
};

ledgerase::SanitizationPlan makePlan() {
    ledgerase::SanitizationPlan plan;
    plan.jobId = "JOB-TEST-0001";
    plan.device.path = "/dev/nvme0n1";
    plan.device.model = "Test Device";
    plan.selectedMethod = ledgerase::SanitizationMethod::NVME_CRYPTO_ERASE;
    return plan;
}

void testFailureIsNeverDowngraded() {
    std::printf("a failing method reports FAILED, not UNKNOWN\n");

    const auto plan = makePlan();
    FailWithoutStatus method;

    bool callbackFired = false;
    ledgerase::JobStatus seenByCallback;
    const auto result = ledgerase::SanitizationExecutor::runMethod(
        method, plan, [&](const ledgerase::JobStatus& status) {
            callbackFired = true;
            seenByCallback = status;
        });

    check(result.ok(), "runMethod returns the outcome as a status, not an error");
    if (!result.ok()) return;

    const auto& status = result.value();
    check(status.state == ledgerase::JobState::FAILED,
          "a method error becomes JobState::FAILED");
    check(status.state != ledgerase::JobState::COMPLETED,
          "a failure is never reported as COMPLETED");
    check(status.errorMessage == "Failed to open device: Permission denied",
          "the error message is preserved verbatim");
    check(status.errorCode == static_cast<int>(ledgerase::ErrorCode::PERMISSION_DENIED),
          "the machine-readable error code is preserved");
    check(status.devicePath == "/dev/nvme0n1", "the target device is recorded");
    check(status.jobId == plan.jobId, "the job id is recorded");
    check(status.elapsedTime.count() >= 0,
          "elapsed time is a real measurement, never an uninitialised value");
    check(status.endTime.time_since_epoch().count() != 0,
          "an end time is always stamped");
    check(callbackFired, "the progress callback is invoked on failure too");
    check(seenByCallback.state == ledgerase::JobState::FAILED,
          "the callback observes the failure, not a default status");
}

void testSuccessWithoutStateIsNotBlindlyTrusted() {
    std::printf("a success without a terminal state is labelled\n");

    const auto plan = makePlan();
    SuccessWithoutState method;

    const auto result = ledgerase::SanitizationExecutor::runMethod(method, plan);
    check(result.ok(), "runMethod succeeds");
    if (!result.ok()) return;

    const auto& status = result.value();
    check(status.state == ledgerase::JobState::COMPLETED,
          "an unset terminal state is resolved to COMPLETED");
    check(!status.errorMessage.empty(),
          "the resolution is disclosed in the error message field");
    check(status.devicePath == plan.device.path, "the device path is filled in");
    check(status.endTime.time_since_epoch().count() != 0, "an end time is stamped");
    check(status.elapsedTime.count() >= 0, "elapsed time is non-negative");
}

void testDefaultJobStatusIsWellFormed() {
    std::printf("a default-constructed JobStatus carries no garbage\n");

    ledgerase::JobStatus fresh;
    check(fresh.elapsedTime.count() == 0,
          "elapsedTime defaults to zero rather than an indeterminate value");
    check(fresh.state == ledgerase::JobState::UNKNOWN, "state defaults to UNKNOWN");
    check(fresh.errorCode == 0, "errorCode defaults to zero");
    check(fresh.simulated == false, "a real job defaults to not simulated");
}

void testSimulationFactoryReplacesRealMethods() {
    std::printf("simulation cannot reach the real methods\n");

    auto config = ledgerase::MockBackend::createMockNvmeSsd();
    ledgerase::MockBackend backend;
    backend.addDevice(config);

    auto plan = makePlan();
    plan.device.path = config.path;

    ledgerase::SanitizationExecutor executor;
    check(!executor.hasMethodFactory(), "a fresh executor uses the real methods");

    auto* implOwner = &backend;
    executor.setMethodFactory(
        [implOwner](ledgerase::SanitizationMethod method,
                    const ledgerase::DeviceInfo& device,
                    const ledgerase::CapabilityInfo& capabilities,
                    const ledgerase::SanitizationPlan& p) {
            return implOwner->createMethod(method, device, capabilities, p);
        });
    check(executor.hasMethodFactory(), "the simulation factory is installed");

    auto method = executor.createMethod(plan.selectedMethod, plan.device,
                                        plan.capabilities, plan);
    check(method.ok(), "the factory produces a method");
    if (method.ok()) {
        check(method.value()->isSimulated(),
              "the produced method is marked as simulated");
    }

    executor.setMethodFactory(nullptr);
    check(!executor.hasMethodFactory(), "the factory can be removed again");

    auto real = executor.createMethod(plan.selectedMethod, plan.device,
                                      plan.capabilities, plan);
    check(real.ok(), "the real method is restored");
    if (real.ok()) {
        check(!real.value()->isSimulated(),
              "the real method is not marked as simulated");
    }
}

void testSimulatedRunIsLabelled() {
    std::printf("a simulated run is labelled simulated\n");

    auto config = ledgerase::MockBackend::createMockNvmeSsd();
    // Keep the run short: the mock advances 10% every 100 ms.
    ledgerase::MockBackend backend;
    backend.addDevice(config);

    auto plan = makePlan();
    plan.device.path = config.path;

    auto method = backend.createMethod(plan.selectedMethod, plan.device,
                                       plan.capabilities, plan);
    check(method.ok(), "the mock backend produces a method");
    if (!method.ok()) return;

    const auto result = ledgerase::SanitizationExecutor::runMethod(*method.value(), plan);
    check(result.ok(), "the simulated run returns a status");
    if (!result.ok()) return;

    check(result.value().simulated,
          "the resulting status is marked simulated so it cannot be mistaken for real");
    check(result.value().state == ledgerase::JobState::COMPLETED,
          "the simulated run completes");
    check(result.value().elapsedTime.count() >= 0,
          "the simulated duration is a real measurement");
    check(result.value().elapsedTime.count() < 60,
          "the simulated duration is plausible, not an uninitialised value");
}

void testSimulatedFailureKeepsItsMessage() {
    std::printf("a simulated device failure keeps its message\n");

    auto config = ledgerase::MockBackend::createMockFailed();
    ledgerase::MockBackend backend;
    backend.addDevice(config);

    auto plan = makePlan();
    plan.device.path = config.path;

    auto method = backend.createMethod(plan.selectedMethod, plan.device,
                                       plan.capabilities, plan);
    if (method.isError()) return;

    const auto result = ledgerase::SanitizationExecutor::runMethod(*method.value(), plan);
    check(result.ok(), "the simulated failure is reported as a status");
    if (!result.ok()) return;

    check(result.value().state == ledgerase::JobState::FAILED,
          "a simulated failure is FAILED, not COMPLETED");
    check(!result.value().errorMessage.empty(),
          "the simulated failure keeps its message");
    check(result.value().simulated, "the failure is still labelled simulated");
}

void testJsonCarriesSimulatedFlag() {
    std::printf("the audit record carries the simulated flag\n");

    ledgerase::JobStatus status;
    status.jobId = "JOB-1";
    status.state = ledgerase::JobState::COMPLETED;
    status.simulated = true;
    status.elapsedTime = std::chrono::seconds(3);

    nlohmann::json j = status;
    check(j.at("simulated").get<bool>(), "the flag is serialised");
    check(j.at("elapsed_seconds").get<long long>() == 3, "the duration is serialised");

    ledgerase::JobStatus parsed;
    j.get_to(parsed);
    check(parsed.simulated, "the flag round-trips");
    check(parsed.elapsedTime.count() == 3, "the duration round-trips");
}

} // namespace

int main() {
    testFailureIsNeverDowngraded();
    testSuccessWithoutStateIsNotBlindlyTrusted();
    testDefaultJobStatusIsWellFormed();
    testSimulationFactoryReplacesRealMethods();
    testSimulatedRunIsLabelled();
    testSimulatedFailureKeepsItsMessage();
    testJsonCarriesSimulatedFlag();

    if (g_failures == 0) {
        std::printf("\nall execution status tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
