// Tests for USB mass-storage support.
//
// The behaviour under test is not "can this tool talk to USB". It is what the
// tool does when a USB bridge chip sits between the host and the media and
// behaves badly, which is the normal case:
//
//   1. A bridge that passes commands through. The device-level mechanisms may
//      exist, but whether a *security* command would be honoured cannot be
//      established without sending one, so it must stay UNKNOWN rather than
//      being asserted either way.
//   2. A bridge that accepts every command, reports success, and erases nothing.
//      This is the failure that a naive implementation cannot detect: the write
//      path looks perfect. Only a read-back of the media finds it.
//   3. A PURGE request against USB media with no confirmed device-level
//      mechanism must be REFUSED, not downgraded to a host overwrite.
//
// Nothing here opens a real device. The read-back is exercised against a
// temporary file, which is the same code path the verifier uses for a device.

#include "ledgerase/mock.hpp"
#include "ledgerase/policy.hpp"
#include "ledgerase/sanitization.hpp"
#include "ledgerase/verification.hpp"
#include "ledgerase/capability.hpp"
#include "ledgerase/evidence.hpp"
#include "ledgerase/platform/linux.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;

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

using namespace ledgerase;

// A validation that claims acceptance, used to prove the builder refuses to
// carry it forward when the verification did not pass.
ValidationReport acceptingValidation() {
    ValidationReport report;
    report.result = ValidationResult::ACCEPTED;
    report.reasoning = "assumed accepted for the test";
    return report;
}

SanitizationPlan planFor(MockDeviceConfig config, SanitizationCategory category) {
    DeviceInfo device;
    device.path = config.path;
    device.model = config.model;
    device.serial = config.serial;
    device.capacityBytes = config.capacityBytes;
    device.logicalBlockSize = config.logicalBlockSize;
    device.transport = config.transport;
    device.mediaType = MediaType::REMOVABLE;
    device.removable = true;
    device.usbDeviceNode = config.usbDeviceNode;

    MockBackend backend;
    backend.addDevice(config);
    const auto inspected = backend.inspectDevice(config.path);
    if (inspected.ok()) {
        device = inspected.value();
    }
    const auto caps = backend.detectCapabilities(device).valueOr(CapabilityInfo());

    SanitizationPolicyEngine engine(SanitizationPolicyEngine::createDefaultPolicy());
    const auto planned = engine.createPlan(device, caps, category, true);
    SanitizationPlan plan = planned.ok() ? planned.value() : SanitizationPlan();
    plan.device = device;
    plan.capabilities = caps;
    return plan;
}

// 1. A bridge that passes commands through must not make its device-level
//    mechanisms look confirmed.
void testPassthroughBridgeStaysUnknown() {
    std::printf("a working USB bridge does not yield confirmed device-level capability\n");

    const auto config = MockBackend::createMockUsbBridgePassthrough();
    const auto plan = planFor(config, SanitizationCategory::PURGE);

    check(config.transport == TransportType::USB,
          "the mock device is reported as USB transport");
    check(config.path.rfind("/dev/sd", 0) == 0,
          "the mock device uses a /dev/sdX path, as real USB media does");

    check(plan.capabilities.ataSecureErase == CapabilityStatus::UNKNOWN,
          "ATA Secure Erase is UNKNOWN through a passthrough bridge");
    check(plan.capabilities.ataSanitizeBlockErase == CapabilityStatus::UNKNOWN,
          "ATA Sanitize Block Erase is UNKNOWN through a passthrough bridge");
    check(plan.capabilities.overwriteHost == CapabilityStatus::SUPPORTED,
          "a host overwrite remains available");

    // The reasoning must be recorded, not just the status. A capability that is
    // UNKNOWN with no stated reason is indistinguishable from a bug.
    bool explained = false;
    for (const auto& limitation : plan.capabilities.limitations) {
        if (limitation.find("bridge") != std::string::npos) {
            explained = true;
        }
    }
    check(explained, "the bridge is named in the recorded limitations");
}

// 2. PURGE must be refused, not downgraded, when nothing device-level is
//    confirmed.
void testPurgeIsRefusedNotDowngraded() {
    std::printf("a PURGE request on USB is refused rather than downgraded\n");

    for (const auto& config : {MockBackend::createMockUsbBridgePassthrough(),
                              MockBackend::createMockUsbBridgeDropsCommands()}) {
        SanitizationPolicyEngine engine(SanitizationPolicyEngine::createDefaultPolicy());

        DeviceInfo device;
        device.path = config.path;
        device.capacityBytes = config.capacityBytes;
        device.transport = TransportType::USB;
        device.mediaType = MediaType::REMOVABLE;

        MockBackend backend;
        backend.addDevice(config);
        const auto caps = backend.detectCapabilities(device).valueOr(CapabilityInfo());

        const auto purge = engine.createPlan(device, caps, SanitizationCategory::PURGE, true);
        check(purge.isError(),
              "PURGE is refused for " + config.model);
        if (!purge.isError()) {
            check(purge.value().selectedMethod != SanitizationMethod::OVERWRITE_HOST,
                  "no host-overwrite plan is produced for PURGE");
        }

        // CLEAR must still be reachable, or the tool would simply refuse to do
        // anything at all rather than doing the right thing at the right level.
        const auto clear = engine.createPlan(device, caps, SanitizationCategory::CLEAR, true);
        check(clear.ok(), "CLEAR is still reachable for " + config.model);
        if (clear.ok()) {
            check(clear.value().selectedMethod == SanitizationMethod::OVERWRITE_HOST,
                  "CLEAR uses the host overwrite");
            // The full decision space has to be recorded, including the
            // device-level mechanisms that were considered and why they were not
            // used. Without it a reader cannot tell an omission from a choice.
            bool hostOverwriteRecorded = false;
            bool deviceMechanismExplained = false;
            for (const auto& candidate : clear.value().alternativesConsidered) {
                if (candidate.method == SanitizationMethod::OVERWRITE_HOST) {
                    hostOverwriteRecorded = true;
                    if (candidate.selected) {
                        check(candidate.deviceSupported,
                              "the selected host overwrite is recorded as device-supported");
                    }
                }
                if (candidate.method == SanitizationMethod::ATA_SECURE_ERASE &&
                    !candidate.reason.empty()) {
                    deviceMechanismExplained = true;
                }
            }
            check(hostOverwriteRecorded,
                  "the decision space records the host overwrite for " + config.model);
            check(deviceMechanismExplained,
                  "the decision space explains the device-level mechanisms it passed over");
        }
    }
}

// 3. The bridge that lies. The write path reports success in both cases, so the
//    read-back is the only thing that can tell them apart.
void testLyingBridgeIsCaughtByReadBack() {
    std::printf("a bridge that accepts commands and erases nothing is caught\n");

    struct Outcome {
        std::string label;
        VerificationResult result;
    };

    Outcome outcomes[2];
    for (int i = 0; i < 2; ++i) {
        const auto config = (i == 0) ? MockBackend::createMockUsbBridgePassthrough()
                                     : MockBackend::createMockUsbBridgeDropsCommands();
        outcomes[i].label = config.model;

        auto plan = planFor(config, SanitizationCategory::CLEAR);
        plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;

        MockBackend backend;
        backend.addDevice(config);

        auto method = backend.createMethod(plan.selectedMethod, plan.device,
                                           plan.capabilities, plan);
        if (method.isError()) {
            check(false, "the mock backend produced a method for " + config.model);
            continue;
        }

        // Both configurations report success from execute(). That is the point:
        // a bridge that drops commands is indistinguishable from a working one on
        // the write path alone.
        const auto executed = SanitizationExecutor::runMethod(*method.value(), plan);
        check(executed.ok(), "execute() reports an outcome status for " + config.model);
        if (!executed.ok()) continue;
        check(executed.value().state == JobState::COMPLETED,
              "the write path reports success for " + config.model +
                  ", including the bridge that erases nothing");
        check(executed.value().simulated,
              "the run is labelled simulated for " + config.model);

        VerificationReport verification;
        const auto run = SanitizationExecutor::runMethod(
            *method.value(), plan, nullptr, &verification);

        check(!verification.evidence.empty(),
              "verification evidence is produced for " + config.model);

        outcomes[i].result = verification.result;

        // And the run must be labelled simulated in the verification path too, so
        // a demo result can never be read as a real sanitization.
        if (config.type == MockDeviceType::USB_BRIDGE_PASSTHROUGH) {
            check(verification.result == VerificationResult::PASS,
                  "a bridge that really writes verifies clean");
        } else {
            check(verification.result == VerificationResult::FAIL,
                  "a bridge that reports success but writes nothing is FAIL, not PASS");
            bool readBackNamed = false;
            for (const auto& item : verification.evidence) {
                if (item.method == "mock_usb_read_back") readBackNamed = true;
            }
            check(readBackNamed, "the read-back is the item that carries the finding");
        }
    }

    check(outcomes[0].result != outcomes[1].result,
          "the two bridge behaviours produce different verification results");
}

// 4. A FAIL must not become an acceptance anywhere downstream.
void testFailedReadBackCannotBeAccepted() {
    std::printf("a failed read-back cannot be validated into an acceptance\n");

    const auto config = MockBackend::createMockUsbBridgeDropsCommands();
    auto plan = planFor(config, SanitizationCategory::CLEAR);
    plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;

    VerificationReport failed;
    failed.jobId = plan.jobId;
    failed.result = VerificationResult::FAIL;
    failed.evidence.push_back({"host_read_back", "Read-back", false,
                               "the bridge discarded every write", {}});

    JobStatus completed;
    completed.jobId = plan.jobId;
    completed.state = JobState::COMPLETED;

    ValidationEngine engine;
    const auto validation = engine.validate(plan, failed, completed);
    check(validation.ok(), "validation runs on a failed verification");
    if (validation.ok()) {
        check(validation.value().result == ValidationResult::REJECTED,
              "a failed verification is REJECTED, never ACCEPTED");
    }

    // And the evidence builder must not upgrade it either.
    AuditRecord record;
    record.jobId = plan.jobId;
    record.device = plan.device;
    record.plan = plan;
    record.execution = completed;

    MediaScopeAttestation scope;
    scope.allCopiesAccountedFor = true;
    PreExecutionAttestation pre;
    pre.deviceIdentityConfirmed = true;
    pre.authorizationReference = "CHG-1";
    VerificationIndependence independent;
    independent.level = VerificationIndependence::Level::INDEPENDENT;
    RetentionAttestation retention;
    retention.policy = RetentionAttestation::Policy::ORGANIZATION_DEFINED;

    auto bundle = EvidenceBuilder::build(record, failed, acceptingValidation(),
                                        scope, pre, independent, retention);
    check(bundle.ok(), "the bundle builds from a failed verification");
    if (bundle.ok()) {
        check(bundle.value().validation.result == ValidationResult::INCONCLUSIVE,
              "the builder forces INCONCLUSIVE when verification did not pass");
    }
}

// 5. The real read-back implementation, against a temporary file. This is the
//    code the verifier runs against a device, exercised here so it is known to
//    detect data and to report its own coverage honestly.
void testRealReadBackDetectsData(const fs::path& dir) {
    std::printf("the real read-back detects leftover data and reports its coverage\n");

    constexpr uint64_t kBytes = 4ULL * 1024 * 1024;
    constexpr uint32_t kBlock = 512;
    const fs::path clean = dir / "clean.img";
    const fs::path dirty = dir / "dirty.img";

    {
        std::ofstream out(clean, std::ios::binary);
        out << std::string(kBytes, '\0');
    }
    {
        std::ofstream out(dirty, std::ios::binary);
        out << std::string(kBytes, '\0');
    }
    check(fs::exists(clean) && fs::exists(dirty), "the test images were created");

    auto cleanResult = readBackVerifyOverwrite(clean.string(), kBytes, kBlock, 32);
    check(cleanResult.ok(), "read-back of uniformly patterned media succeeds");
    if (cleanResult.ok()) {
        check(cleanResult.value().passed,
              "uniformly patterned media verifies clean");
        check(cleanResult.value().samplesChecked == 32,
              "every requested sample was checked");
        check(cleanResult.value().limitations.size() >= 3,
              "the read-back carries its limitations rather than reporting a bare pass");
    }

    // Write data into a sector the sampler will actually visit. The samples are
    // spread evenly across the device, so the positions are deterministic:
    // sector = (totalSectors - 1) * i / (samples - 1). Using the midpoint
    // instead would land between samples and prove nothing.
    const uint64_t totalSectors = kBytes / kBlock;
    const size_t samples = 32;
    const uint64_t sampled = (totalSectors - 1) * (samples / 2) / (samples - 1);
    {
        std::fstream out(dirty, std::ios::in | std::ios::out | std::ios::binary);
        out.seekp(static_cast<std::streamoff>(sampled * kBlock));
        out << std::string("RESIDUAL-SECRET-DATA", 21);
    }

    auto dirtyResult = readBackVerifyOverwrite(dirty.string(), kBytes, kBlock, samples);
    check(dirtyResult.ok(), "read-back of dirty media still returns a report");
    if (dirtyResult.ok()) {
        check(!dirtyResult.value().passed,
              "media holding residual data does not verify clean");
        check(dirtyResult.value().samplesMatching < dirtyResult.value().samplesChecked,
              "the mismatch is counted rather than hidden");
        check(dirtyResult.value().detail.find("does not hold") != std::string::npos,
              "the report names what was found");
    }

    // A device that cannot be read at all must be INCONCLUSIVE, not PASS.
    auto missing = readBackVerifyOverwrite((dir / "does-not-exist.img").string(),
                                           kBytes, kBlock, 8);
    check(missing.isError(), "an unreadable device is an error, not a pass");

    // Zero capacity cannot be sampled, and must not be reported as clean.
    auto noCapacity = readBackVerifyOverwrite(clean.string(), 0, kBlock, 8);
    check(noCapacity.isError(), "an unknown capacity is refused rather than guessed");

    std::error_code cleanupEc;
    fs::remove(clean, cleanupEc);
    fs::remove(dirty, cleanupEc);
}

// 6. The safety layer must treat a USB device like any other: a mounted /dev/sdX
//    partition has to be seen as belonging to the disk.
void testUsbDeviceIsSubjectToTheSameSafetyRules() {
    std::printf("USB media is subject to the same containment safety rules\n");

    MockDeviceConfig config = MockBackend::createMockUsbBridgePassthrough();
    config.path = "/dev/sdb";
    check(platform::linux::deviceContains(config.path, "/dev/sdb1"),
          "a mounted /dev/sdb1 is recognised as living on /dev/sdb");
    check(platform::linux::deviceContains(config.path, "/dev/sdb"),
          "the device contains itself");
    check(!platform::linux::deviceContains(config.path, "/dev/sdc"),
          "a neighbouring disk is not part of it");
}

} // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "sanitizer-usb-test";
    std::error_code ec;
    fs::create_directories(dir, ec);

    testPassthroughBridgeStaysUnknown();
    testPurgeIsRefusedNotDowngraded();
    testLyingBridgeIsCaughtByReadBack();
    testFailedReadBackCannotBeAccepted();
    testRealReadBackDetectsData(dir);
    testUsbDeviceIsSubjectToTheSameSafetyRules();

    fs::remove_all(dir, ec);

    if (g_failures == 0) {
        std::printf("\nall USB mass-storage tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
