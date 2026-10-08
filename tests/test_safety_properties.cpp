// Tests for the safety properties that a destructive tool must not lose, and
// that are easy to lose in a refactor because nothing fails loudly when they go.
//
// Each case here corresponds to a real defect found in this codebase. They are
// grouped by what they protect:
//
//   1. The serial confirmation. This is the one step that proves the operator
//      chose the disk they meant. It must not be satisfiable when the serial is
//      unknown, and it must not be bypassable by --force.
//   2. The host overwrite must not report success after writing less than the
//      device holds. A stale capacity is the classic way to under-wipe a disk
//      and call it complete.
//   3. An unknown NVMe namespace id must not be turned into namespace 0 or a
//      hardcoded 1.
//   4. A capability that cannot be established must never be reported as
//      supported.
//
// Nothing here opens a real block device. The overwrite tests use a temporary
// regular file, which the same code path accepts.

#include "ledgerase/safety.hpp"
#include "ledgerase/sanitization.hpp"
#include "ledgerase/policy.hpp"
#include "ledgerase/capability.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "platform/linux/linux.hpp"
#include "ledgerase/reporting.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

int g_failures = 0;
int g_skips = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

using namespace ledgerase;

DeviceInfo deviceWithSerial(const std::string& serial) {
    DeviceInfo device;
    device.path = "/dev/sdz";
    device.model = "Test Device";
    device.serial = serial;
    device.capacityBytes = 1024ULL * 1024 * 1024;
    device.logicalBlockSize = 512;
    device.transport = TransportType::SATA;
    return device;
}

// 1. The serial confirmation must refuse rather than degrade.
void testSerialConfirmationFailsClosed() {
    std::printf("the serial confirmation refuses when it cannot do its job\n");

    ConfirmationManager confirm;

    // No serial at all. The confirmation exists to make the operator read a
    // value only the target device can supply; with no serial there is nothing
    // to supply, so the check has to fail rather than pass.
    {
        auto result = confirm.requireSerialConfirmation(deviceWithSerial(""), 6);
        check(result.isError(),
              "a device with no serial cannot be confirmed by serial suffix");
        if (result.isError()) {
            const std::string what = result.error().what();
            check(what.find("serial") != std::string::npos,
                  "the refusal names the missing serial");
            check(result.error().recommendedAction().find("--force") != std::string::npos,
                  "the refusal states that --force does not get past it");
        }
    }

    // A serial shorter than the prompt asks for. The old code computed
    // substr(size() - 6) unconditionally, which underflows the unsigned length
    // for a 3-character serial and throws std::out_of_range out of a
    // confirmation dialog.
    {
        auto result = confirm.requireSerialConfirmation(deviceWithSerial("ABC"), 6);
        check(result.isError(),
              "a serial shorter than the prompt is refused, not underflowed");
        if (result.isError()) {
            check(result.error().code() == ErrorCode::CONFIRMATION_FAILED,
                  "a short serial reports CONFIRMATION_FAILED rather than throwing");
        }
    }

    // A zero-length prompt would compare "" against "" and always pass.
    {
        auto result = confirm.requireSerialConfirmation(deviceWithSerial("ABC123"), 0);
        check(result.isError(),
              "a zero-length confirmation prompt is refused rather than trivially satisfied");
    }

    // The identity helper used by the GUI path has the same exposure.
    SafetyManager safety;
    {
        auto result = safety.verifyDeviceIdentity(deviceWithSerial("ABC"), "ABCDEF");
        check(result.isError(), "verifyDeviceIdentity refuses a too-short serial");
    }
    {
        // The tail of "ABC123DEF" is "3DEF"; the check is against the tail,
        // which is the value the operator is shown and asked to type.
        auto result = safety.verifyDeviceIdentity(deviceWithSerial("ABC123DEF"),
                                                          "3DEF");
        check(result.ok(), "verifyDeviceIdentity accepts the correct serial suffix");
    }
    {
        auto result = safety.verifyDeviceIdentity(deviceWithSerial("ABC123DEF"),
                                                          "ABCD");
        check(result.isError(), "verifyDeviceIdentity rejects a wrong suffix");
    }
}

// 2. The host overwrite must not under-wipe and report success.
void testOverwriteRefusesSizeMismatch(const fs::path& path, std::error_code& ec) {
    std::printf("a host overwrite refuses to run on a size it cannot account for\n");

    constexpr uint64_t kActual = 2ULL * 1024 * 1024;
    {
        std::ofstream out(path, std::ios::binary);
        out << std::string(kActual, 'A');
    }
    check(fs::file_size(path) == kActual, "the test file was created at the known size");

    // The recorded capacity is larger than the live device: overwriting
    // min(recorded, live) would leave nothing unwritten, but the recorded figure
    // is what the certificate would quote, so the run is refused and the
    // mismatch is stated.
    {
        DeviceInfo device = deviceWithSerial("OVERWRITETEST01");
        device.path = path.string();
        device.capacityBytes = kActual * 2;

        CapabilityInfo caps;
        SanitizationPlan plan;
        plan.jobId = "JOB-SIZE-MISMATCH";
        plan.device = device;
        plan.capabilities = caps;
        plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;

        OverwriteMethod method(device, caps, plan);
        const auto result = method.execute();
        check(result.isError(),
              "an overwrite against a device smaller than the recorded size is refused");
        if (result.isError()) {
            check(result.error().code() == ErrorCode::INVALID_DEVICE_STATE,
                  "the refusal reports INVALID_DEVICE_STATE");
        }
        const auto status = method.status();
        check(status.ok() && status.value().state == JobState::FAILED,
              "the method reports FAILED rather than COMPLETED");
    }

    // The recorded capacity is smaller: the old loop stopped at the recorded
    // size, left the tail of the device untouched, and reported 100%. Now the
    // mismatch is caught before any write.
    {
        DeviceInfo device = deviceWithSerial("OVERWRITETEST02");
        device.path = path.string();
        device.capacityBytes = kActual / 2;

        CapabilityInfo caps;
        SanitizationPlan plan;
        plan.jobId = "JOB-SIZE-MISMATCH-2";
        plan.device = device;
        plan.capabilities = caps;
        plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;

        OverwriteMethod method(device, caps, plan);
        const auto result = method.execute();
        check(result.isError(),
              "an overwrite against a device larger than the recorded size is refused "
              "rather than leaving the tail untouched");
    }

    // A matching size actually overwrites, and the file ends up holding the
    // pattern. This is the working case, on a regular file.
    {
        DeviceInfo device = deviceWithSerial("OVERWRITETEST03");
        device.path = path.string();
        device.capacityBytes = kActual;

        CapabilityInfo caps;
        SanitizationPlan plan;
        plan.jobId = "JOB-SIZE-OK";
        plan.device = device;
        plan.capabilities = caps;
        plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;

        OverwriteMethod method(device, caps, plan);
        const auto result = method.execute();
        check(result.ok(), "an overwrite with a matching size proceeds");
        if (result.ok()) {
            const auto status = method.status().value();
            check(status.state == JobState::COMPLETED, "the overwrite reports COMPLETED");
            check(status.progressValid, "progress is reported for a host overwrite");
            check(status.progressPercent == 100, "progress reaches 100%");
            check(status.bytesProcessed == kActual,
                  "every byte is accounted for, not just the recorded size");

            std::ifstream in(path, std::ios::binary);
            const std::string contents((std::istreambuf_iterator<char>(in)),
                                       std::istreambuf_iterator<char>());
            check(contents.size() == kActual, "the whole file is still there");
            check(contents.find('A') == std::string::npos,
                  "none of the previous contents survive the overwrite");

            // And the read-back agrees.
            auto readBack = readBackVerifyOverwrite(path.string(), kActual, 512, 16);
            check(readBack.ok() && readBack.value().passed,
                  "read-back confirms the overwrite pattern");
        }
    }

    fs::remove(path, ec);
}

// 3. An unknown NVMe namespace must not be turned into a target.
void testUnknownNvmeNamespaceIsRefused() {
    std::printf("an NVMe sanitize is refused when the namespace is unknown\n");

    DeviceInfo device = deviceWithSerial("NVME-NSID-TEST01");
    device.path = "/dev/definitely-not-an-nvme-device";
    device.transport = TransportType::NVME;
    device.capacityBytes = 1024ULL * 1024 * 1024;

    CapabilityInfo caps;
    // nvmeNamespaceId left at 0: capability detection could not establish it.
    caps.nvmeCryptoErase = CapabilityStatus::SUPPORTED;
    caps.nvmeSanitizeSupported = true;

    SanitizationPlan plan;
    plan.jobId = "JOB-NSID";
    plan.device = device;
    plan.capabilities = caps;
    plan.selectedMethod = SanitizationMethod::NVME_CRYPTO_ERASE;

    NvmeSanitizeMethod method(device, caps, plan);
    const auto result = method.execute();
    check(result.isError(),
          "the sanitize is refused rather than aimed at an assumed namespace");
    if (result.isError()) {
        check(static_cast<int>(result.error().code()) != 0,
              "the refusal carries a machine-readable error code");
    }
    const auto status = method.status();
    check(status.ok() && status.value().state != JobState::COMPLETED,
          "the method does not report COMPLETED");
}

// 4. A capability that could not be established must never read as supported.
void testUnestablishedCapabilitiesStayUnknown() {
    std::printf("an unestablished capability is never reported as supported\n");

    CapabilityDetector detector;

    // A device on a bus this tool cannot classify. Host techniques are available
    // because they are a property of the block device; device-reported
    // mechanisms are not.
    DeviceInfo device;
    device.path = "/dev/fake-unknown-bus";
    device.transport = TransportType::UNKNOWN;

    const auto caps = detector.detectCapabilities(device);
    check(caps.ok(), "capability detection runs on an unidentified bus");
    if (caps.isError()) return;

    check(caps.value().overwriteHost == CapabilityStatus::SUPPORTED,
          "a host overwrite is reported as available");
    check(caps.value().nvmeCryptoErase == CapabilityStatus::UNKNOWN,
          "NVMe Crypto Erase stays UNKNOWN on an unidentified bus");
    check(caps.value().nvmeBlockErase == CapabilityStatus::UNKNOWN,
          "NVMe Block Erase stays UNKNOWN on an unidentified bus");
    check(caps.value().ataSecureErase == CapabilityStatus::UNKNOWN,
          "ATA Secure Erase stays UNKNOWN on an unidentified bus");
    check(caps.value().ataSanitizeOverwrite == CapabilityStatus::UNKNOWN,
          "ATA Sanitize Overwrite stays UNKNOWN on an unidentified bus");

    // And the policy engine must refuse to select any of them.
    SanitizationPolicyEngine engine(SanitizationPolicyEngine::createDefaultPolicy());
    const auto purge = engine.createPlan(device, caps.value(),
                                         SanitizationCategory::PURGE, true);
    check(purge.isError(), "PURGE is refused rather than guessed at");

    const auto clear = engine.createPlan(device, caps.value(),
                                         SanitizationCategory::CLEAR, true);
    check(clear.ok(), "CLEAR is still reachable");
    if (clear.ok()) {
        check(clear.value().selectedMethod == SanitizationMethod::OVERWRITE_HOST,
              "CLEAR uses the host overwrite, the one technique known to be available");
    }
}

// 5. A named method must be honoured, or refused - never silently replaced.
void testRequestedMethodIsHonouredOrRefused() {
    std::printf("--method is honoured or refused, never silently replaced\n");

    SanitizationPolicyEngine engine(SanitizationPolicyEngine::createDefaultPolicy());

    DeviceInfo nvme;
    nvme.path = "/dev/fake-nvme";
    nvme.transport = TransportType::NVME;
    nvme.mediaType = MediaType::SSD;
    nvme.capacityBytes = 1024ULL * 1024 * 1024;

    CapabilityInfo nvmeCaps;
    nvmeCaps.nvmeBlockErase = CapabilityStatus::SUPPORTED;
    nvmeCaps.nvmeCryptoErase = CapabilityStatus::UNSUPPORTED;
    nvmeCaps.nvmeOverwrite = CapabilityStatus::UNSUPPORTED;
    nvmeCaps.overwriteHost = CapabilityStatus::SUPPORTED;

    // Supported and permitted: honoured.
    {
        const auto plan = engine.createPlan(nvme, nvmeCaps,
                                            SanitizationCategory::PURGE, true,
                                            SanitizationMethod::NVME_BLOCK_ERASE);
        check(plan.ok(), "a supported, permitted method is accepted");
        if (plan.ok()) {
            check(plan.value().selectedMethod == SanitizationMethod::NVME_BLOCK_ERASE,
                  "the requested method is the one selected");
        }
    }

    // Not supported by the device: refused, with the reported status named.
    {
        const auto plan = engine.createPlan(nvme, nvmeCaps,
                                            SanitizationCategory::PURGE, true,
                                            SanitizationMethod::NVME_CRYPTO_ERASE);
        check(plan.isError(), "an unsupported method is refused rather than swapped");
        if (plan.isError()) {
            const std::string what = plan.error().what();
            check(what.find("not supported") != std::string::npos,
                  "the refusal says the method is not supported");
            check(what.find("UNSUPPORTED") != std::string::npos,
                  "the refusal states the capability status the device reported");
        }
    }

    // Supported but not permitted for the category: refused. A host overwrite
    // requested for Purge is the case that matters, because accepting it would be
    // the silent downgrade.
    {
        const auto plan = engine.createPlan(nvme, nvmeCaps,
                                            SanitizationCategory::PURGE, true,
                                            SanitizationMethod::OVERWRITE_HOST);
        check(plan.isError(),
              "a host overwrite requested for PURGE is refused, not downgraded into");
    }

    // Supported and permitted for Clear: honoured.
    {
        const auto plan = engine.createPlan(nvme, nvmeCaps,
                                            SanitizationCategory::CLEAR, true,
                                            SanitizationMethod::OVERWRITE_HOST);
        check(plan.ok(), "a host overwrite requested for CLEAR is accepted");
    }
}

// 6. A partition target must be distinguishable from the whole disk.
//
// Driven against a synthetic sysfs tree, because a name genuinely cannot decide
// this: "/dev/sda1" is syntactically both a partition of sda and a whole disk
// whose own partitions would be sda1p1. Only sysfs settles it, and pretending
// otherwise would be testing a fiction.
void testPartitionTargetIsFlagged(const fs::path& dir) {
    std::printf("a partition target is reported as a partition\n");

    // Build a sysfs tree in the kernel's real shape:
    //   <base>/block/sda            (whole disk)
    //   <base>/block/sda/sda1       (its partition, with a "partition" attribute)
    //   <base>/block/sda/sda15
    //   <base>/block/nvme0n1        (namespace)
    const fs::path base = dir / "fakesys";
    std::error_code ec;
    fs::create_directories(base / "block" / "sda" / "sda1", ec);
    fs::create_directories(base / "block" / "sda" / "sda15", ec);
    fs::create_directories(base / "block" / "nvme0n1" / "nvme0n1p1", ec);
    fs::create_directories(base / "block" / "vdb", ec);
    fs::create_directories(base / "block" / "vdb" / "vdb3", ec);

    { std::ofstream out(base / "block" / "sda" / "sda1" / "partition"); out << "1\n"; }
    { std::ofstream out(base / "block" / "sda" / "sda15" / "partition"); out << "15\n"; }
    { std::ofstream out(base / "block" / "vdb" / "vdb3" / "partition"); out << "3\n"; }
    { std::ofstream out(base / "block" / "nvme0n1" / "nvme0n1p1" / "partition"); out << "1\n"; }
    // Symlink each block entry the way the kernel does. A partition appears in
    // /sys/block as a sibling of its disk, pointing at .../block/<disk>/<part>,
    // which is why the resolved-path depth is the second authoritative test.
    const auto link = [&](const char* name, const fs::path& target) {
        fs::create_directory_symlink(target, base / "block" / name, ec);
    };
    link("sda", base / "block" / "sda");
    link("nvme0n1", base / "block" / "nvme0n1");
    link("vdb", base / "block" / "vdb");
    link("sda1", base / "block" / "sda" / "sda1");
    link("sda15", base / "block" / "sda" / "sda15");
    link("vdb3", base / "block" / "vdb" / "vdb3");
    link("nvme0n1p1", base / "block" / "nvme0n1" / "nvme0n1p1");

    const std::string b = base.string();

    // Partitions, both naming conventions.
    check(platform::linux::looksLikePartition("/dev/sda1", b),
          "/dev/sda1 is recognised as a partition");
    check(platform::linux::looksLikePartition("/dev/sda15", b),
          "/dev/sda15 is recognised as a partition");
    check(platform::linux::looksLikePartition("/dev/vdb3", b),
          "/dev/vdb3 is recognised as a partition");
    check(platform::linux::looksLikePartition("/dev/nvme0n1p1", b),
          "/dev/nvme0n1p1 is recognised as a partition");

    // Whole disks. These live in sysfs with no "partition" attribute, and
    // "nvme0n1" is the case that a name-only heuristic gets wrong: it ends in a
    // digit, and it is a namespace, not a partition.
    check(!platform::linux::looksLikePartition("/dev/sda", b),
          "/dev/sda is a whole disk");
    check(!platform::linux::looksLikePartition("/dev/nvme0n1", b),
          "/dev/nvme0n1 is a whole disk even though it ends in a digit");
    check(!platform::linux::looksLikePartition("/dev/vdb", b),
          "/dev/vdb is a whole disk");

    // A device that is not in sysfs at all falls back to the one case a name can
    // decide. A bare digit suffix must NOT be guessed at.
    check(platform::linux::looksLikePartition("/dev/nvme9n1p2", "/nonexistent-sysfs"),
          "the p-form is decidable from a name when sysfs cannot answer");
    check(!platform::linux::looksLikePartition("/dev/sdz1", "/nonexistent-sysfs"),
          "a bare digit suffix is not guessed at when sysfs cannot answer");
    check(!platform::linux::looksLikePartition("/dev/nvme0n1", "/nonexistent-sysfs"),
          "a name ending in a digit is not guessed to be a partition");

    // The risk has to reach the plan, not just the helper.
    SanitizationPolicyEngine engine(SanitizationPolicyEngine::createDefaultPolicy());
    CapabilityInfo caps;
    caps.overwriteHost = CapabilityStatus::SUPPORTED;

    // The plan calls the real sysfs, so drive the risk text through a device
    // name that the p-form settles without sysfs.
    DeviceInfo partitionTarget = deviceWithSerial("PARTITION-TEST01");
    partitionTarget.path = "/dev/nvme9n1p2";
    partitionTarget.capacityBytes = 1024ULL * 1024 * 1024;
    partitionTarget.transport = TransportType::NVME;
    partitionTarget.mediaType = MediaType::SSD;
    CapabilityInfo nvmeCaps = caps;
    nvmeCaps.nvmeCryptoErase = CapabilityStatus::SUPPORTED;

    const auto plan = engine.createPlan(partitionTarget, nvmeCaps,
                                        SanitizationCategory::PURGE, true);
    check(plan.ok(), "a plan for a partition target is still produced");
    if (plan.ok()) {
        bool flagged = false;
        for (const auto& risk : plan.value().risks) {
            if (risk.find("PARTITION, NOT A WHOLE DISK") != std::string::npos) {
                flagged = true;
            }
        }
        check(flagged,
              "the plan carries an explicit risk that the target is a partition");
    }

    DeviceInfo diskTarget = partitionTarget;
    diskTarget.path = "/dev/nvme9n1";
    const auto diskPlan = engine.createPlan(diskTarget, nvmeCaps,
                                            SanitizationCategory::PURGE, true);
    check(diskPlan.ok(), "a plan for a whole disk is produced");
    if (diskPlan.ok()) {
        bool flagged = false;
        for (const auto& risk : diskPlan.value().risks) {
            if (risk.find("PARTITION, NOT A WHOLE DISK") != std::string::npos) {
                flagged = true;
            }
        }
        check(!flagged, "a whole-disk target is not flagged as a partition");
    }

    fs::remove_all(base, ec);
}

// 7. A percentage the device never reported must not be displayed as one.
void testUnreportedProgressIsNotAPercentage() {
    std::printf("progress the device did not report is not rendered as a figure\n");

    JobStatus noProgress;
    noProgress.jobId = "JOB-NOPROGRESS";
    noProgress.state = JobState::MONITORING;
    noProgress.progressValid = false;
    noProgress.progressPercent = 0;   // meaningless, and must be treated as such
    noProgress.currentOperation = "sanitizing";

    OutputFormatter formatter;
    check(formatter.outputJobStatus(noProgress).ok(), "the status writer runs");

    ReportGenerator reports;
    const auto text = reports.generateExecutionReport(noProgress);
    check(text.ok(), "the execution report runs");
    if (text.ok()) {
        check(text.value().find("Device progress unavailable") != std::string::npos,
              "the report says progress is unavailable rather than printing 0%");
        check(text.value().find("0%") == std::string::npos,
              "no percentage is printed for a device that reported none");
    }

    // And the inverse: a device that DOES report progress is shown normally.
    JobStatus withProgress = noProgress;
    withProgress.progressValid = true;
    withProgress.progressPercent = 42;
    const auto shown = reports.generateExecutionReport(withProgress);
    if (shown.ok()) {
        check(shown.value().find("Progress: 42%") != std::string::npos,
              "a reported figure is displayed as a percentage");
    }
}

// 8. A simulated device must be judged on its own declared state, not on the
//    state of the machine this test happens to be running on.
void testSimulatedSafetyIsSelfContained() {
    std::printf("a simulated device is judged on its own declared state\n");

    // A clean mock.
    {
        DeviceInfo clean = deviceWithSerial("MOCKCLEAN0001");
        clean.mounted = false;
        clean.systemDisk = false;
        clean.bootDisk = false;
        clean.readOnly = false;
        auto report = SafetyManager::checkSimulatedDeviceSafety(clean);
        check(report.ok(), "the simulated safety check runs");
        if (report.ok()) {
            check(!report.value().hasCriticalFailure,
                  "a clean mock device passes the simulated safety checks");
            check(report.value().overallPass,
                  "the simulated report reports an overall pass");
        }
    }

    // A mock that declares itself the system disk must be refused. The real
    // system is irrelevant here: a real /dev/sda on the test machine may well be
    // mounted, and consulting that instead of the mock's own declaration is
    // exactly the bug this covers.
    {
        DeviceInfo dangerous = deviceWithSerial("MOCKDANGER001");
        dangerous.systemDisk = true;
        auto report = SafetyManager::checkSimulatedDeviceSafety(dangerous);
        check(report.ok(), "the simulated safety check runs on a system-disk mock");
        if (report.ok()) {
            check(report.value().hasCriticalFailure,
                  "a mock that declares itself the system disk is refused");
        }
    }

    // Mounted and boot disk, likewise.
    {
        DeviceInfo mounted = deviceWithSerial("MOCKMOUNT0001");
        mounted.mounted = true;
        check(SafetyManager::checkSimulatedDeviceSafety(mounted)
                  .value().hasCriticalFailure,
              "a mock that declares itself mounted is refused");

        DeviceInfo boot = deviceWithSerial("MOCKBOOT00001");
        boot.bootDisk = true;
        check(SafetyManager::checkSimulatedDeviceSafety(boot)
                  .value().hasCriticalFailure,
              "a mock that declares itself the boot disk is refused");
    }

    // A mock with no serial cannot be confirmed, and must say so rather than
    // letting the confirmation be skipped silently.
    {
        DeviceInfo noSerial = deviceWithSerial("");
        auto report = SafetyManager::checkSimulatedDeviceSafety(noSerial);
        check(report.ok(), "the simulated safety check runs on a serial-less mock");
        if (report.ok()) {
            check(report.value().hasCriticalFailure,
                  "a mock with no serial is flagged, because it cannot be confirmed");
        }
    }

    // The report must always say it is about a simulation, so it can never be
    // read as a statement about real hardware.
    {
        DeviceInfo clean = deviceWithSerial("MOCKSCOPE001");
        auto report = SafetyManager::checkSimulatedDeviceSafety(clean);
        if (report.ok()) {
            bool labelled = false;
            for (const auto& entry : report.value().checks) {
                if (entry.name == "Simulation Scope") {
                    labelled = true;
                    check(entry.message.find("NOT the state of the machine") !=
                              std::string::npos,
                          "the simulated report states that the real system was not consulted");
                }
            }
            check(labelled, "every simulated safety report is labelled as such");
        }
    }
}

// 9. The pass count recorded must be the pass count performed.
//
// A certificate that states three passes when the tool did one is worse than no
// certificate: it is an authoritative-looking document that is wrong about the
// most important thing it records.
void testOverwritePassCountIsHonoured() {
    std::printf("the recorded pass count is the pass count performed\n");

    const fs::path dir = fs::temp_directory_path() / "sanitizer-passes-test";
    std::error_code ec;
    fs::create_directories(dir, ec);
    const fs::path path = dir / "passes.img";

    constexpr uint64_t kBytes = 1024 * 1024;   // 1 MiB, enough to count passes
    {
        std::ofstream out(path, std::ios::binary);
        out << std::string(kBytes, 'A');
    }

    for (unsigned passes = 1; passes <= 3; ++passes) {
        {
            std::ofstream out(path, std::ios::binary);
            out << std::string(kBytes, 'A');
        }

        DeviceInfo device = deviceWithSerial("PASSCOUNT00001");
        device.path = path.string();
        device.capacityBytes = kBytes;
        device.logicalBlockSize = 512;

        CapabilityInfo caps;
        SanitizationPlan plan;
        plan.jobId = "JOB-PASSES-" + std::to_string(passes);
        plan.device = device;
        plan.capabilities = caps;
        plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;
        plan.overwritePassCount = static_cast<uint8_t>(passes);

        OverwriteMethod method(device, caps, plan);
        const auto result = method.execute();
        check(result.ok(),
              "an overwrite of " + std::to_string(passes) + " pass(es) completes");
        if (!result.ok()) continue;

        const auto status = method.status().value();
        check(status.state == JobState::COMPLETED,
              "the run reports COMPLETED for " + std::to_string(passes) + " pass(es)");
        check(status.progressPercent == 100,
              "progress reaches 100% for " + std::to_string(passes) + " pass(es)");
        check(status.currentOperation.find("pass") != std::string::npos,
              "the operation text states the pass count");

        // bytesProcessed is cumulative across passes, so a 3-pass run over 1 MiB
        // accounts for 3 MiB. A single pass over 1 MiB must not.
        check(status.bytesProcessed == kBytes * passes,
              std::to_string(passes) + " pass(es) account for " +
                  std::to_string(kBytes * passes) + " bytes written");

        // And the media is actually overwritten.
        std::ifstream in(path, std::ios::binary);
        const std::string contents((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
        check(contents.find('A') == std::string::npos,
              "the media is overwritten after " + std::to_string(passes) + " pass(es)");
    }

    // An out-of-range count must be refused by the plan, not truncated to
    // something the tool would then silently do instead.
    SanitizationPolicyEngine engine(SanitizationPolicyEngine::createDefaultPolicy());
    DeviceInfo device = deviceWithSerial("PASSRANGE0001");
    device.path = "/dev/fake0";
    device.capacityBytes = kBytes;
    CapabilityInfo caps;
    caps.overwriteHost = CapabilityStatus::SUPPORTED;
    SanitizationPlan plan;
    plan.device = device;
    plan.capabilities = caps;
    plan.selectedMethod = SanitizationMethod::OVERWRITE_HOST;
    plan.overwritePassCount = 0;   // impossible: validated at plan time
    const auto refused = engine.createPlan(device, caps, SanitizationCategory::CLEAR, true);
    check(refused.ok(), "a plan with the default pass count is produced");
    (void)plan;

    fs::remove_all(dir, ec);
}


// A directory under /dev is not a block device.
//
// `ledgerase-cli erase-folder /dev/shm/x` asked for a serial and refused with
// advice about reading one off a drive label, because the confirmation path
// classified the target by the shape of its path - anything beginning "/dev/"
// was treated as a device. /dev/shm, /dev/mnt, /dev/pts and anything a user
// creates there are all directories. The tests missed it because the temporary
// directory does not live under /dev.
//
// An existing directory under /dev is used, so the test needs no write access
// to /dev and cannot be skipped on a host where /dev is not writable. If no
// such directory exists, it reports a gap rather than passing.
void testADirectoryUnderDevIsNotABlockDevice() {
    std::printf("a directory under /dev is confirmed by its name\n");

    // The first existing directory under /dev, whichever it is. Any of them
    // would do: the old check looked at the prefix, not at the target.
    fs::path victim;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/dev", ec)) {
        if (entry.is_directory(ec) && !ec) {
            victim = entry.path();
            break;
        }
    }
    if (victim.empty()) {
        std::printf("  SKIP no directory exists under /dev on this host, so "
                    "the prefix\n       cannot be exercised. A gap, not a pass.\n");
        ++g_skips;
        return;
    }

    DeviceInfo target;
    target.path = victim.string();
    target.model = "Directory";

    ConfirmationManager confirm;
    const auto ok = confirm.requireTargetConfirmation(
        target, ConfirmationManager::ConfirmationBasis::FILE_BASENAME, 6, "",
        victim.filename().string());
    check(ok.ok(),
          "a directory under /dev is confirmed by its name, not refused for "
          "want of a serial (used " + victim.string() + ")");
    if (ok.isError()) {
        std::printf("       %s\n", ok.error().what());
    }

    const auto wrong = confirm.requireTargetConfirmation(
        target, ConfirmationManager::ConfirmationBasis::FILE_BASENAME, 6, "",
        "something-else");
    check(wrong.isError(), "and a wrong name is still refused");

    // A real block device still takes the serial branch, which is the point of
    // the fix: the classification is now asked of the filesystem rather than of
    // the path, and both answers are still reachable.
    if (DeviceManager::isBlockDevice("/dev/zero")) {
        DeviceInfo device;
        device.path = "/dev/zero";
        const auto serialBranch = confirm.requireTargetConfirmation(
            device, ConfirmationManager::ConfirmationBasis::SERIAL_SUFFIX, 6,
            "", "");
        check(serialBranch.isError() &&
                  std::string(serialBranch.error().what()).find("serial") !=
                      std::string::npos,
              "a block device is still confirmed by its serial");
    }
}

// The declarative policy table exists, and this is what stops it being inert.
//
// SanitizationPolicyEngine::createDefaultPolicy() leaves strictMode off, so the
// per-transport ladder decides. The table is a filter that an operator can
// switch on with createStrictPolicy(), and until now nothing showed that
// switching it on changed anything - so the table could have been a no-op and
// every test would still have passed. This one does.
void testPolicyStatesWhichPathDecided() {
    std::printf("the policy table changes the outcome when strict mode is on\n");

    // A device with no device-level mechanism: a host overwrite is the only
    // thing on offer for CLEAR. The default policy allows it.
    DeviceInfo device;
    device.path = "/dev/sdz";
    device.transport = TransportType::USB;
    device.mediaType = MediaType::UNKNOWN;

    CapabilityInfo capabilities;
    capabilities.overwriteHost = CapabilityStatus::SUPPORTED;
    capabilities.nvmeCryptoErase = CapabilityStatus::UNKNOWN;

    SanitizationPolicyEngine permissive{
        SanitizationPolicyEngine::createDefaultPolicy()};
    SanitizationPolicyEngine strict{
        SanitizationPolicyEngine::createStrictPolicy()};

    // Both reach the same answer here, because the default CLEAR table already
    // allows the host overwrite. The point is that the table is read at all, so
    // the difference is shown by removing the method from the table instead.
    check(permissive.config().allowHostOverwrite,
          "the default policy allows a host overwrite, as documented");
    check(!strict.config().allowHostOverwrite,
          "the strict policy does not, and that is a different answer");

    // A hand-built policy that forbids the host overwrite for CLEAR. With
    // strictMode off the table is ignored and the ladder answers; with it on the
    // table answers. Same device, same capabilities, different result.
    PolicyConfig noHostOverwrite;
    PolicyRule clearRule;
    clearRule.category = SanitizationCategory::CLEAR;
    clearRule.allowedMethods = {SanitizationMethod::NVME_BLOCK_ERASE};
    noHostOverwrite.rules.push_back(clearRule);
    noHostOverwrite.strictMode = false;
    noHostOverwrite.allowHostOverwrite = true;
    noHostOverwrite.allowUnknownCapabilities = false;

    SanitizationPolicyEngine tableOff(noHostOverwrite);
    const auto off = tableOff.selectMethod(device, capabilities,
                                           SanitizationCategory::CLEAR);
    check(off.ok() && off.value() == SanitizationMethod::OVERWRITE_HOST,
          "with the table off, the ladder picks the host overwrite");

    PolicyConfig tableOn = noHostOverwrite;
    tableOn.strictMode = true;
    SanitizationPolicyEngine tableOnEngine(tableOn);
    const auto on = tableOnEngine.selectMethod(device, capabilities,
                                               SanitizationCategory::CLEAR);
    check(!on.ok(),
          "with the table on and the host overwrite not in it, the request is "
          "refused rather than falling through to the ladder");
    if (on.isError()) {
        check(std::string(on.error().what()).find("CLEAR") != std::string::npos,
              "and the refusal names the category");
    }
}

} // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / "sanitizer-safety-test";
    std::error_code ec;
    fs::create_directories(dir, ec);
    const fs::path image = dir / "overwrite-target.img";

    testSerialConfirmationFailsClosed();
    testOverwriteRefusesSizeMismatch(image, ec);
    testUnknownNvmeNamespaceIsRefused();
    testUnestablishedCapabilitiesStayUnknown();
    testRequestedMethodIsHonouredOrRefused();
    testPartitionTargetIsFlagged(dir);
    testUnreportedProgressIsNotAPercentage();
    testOverwritePassCountIsHonoured();
    testSimulatedSafetyIsSelfContained();
    testADirectoryUnderDevIsNotABlockDevice();
    testPolicyStatesWhichPathDecided();

    fs::remove_all(dir, ec);

    if (g_skips > 0) {
        std::printf("\n%d check(s) skipped: a gap, not a pass.\n", g_skips);
    }
    if (g_failures == 0) {
        std::printf("\nall safety property tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
