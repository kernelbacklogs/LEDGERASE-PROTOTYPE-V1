#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/device.hpp"
#include <string>
#include <vector>

namespace ledgerase {

enum class SafetyCheckResult {
    PASS,
    FAIL,
    WARNING
};

struct SafetyCheck {
    std::string name;
    SafetyCheckResult result = SafetyCheckResult::PASS;
    std::string message;
    std::string recommendation;
    bool critical = false;
};

struct SafetyReport {
    std::vector<SafetyCheck> checks;
    bool overallPass = true;
    bool hasCriticalFailure = false;

    void addCheck(const SafetyCheck& check);
    void addCheck(const std::string& name, SafetyCheckResult result,
                  const std::string& message, const std::string& recommendation,
                  bool critical = false);
};

class SafetyManager {
public:
    SafetyManager();
    ~SafetyManager();

    // The full safety report for a device.
    //
    // allowSystemDisk exists so a non-destructive command can inspect the running
    // system disk. It is deliberately NOT honoured on the sanitization path:
    // checkPreSanitization() passes false unconditionally, and the CLI's
    // --force does not reach either. Destroying the disk the running system
    // boots from is not something a command-line flag should be able to permit,
    // so there is no path by which it can be permitted.
    Result<SafetyReport> checkDeviceSafety(const std::string& devicePath,
                                           bool requireUnmounted = true,
                                           bool allowSystemDisk = false);

    // The pre-destruction check. The system-disk and boot-disk refusals here are
    // unconditional; there is no override.
    // The checks that need a plan: whether the chosen method is supported, and
    // the capability limitations that bear on it.
    //
    // Split out of checkPreSanitization() because the CLI runs the device checks
    // *before* it plans - a plan needs the capabilities, and the capabilities are
    // one of the things the safety report records. checkPreSanitization() has no
    // call site and never ran on any sanitization, which meant the method-support
    // check and the capability limitations were checked by nothing. This is what
    // the sanitize path calls instead, with the report it already has.
    Result<SafetyReport> addPlanChecks(const SafetyReport& basic,
                                       const DeviceInfo& device,
                                       const CapabilityInfo& capabilities,
                                       SanitizationCategory category,
                                       SanitizationMethod method);

    // basic checks, then addPlanChecks(). Kept for callers that have not already
    // run the device checks.
    Result<SafetyReport> checkPreSanitization(const DeviceInfo& device,
                                              const CapabilityInfo& capabilities,
                                              SanitizationCategory category,
                                              SanitizationMethod method);

    // Safety evaluation for a SIMULATED device.
    //
    // checkDeviceSafety() answers questions about the machine this code is
    // running on: it stats the path and reads the host's mount table and sysfs.
    // Against a mock device that is simply the wrong question. A mock
    // /dev/nvme0n1 would inherit the host's real safety state, so a demo run on
    // a machine whose /dev/nvme0n1 is the system disk would be refused for a
    // disk that does not exist - and, worse, a mock declared systemDisk=true
    // would be allowed through, because the host's state said otherwise.
    //
    // This evaluates only what the device itself reports, and records in the
    // report that the running system was not consulted, so nobody can read a
    // simulated safety report as a statement about real hardware.
    static Result<SafetyReport> checkSimulatedDeviceSafety(const DeviceInfo& device);

    Result<void> verifyDeviceIdentity(const DeviceInfo& device,
                                      const std::string& expectedSerialSuffix);

    // The unmounted / not-the-system-disk / not-the-boot-disk / writable checks
    // used to be reachable individually as well as through checkDeviceSafety().
    // Nothing called the individual forms, so they duplicated logic in one
    // place and could drift from the check that actually runs. They are gone;
    // checkDeviceSafety() is the one path, and it is the one the CLI uses.
    static std::vector<std::string> getActiveSwapDevices();
    static bool isDeviceMapperInUse(const std::string& devicePath);
    static bool isLvmInUse(const std::string& devicePath);
    static bool isRaidInUse(const std::string& devicePath);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class ConfirmationManager {
public:
    ConfirmationManager();
    ~ConfirmationManager();

    Result<void> requireSerialConfirmation(const DeviceInfo& device,
                                           int requiredSuffixLength = 6);

    // How a target is confirmed before it is destroyed.
    //
    // A block device is confirmed by its serial suffix, which is the strongest
    // thing available and is unchanged. A file or a disk image has no serial, so
    // a serial prompt can never be satisfied: the check that proves "this is the
    // file I meant" has to be the file's own name instead. Requiring a serial
    // that does not exist made confirmation impossible without --force, which is
    // a real gap rather than a safety feature.
    enum class ConfirmationBasis {
        SERIAL_SUFFIX,   // block device
        FILE_BASENAME,   // regular file or disk image
    };

    // `expectedSerial` and `expectedName` are the non-interactive forms
    // (--expect-serial, --expect-name), for scripts. When set, the value is
    // compared without prompting; when empty, the operator is asked.
    Result<void> requireTargetConfirmation(
        const DeviceInfo& device,
        ConfirmationBasis basis,
        int requiredSuffixLength = 6,
        const std::string& expectedSerial = std::string(),
        const std::string& expectedName = std::string());

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace ledgerase