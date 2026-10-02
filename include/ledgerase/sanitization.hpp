#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include <cstdint>
#include <string>

#include "ledgerase/limitations.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace ledgerase {

class ISanitizationMethod {
public:
    virtual ~ISanitizationMethod() = default;

    virtual Result<void> execute() = 0;
    virtual Result<void> cancel() = 0;
    virtual Result<JobStatus> status() const = 0;
    virtual Result<VerificationReport> verify() = 0;
    virtual std::string describe() const = 0;
    virtual LimitationSet limitations() const = 0;
    virtual SanitizationMethod methodType() const = 0;
    virtual bool supportsCancel() const = 0;
    virtual bool supportsProgress() const = 0;

    // True only for simulated methods. The executor stamps this into the
    // resulting JobStatus so a mock run is never presented as real.
    virtual bool isSimulated() const { return false; }
};

// Builds a sanitization method for a plan. The CLI installs a mock factory in
// simulation mode so a mock plan can never reach a real device method, and
// leaves it unset for real hardware.
using SanitizationMethodFactory =
    std::function<Result<std::unique_ptr<ISanitizationMethod>>(
        SanitizationMethod,
        const DeviceInfo&,
        const CapabilityInfo&,
        const SanitizationPlan&)>;

class SanitizationExecutor {
public:
    SanitizationExecutor();
    ~SanitizationExecutor();

    // Installs an alternative method factory (simulation). Passing nullptr
    // restores the built-in real-hardware methods.
    void setMethodFactory(SanitizationMethodFactory factory);
    bool hasMethodFactory() const;

    Result<std::unique_ptr<ISanitizationMethod>> createMethod(
        SanitizationMethod method,
        const DeviceInfo& device,
        const CapabilityInfo& capabilities,
        const SanitizationPlan& plan);

    Result<void> execute(const SanitizationPlan& plan,
                         std::function<void(const JobStatus&)> progressCallback = nullptr);

    // Executes and, through `outMethodVerification`, returns the verification
    // the method itself produced.
    //
    // The method performed the operation and is the only component that knows
    // what actually happened to it, so its verification is preferred over a
    // re-derivation from the plan. The engine's verify() is a fallback for
    // answering questions about a *recorded* job, where no method object exists
    // any more. Without this distinction the method-level verify()
    // implementations were unreachable, and a simulated device's simulated
    // read-back never ran.
    Result<JobStatus> executeWithMonitoring(const SanitizationPlan& plan,
                                            std::function<void(const JobStatus&)> progressCallback = nullptr,
                                            VerificationReport* outMethodVerification = nullptr);

    // Runs an already-constructed method and produces the final JobStatus.
    // Shared by the real and simulated paths so both report failures, states
    // and durations identically. A method that returns an error is always
    // reported as JobState::FAILED carrying the error message and code; the
    // method's own status is never allowed to overwrite that outcome with a
    // default-constructed value.
    static Result<JobStatus> runMethod(ISanitizationMethod& method,
                                       const SanitizationPlan& plan,
                                       std::function<void(const JobStatus&)> progressCallback = nullptr,
                                       VerificationReport* outMethodVerification = nullptr);

    static std::string generateJobId();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class NvmeSanitizeMethod : public ISanitizationMethod {
public:
    NvmeSanitizeMethod(const DeviceInfo& device,
                       const CapabilityInfo& capabilities,
                       const SanitizationPlan& plan);
    ~NvmeSanitizeMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class AtaSanitizeMethod : public ISanitizationMethod {
public:
    AtaSanitizeMethod(const DeviceInfo& device,
                      const CapabilityInfo& capabilities,
                      const SanitizationPlan& plan);
    ~AtaSanitizeMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ---------------------------------------------------------------------------
// Read-back verification
//
// A device that offers no trustworthy status log - which is the normal case for
// USB mass storage, where the bridge decides what reaches the media and there
// is usually no Sanitize Status page to read - leaves the tool with one kind of
// evidence available: read the media back and see what is there.
//
// What that evidence is worth has to be stated precisely, because it is easy to
// overstate. A read-back establishes that the sampled locations hold the
// written pattern. It does not establish anything about locations that were not
// sampled, nor about media the device hides from the host, and a device that
// silently ignores writes would fail it while a device that writes to a
// different physical location than it reports would pass it. So the result
// carries the sample count, the fraction of the device covered, and an explicit
// list of what it cannot speak for.
// ---------------------------------------------------------------------------

// The byte written by a host overwrite. Zero rather than a random pattern on
// purpose: a fixed pattern is reproducible, so a verifier can state exactly what
// it looked for, and it costs no entropy generation on the sanitization path.
constexpr uint8_t kOverwritePatternByte = 0x00;

// Default read-back sample count. Enough to make an accidental "nothing was
// written" pass unlikely, few enough that verification stays quick on a large
// device.
constexpr size_t kDefaultReadBackSamples = 64;

struct ReadBackReport {
    bool attempted = false;
    bool passed = false;
    size_t samplesChecked = 0;
    size_t samplesMatching = 0;
    // Fraction of the device the samples cover. 0 when the capacity is unknown.
    double coveredFraction = 0.0;
    // True when every sector of the target was read, as opposed to a sample of
    // them. The two support very different statements, and the evidence has to
    // say which one was performed.
    bool exhaustive = false;
    std::string detail;
    LimitationSet limitations;
};

// Reads back `samples` evenly spaced sectors and reports whether they hold the
// overwrite pattern.
//
// The device is opened read-only. This never writes.
Result<ReadBackReport> readBackVerifyOverwrite(const std::string& devicePath,
                                               uint64_t capacityBytes,
                                               uint32_t blockSize,
                                               size_t samples = kDefaultReadBackSamples);

// Reads back every sector of the target.
//
// A sample says "the sectors I looked at are clean". This says "every sector
// is clean", which is a different and much stronger statement - and costs a
// full read of the medium, so it is not the default. `samplesChecked` then
// equals the sector count and `coveredFraction` is 1.0, and the report says so
// explicitly rather than leaving the reader to work it out.
Result<ReadBackReport> readBackVerifyEverySector(const std::string& devicePath,
                                                 uint64_t capacityBytes,
                                                 uint32_t blockSize);

class OverwriteMethod : public ISanitizationMethod {
public:
    OverwriteMethod(const DeviceInfo& device,
                    const CapabilityInfo& capabilities,
                    const SanitizationPlan& plan);
    ~OverwriteMethod() override;
    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class CryptoEraseMethod : public ISanitizationMethod {
public:
    CryptoEraseMethod(const DeviceInfo& device,
                      const CapabilityInfo& capabilities,
                      const SanitizationPlan& plan);
    ~CryptoEraseMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

class UnsupportedMethod : public ISanitizationMethod {
public:
    UnsupportedMethod(const DeviceInfo& device,
                      const CapabilityInfo& capabilities,
                      const SanitizationPlan& plan);
    ~UnsupportedMethod() override;

    Result<void> execute() override;
    Result<void> cancel() override;
    Result<JobStatus> status() const override;
    Result<VerificationReport> verify() override;
    std::string describe() const override;
    LimitationSet limitations() const override;
    SanitizationMethod methodType() const override;
    bool supportsCancel() const override;
    bool supportsProgress() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace ledgerase