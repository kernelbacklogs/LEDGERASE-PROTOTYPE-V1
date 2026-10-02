#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/sanitization.hpp"
#include <string>
#include <vector>

namespace ledgerase {

class VerificationEngine {
public:
    VerificationEngine();
    ~VerificationEngine();

    Result<VerificationReport> verify(const SanitizationPlan& plan,
                                      const JobStatus& executionStatus,
                                      std::unique_ptr<ISanitizationMethod> method);

    Result<VerificationReport> verifyNvme(const DeviceInfo& device,
                                          const JobStatus& executionStatus,
                                          SanitizationMethod method);

    Result<VerificationReport> verifyAta(const DeviceInfo& device,
                                         const JobStatus& executionStatus,
                                         SanitizationMethod method);

    // Takes the plan rather than just the device, because the plan carries the
    // requested read-back depth (--verify sampled|full).
    Result<VerificationReport> verifyOverwrite(const SanitizationPlan& plan,
                                               const JobStatus& executionStatus);

    Result<VerificationReport> verifyCryptoErase(const DeviceInfo& device,
                                                 const JobStatus& executionStatus);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// Adds the read-back evidence item for a host overwrite to a report, and sets
// report.result from it.
//
// Shared by OverwriteMethod::verify() and VerificationEngine::verifyOverwrite()
// deliberately. The method's verification is preferred by the executor, so if
// only the engine did the read-back a real overwrite would never be verified by
// one: the method's own PASS, based on write completion alone, would shadow it.
// Two copies of this logic would drift; there is one.
//
// The item is appended, not substituted, and the caller adds whatever else it
// can evidence. result is set to PASS on a clean read-back, FAIL on a dirty one,
// and INCONCLUSIVE when the media could not be read at all - "we could not look"
// is not "we looked and it was clean".
// `exhaustive` reads every sector rather than a 64-sector sample. The two
// support very different statements, so the caller states which one it wants
// and the evidence records which was performed.
void addOverwriteReadBackEvidence(const DeviceInfo& device,
                                   VerificationReport& report,
                                   bool exhaustive = false);

class ValidationEngine {
public:
    ValidationEngine();
    ~ValidationEngine();

    Result<ValidationReport> validate(const SanitizationPlan& plan,
                                      const VerificationReport& verification,
                                      const JobStatus& executionStatus);

    Result<ValidationReport> validateNvme(const SanitizationPlan& plan,
                                          const VerificationReport& verification,
                                          const JobStatus& executionStatus);

    Result<ValidationReport> validateAta(const SanitizationPlan& plan,
                                         const VerificationReport& verification,
                                         const JobStatus& executionStatus);

    Result<ValidationReport> validateOverwrite(const SanitizationPlan& plan,
                                               const VerificationReport& verification,
                                               const JobStatus& executionStatus);

    Result<ValidationReport> validateCryptoErase(const SanitizationPlan& plan,
                                                 const VerificationReport& verification,
                                                 const JobStatus& executionStatus);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace ledgerase