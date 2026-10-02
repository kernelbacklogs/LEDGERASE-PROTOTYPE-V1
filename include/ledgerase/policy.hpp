#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include <string>

#include "ledgerase/limitations.hpp"
#include <vector>

namespace ledgerase {

// One rule of the declarative policy table: for a category, the methods that
// may be chosen, in preference order.
//
// Only `category` and `allowedMethods` constrain anything. An earlier version
// of this struct also carried name, description, requiredCapabilities,
// forbiddenCapabilities, requireEncryption, allowHostOverwrite and
// allowHostCryptoErase. They read like policy and none of them was ever
// consulted - including the two host-method flags, whose names are exactly the
// ones an operator would look at to find out whether a host overwrite is
// permitted. A field that looks like a constraint and is not is worse than no
// field, so they are gone. The host-method permissions that do exist are
// PolicyConfig's, below, and they are read.
struct PolicyRule {
    SanitizationCategory category = SanitizationCategory::PURGE;
    std::vector<SanitizationMethod> allowedMethods;
};

struct PolicyConfig {
    // The declarative table. It is a *filter*, applied only when strictMode is
    // true: the per-transport ladder in selectMethod() is always consulted
    // afterwards and is the only thing that knows about NVMe SANICAP, USB
    // bridge opacity and the host overwrite floor. The default policy leaves
    // strictMode off, so the ladder alone decides - and createStrictPolicy()
    // turns the table on, which is what test_policy_states_which_path_decided
    // exercises.
    std::vector<PolicyRule> rules;
    bool strictMode = true;
    // When true, a method whose capability is UNKNOWN is not refused on that
    // basis alone. Read.
    bool allowUnknownCapabilities = false;
    // Whether a host overwrite or host crypto erase may be chosen at all. Read
    // by the ladder. These are the fields an operator looks at to learn whether
    // CLEAR is reachable on a device with no device-level mechanism.
    bool allowHostOverwrite = false;
    bool allowHostCryptoErase = false;
};

class SanitizationPolicyEngine {
public:
    explicit SanitizationPolicyEngine(const PolicyConfig& config = PolicyConfig());
    ~SanitizationPolicyEngine();

    // requestedMethod is honoured only when the device reports it as supported
    // and it is permitted for the requested category. A method named on the
    // command line is never adopted without both, and never adopted for Purge if
    // it is a host-side technique.
    Result<SanitizationPlan> createPlan(const DeviceInfo& device,
                                        const CapabilityInfo& capabilities,
                                        SanitizationCategory requestedCategory,
                                        bool dryRun = false,
                                        SanitizationMethod requestedMethod =
                                            SanitizationMethod::NONE);

    Result<SanitizationMethod> selectMethod(const DeviceInfo& device,
                                            const CapabilityInfo& capabilities,
                                            SanitizationCategory category);

    std::vector<std::string> getMethodRationale(SanitizationMethod method,
                                                 const DeviceInfo& device,
                                                 const CapabilityInfo& capabilities,
                                                 SanitizationCategory category);

    std::vector<std::string> getStandardReferences(SanitizationMethod method);
    std::vector<std::string> getVerificationPlan(SanitizationMethod method);
    std::vector<std::string> getValidationPlan(SanitizationMethod method);
    LimitationSet getLimitations(const DeviceInfo& device,
                                             const CapabilityInfo& capabilities,
                                             SanitizationMethod method);
    std::vector<std::string> getRisks(const DeviceInfo& device,
                                       const CapabilityInfo& capabilities,
                                       SanitizationMethod method);

    // Records every method that could have satisfied the requested category,
    // whether or not it was chosen, with the reason for each decision. This is
    // what makes "why this method" auditable instead of merely asserted.
    std::vector<MethodAssessment> assessCandidates(const DeviceInfo& device,
                                                   const CapabilityInfo& capabilities,
                                                   SanitizationCategory category,
                                                   SanitizationMethod selected);

    // The policy this engine is using. Exposed so a test can show that the
    // declarative table changes the answer when strict mode is on, rather than
    // leaving the table to be taken on trust.
    const PolicyConfig& config() const { return config_; }

    static PolicyConfig createDefaultPolicy();
    static PolicyConfig createStrictPolicy();
    static PolicyConfig createPermissivePolicy();

    bool isMethodSupported(SanitizationMethod method, const CapabilityInfo& caps) const;

    // The capability field a given method depends on. Centralised so the
    // decision record and the refusal message cannot disagree about why a method
    // was unavailable.
    static CapabilityStatus capabilityStatusFor(SanitizationMethod method,
                                                const CapabilityInfo& caps);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    PolicyConfig config_;
};

class SanitizationPlanner {
public:
    explicit SanitizationPlanner(SanitizationPolicyEngine& engine);
    ~SanitizationPlanner();

    Result<SanitizationPlan> plan(const DeviceInfo& device,
                                  const CapabilityInfo& capabilities,
                                  SanitizationCategory category,
                                  bool dryRun = false,
                                  SanitizationMethod requestedMethod =
                                      SanitizationMethod::NONE);

    // Applies the operator's overwrite pass count to a finished plan, and
    // attaches the disclosure that goes with it.
    //
    // This exists as its own step because the CLI learns the pass count from
    // the command line *after* the method has been selected, so the count is
    // not an input to selection and cannot live inside plan(). Leaving the
    // count out of this function is not a cosmetic omission: the flash warning
    // in policy.cpp is computed from it, so a caller that set
    // overwritePassCount directly would silently lose the disclosure.
    static void applyOverwritePassCount(SanitizationPlan& plan,
                                        uint8_t passCount);

    // The short form is the default: selected method, one-line reason, and a
    // single line naming what was ruled out when that is not already obvious
    // from the device type. `verbose` restores the full section-per-heading
    // report.
    Result<std::string> generatePlanReport(const SanitizationPlan& plan,
                                           bool verbose = false);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    SanitizationPolicyEngine& engine_;
};

} // namespace ledgerase