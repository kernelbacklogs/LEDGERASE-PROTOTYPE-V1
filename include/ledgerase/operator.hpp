#pragma once

#include <cstdint>
#include <string>

namespace ledgerase {

// Who ran the job, and who the process ran as. Under sudo these differ, and
// the difference is what a certificate has to record: "root" names no person.
// Not a credential and not an authentication mechanism - an attribution label.
struct OperatorIdentity {
    std::string invokingUser = "unknown-operator";
    uint32_t invokingUid = 0;
    std::string effectiveUser = "unknown";
    uint32_t effectiveUid = 0;
    // True when the effective user is not the invoking user.
    bool elevated = false;
};

// Exposed so the behaviour can be tested: the point of the function is what it
// does when SUDO_USER is set, and that cannot be checked while it is hidden.
OperatorIdentity currentOperatorIdentity();

} // namespace ledgerase
