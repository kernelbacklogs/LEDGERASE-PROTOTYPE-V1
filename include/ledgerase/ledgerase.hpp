#pragma once

#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"
#include "ledgerase/device.hpp"
#include "ledgerase/capability.hpp"
#include "ledgerase/safety.hpp"
#include "ledgerase/policy.hpp"
#include "ledgerase/sanitization.hpp"
#include "ledgerase/verification.hpp"
#include "ledgerase/reporting.hpp"
#include "ledgerase/mock.hpp"
#include "ledgerase/cli.hpp"
#include "ledgerase/platform/linux.hpp"

#define LEDGERASE_VERSION "1.0.0"
#define LEDGERASE_VERSION_MAJOR 1
#define LEDGERASE_VERSION_MINOR 0
#define LEDGERASE_VERSION_PATCH 0

namespace ledgerase {

inline std::string getVersion() {
    return LEDGERASE_VERSION;
}

inline std::tuple<int, int, int> getVersionTuple() {
    return {LEDGERASE_VERSION_MAJOR, LEDGERASE_VERSION_MINOR, LEDGERASE_VERSION_PATCH};
}

} // namespace ledgerase