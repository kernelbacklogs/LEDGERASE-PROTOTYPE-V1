// Operator identity for the evidence record.
//
// This lives in the core library rather than the CLI because it is not a
// command-line concern: anything that produces an evidence record needs it, and
// a GUI would need it too.
//
// The whole reason this is a function rather than a call to getenv("USER") is
// sudo. sudo sets the effective user to root and overwrites USER and LOGNAME to
// match, so the environment names the account the process runs as and not the
// person who ran the command. A certificate that recorded "root" would name a
// machine account instead of the person who authorised destroying a disk.
//
// None of this is authentication. It is attribution: a label that says who to
// ask about the job. It proves nothing on its own and is not treated as if it
// did.

#include "ledgerase/operator.hpp"

#include <cstdlib>
#include <pwd.h>
#include <unistd.h>

#include <string>

namespace ledgerase {
namespace {

// The effective user's name, from the passwd database. sudo overwrites USER and
// LOGNAME with the target account, so the environment cannot answer this.
std::string passwdNameForUid(uint32_t uid) {
    const struct passwd* entry = ::getpwuid(static_cast<uid_t>(uid));
    if (entry != nullptr && entry->pw_name != nullptr && entry->pw_name[0] != '\0') {
        return entry->pw_name;
    }
    // Falling back to the numeric id is more useful than "unknown": it at least
    // distinguishes two different root-owned accounts.
    return "uid:" + std::to_string(uid);
}

uint32_t passwdUidForName(const std::string& name) {
    if (name.empty()) {
        return 0;
    }
    const struct passwd* entry = ::getpwnam(name.c_str());
    if (entry != nullptr) {
        return static_cast<uint32_t>(entry->pw_uid);
    }
    return 0;
}

} // namespace

OperatorIdentity currentOperatorIdentity() {
    OperatorIdentity identity;

    // SUDO_USER is the person who ran sudo, which is what an assessor needs.
    const char* sudoUser = std::getenv("SUDO_USER");
    const char* sudoUid = std::getenv("SUDO_UID");
    if (sudoUser != nullptr && sudoUser[0] != '\0') {
        identity.invokingUser = sudoUser;
        if (sudoUid != nullptr && sudoUid[0] != '\0') {
            identity.invokingUid =
                static_cast<uint32_t>(std::strtoul(sudoUid, nullptr, 10));
        }
    } else {
        // Not elevated: the login name is the person.
        if (const char* name = std::getenv("LOGNAME")) {
            if (name[0] != '\0') {
                identity.invokingUser = name;
            }
        }
        if (identity.invokingUser == "unknown-operator") {
            if (const char* name = std::getenv("USER")) {
                if (name[0] != '\0') {
                    identity.invokingUser = name;
                }
            }
        }
        identity.invokingUid = passwdUidForName(identity.invokingUser);
    }

    // The effective user, which under sudo is root.
    identity.effectiveUid = static_cast<uint32_t>(::geteuid());
    identity.effectiveUser = passwdNameForUid(identity.effectiveUid);
    identity.elevated = identity.invokingUser != identity.effectiveUser;
    return identity;
}

} // namespace ledgerase
