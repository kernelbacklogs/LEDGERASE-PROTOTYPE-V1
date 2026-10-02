#include "ledgerase/error.hpp"
#include <cerrno>
#include <cstring>

namespace ledgerase {

SanitizerError SanitizerError::fromErrno(int err, const std::string& context) {
    ErrorCode code;
    std::string action;

    switch (err) {
        case EACCES:
        case EPERM:
            code = ErrorCode::PERMISSION_DENIED;
            action = "Run with appropriate privileges (sudo) or check device permissions";
            break;
        case ENOENT:
            code = ErrorCode::DEVICE_NOT_FOUND;
            action = "Verify the device path exists and the device is connected";
            break;
        case EBUSY:
            code = ErrorCode::DEVICE_BUSY;
            action = "Unmount all partitions and stop any processes using the device";
            break;
        case EIO:
            code = ErrorCode::IO_ERROR;
            action = "Check device health and connections; may indicate hardware failure";
            break;
        case ENODEV:
            code = ErrorCode::DEVICE_REMOVED;
            action = "Device was removed during operation";
            break;
        case EROFS:
            code = ErrorCode::DEVICE_READ_ONLY;
            action = "Device is read-only; check write-protect switch or filesystem state";
            break;
        case ETIMEDOUT:
            code = ErrorCode::OPERATION_TIMEOUT;
            action = "Operation timed out; device may be unresponsive";
            break;
        case EINVAL:
            // EINVAL is overloaded on Linux. It means both "you passed me
            // something invalid" and "the device rejected this command" - an
            // NVMe controller answers a malformed CDB or an unsupported log page
            // with EINVAL, as does libata for a taskfile it will not accept.
            //
            // Mapping it to INVALID_ARGUMENT unconditionally put "check device
            // path and parameters" in front of an operator whose parameters were
            // fine and whose *drive* had rejected the command. The caller that
            // knows better overrides the code; where it does not, the message
            // states both possibilities instead of asserting one.
            code = ErrorCode::INVALID_ARGUMENT;
            action = "Either an argument was rejected, or the device refused the "
                     "command. Run 'capabilities <device>' to check what the device "
                     "reports supporting";
            break;
        case ENOTTY:
        case ENOTBLK:
            code = ErrorCode::UNSUPPORTED_OPERATION;
            action = "The target does not implement this interface. A disk image "
                     "cannot be sanitized with a device-level command";
            break;
        case ENXIO:
            code = ErrorCode::DEVICE_NOT_FOUND;
            action = "The device node exists but the device behind it does not. "
                     "Re-run 'list-devices' to refresh the device list";
            break;
        case ENOSPC:
            code = ErrorCode::IO_ERROR;
            action = "The device is full. Free space before sanitizing; a partial "
                     "overwrite is not a sanitization";
            break;
        case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            code = ErrorCode::DEVICE_BUSY;
            action = "The device is not accepting commands right now. Wait and retry";
            break;
        default:
            code = ErrorCode::INTERNAL_ERROR;
            action = "Check system logs for details";
            break;
    }

    std::string msg = context + ": " + std::strerror(err);
    return SanitizerError(code, msg, action);
}

} // namespace ledgerase

namespace std {
std::error_code make_error_code(ledgerase::ErrorCode e) {
    return std::error_code(static_cast<int>(e), std::generic_category());
}
}