#pragma once

#include <string>
#include <system_error>
#include <optional>
#include <variant>
#include <vector>

namespace ledgerase {

enum class ErrorCode : int {
    SUCCESS = 0,
    INVALID_ARGUMENT = 1,
    PERMISSION_DENIED = 2,
    DEVICE_NOT_FOUND = 3,
    DEVICE_BUSY = 4,
    DEVICE_REMOVED = 5,
    DEVICE_MOUNTED = 6,
    DEVICE_SYSTEM_DISK = 7,
    DEVICE_READ_ONLY = 8,
    UNSUPPORTED_OPERATION = 9,
    OPERATION_REJECTED = 10,
    OPERATION_TIMEOUT = 11,
    OPERATION_FAILED = 12,
    VERIFICATION_FAILED = 13,
    VALIDATION_FAILED = 14,
    VALIDATION_REJECTED = 15,
    INSUFFICIENT_PRIVILEGES = 16,
    IO_ERROR = 17,
    NVME_COMMAND_FAILED = 18,
    ATA_COMMAND_FAILED = 19,
    INVALID_DEVICE_STATE = 20,
    CAPABILITY_UNKNOWN = 21,
    NO_SUITABLE_METHOD = 22,
    CONFIRMATION_FAILED = 23,
    DRY_RUN_ONLY = 24,
    INTERNAL_ERROR = 25,
    NOT_IMPLEMENTED = 26,
    RESOURCE_EXHAUSTED = 27,
    CANCELLED = 28
};

class SanitizerError : public std::runtime_error {
public:
    explicit SanitizerError(ErrorCode code, const std::string& message,
                           const std::string& recommendedAction = "")
        : std::runtime_error(message), code_(code), recommendedAction_(recommendedAction) {}

    ErrorCode code() const noexcept { return code_; }
    const std::string& recommendedAction() const noexcept { return recommendedAction_; }

    static SanitizerError fromErrno(int err, const std::string& context);

private:
    ErrorCode code_;
    std::string recommendedAction_;
};

template<typename T>
class Result {
public:
    Result() = default;
    Result(const T& value) : value_(value) {}
    Result(T&& value) : value_(std::move(value)) {}
    Result(const SanitizerError& error) : error_(error) {}
    Result(SanitizerError&& error) : error_(std::move(error)) {}

    bool ok() const noexcept { return !error_.has_value(); }
    bool isError() const noexcept { return error_.has_value(); }

    const T& value() const & {
        if (error_) throw *error_;
        return *value_;
    }

    T& value() & {
        if (error_) throw *error_;
        return *value_;
    }

    const T&& value() const && {
        if (error_) throw *error_;
        return std::move(*value_);
    }

    T&& value() && {
        if (error_) throw *error_;
        return std::move(*value_);
    }

    const SanitizerError& error() const {
        if (!error_) throw SanitizerError(ErrorCode::INTERNAL_ERROR, "No error");
        return *error_;
    }

    SanitizerError& error() {
        if (!error_) throw SanitizerError(ErrorCode::INTERNAL_ERROR, "No error");
        return *error_;
    }

    T valueOr(const T& defaultValue) const noexcept {
        return error_ ? defaultValue : *value_;
    }

    static Result<T> ok(const T& value) { return Result<T>(value); }
    static Result<T> ok(T&& value) { return Result<T>(std::move(value)); }
    static Result<T> err(const SanitizerError& error) { return Result<T>(error); }
    static Result<T> err(SanitizerError&& error) { return Result<T>(std::move(error)); }
    static Result<T> err(ErrorCode code, const std::string& msg, const std::string& action = "") {
        return Result<T>(SanitizerError(code, msg, action));
    }

private:
    std::optional<T> value_;
    std::optional<SanitizerError> error_;
};

template<>
class Result<void> {
public:
    Result() = default;
    Result(const SanitizerError& error) : error_(error) {}
    Result(SanitizerError&& error) : error_(std::move(error)) {}

    bool ok() const noexcept { return !error_.has_value(); }
    bool isError() const noexcept { return error_.has_value(); }

    void value() const {
        if (error_) throw *error_;
    }

    const SanitizerError& error() const {
        if (!error_) throw SanitizerError(ErrorCode::INTERNAL_ERROR, "No error");
        return *error_;
    }

    SanitizerError& error() {
        if (!error_) throw SanitizerError(ErrorCode::INTERNAL_ERROR, "No error");
        return *error_;
    }

    static Result<void> success() { return Result<void>(); }
    static Result<void> err(const SanitizerError& error) { return Result<void>(error); }
    static Result<void> err(SanitizerError&& error) { return Result<void>(std::move(error)); }
    static Result<void> err(ErrorCode code, const std::string& msg, const std::string& action = "") {
        return Result<void>(SanitizerError(code, msg, action));
    }

private:
    std::optional<SanitizerError> error_;
};

#define TRY(expr) \
    ({ auto&& _result = (expr); \
       if (_result.isError()) return _result.error(); \
       std::move(_result).value(); })

#define TRY_VOID(expr) \
    ({ auto&& _result = (expr); \
       if (_result.isError()) return _result.error(); })

} // namespace ledgerase

namespace std {
template<>
struct is_error_code_enum<ledgerase::ErrorCode> : true_type {};
}