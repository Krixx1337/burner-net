#pragma once

#include "burner/net/export.h"
#include "burner/net/detail/polymorphic_error.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace burner::net {

namespace detail {

BURNER_API std::uint32_t ErrorXorKey() noexcept;

} // namespace detail

#ifndef BURNERNET_HARDEN_ERRORS
#if defined(BURNER_HARDEN_ERRORS)
#define BURNERNET_HARDEN_ERRORS BURNER_HARDEN_ERRORS
#elif defined(NDEBUG) && !defined(_DEBUG)
#define BURNERNET_HARDEN_ERRORS 1
#else
#define BURNERNET_HARDEN_ERRORS 0
#endif
#endif

enum class ErrorCode : uint32_t {
    None = 0,
    DisabledBackend,
    InitCurl,
    NoCurlHandle,
    CurlGeneric,
    VerifyGeneric,
    SigProvider,
    SigEmpty,
    SigHeaderMissing,
    SigCompute,
    SigMismatch,
    BootstrapConfig,
    BootstrapAddDir,
    BootstrapLoad,
    BootstrapSkip,
    BootstrapLoaded,
    BootstrapWinOnly,
    BootstrapIntegrityCfg,
    BootstrapIntegrityMissing,
    BootstrapIntegrityCompute,
    BootstrapIntegrityMismatch,
    BootstrapModulePath,
    BodyTooLarge,
    InvalidHeader,
    RedirectAuth,
    BootstrapDllDirs,
    RequestBodyTooLarge,
    CurlApiIncomplete,
    CurlApiUntrusted,
    EnvironmentCompromised,
    PreFlightAbort,
    HeartbeatAbort,
    TransportVerificationFailed,
    TlsVerificationFailed
};

inline constexpr bool IsSuccessCode(ErrorCode code) {
    return code == ErrorCode::None ||
        code == ErrorCode::BootstrapSkip ||
        code == ErrorCode::BootstrapLoaded ||
        code == ErrorCode::BootstrapWinOnly;
}

inline const char* ErrorCodeDebugString(ErrorCode code) {
#if defined(BURNERNET_HARDEN_ERRORS) && BURNERNET_HARDEN_ERRORS
    (void)code;
    return "Unknown";
#else
    static constexpr const char* kNames[] = {
        "None",
        "DisabledBackend",
        "InitCurl",
        "NoCurlHandle",
        "CurlGeneric",
        "VerifyGeneric",
        "SigProvider",
        "SigEmpty",
        "SigHeaderMissing",
        "SigCompute",
        "SigMismatch",
        "BootstrapConfig",
        "BootstrapAddDir",
        "BootstrapLoad",
        "BootstrapSkip",
        "BootstrapLoaded",
        "BootstrapWinOnly",
        "BootstrapIntegrityCfg",
        "BootstrapIntegrityMissing",
        "BootstrapIntegrityCompute",
        "BootstrapIntegrityMismatch",
        "BootstrapModulePath",
        "BodyTooLarge",
        "InvalidHeader",
        "RedirectAuth",
        "BootstrapDllDirs",
        "RequestBodyTooLarge",
        "CurlApiIncomplete",
        "CurlApiUntrusted",
        "EnvironmentCompromised",
        "PreFlightAbort",
        "HeartbeatAbort",
        "TransportVerificationFailed",
        "TlsVerificationFailed"
    };

    const auto index = static_cast<std::size_t>(code);
    return index < (sizeof(kNames) / sizeof(kNames[0])) ? kNames[index] : "Unknown";
#endif
}

inline std::string ErrorCodeToString(ErrorCode code) {
#if defined(BURNERNET_HARDEN_ERRORS) && BURNERNET_HARDEN_ERRORS
    return ::burner::hostile_core::harden_error_code(code, detail::ErrorXorKey());
#else
    return ErrorCodeDebugString(code);
#endif
}

} // namespace burner::net
