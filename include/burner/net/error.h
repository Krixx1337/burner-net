#pragma once

#ifndef HOSTILE_CORE_NAMESPACE
#define HOSTILE_CORE_NAMESPACE burner_hostile
#endif

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

BURNER_API const char* ErrorCodeDebugString(ErrorCode code) noexcept;
BURNER_API std::string ErrorCodeToString(ErrorCode code);

} // namespace burner::net
