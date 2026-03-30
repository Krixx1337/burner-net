#pragma once

#include "burner/net/config_bridge.h"
#include "burner/net/detail/polymorphic_error.h"

#include <cstdint>
#include <string>

namespace burner::net {

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

inline std::string ErrorCodeToString(ErrorCode code) {
#if defined(BURNERNET_HARDEN_ERRORS) && BURNERNET_HARDEN_ERRORS
    return ::burner::hostile_core::harden_error_code(code, static_cast<std::uint32_t>(BURNERNET_ERROR_XOR));
#else
    switch (code) {
    case ErrorCode::None:
        return "None";
    case ErrorCode::DisabledBackend:
        return "DisabledBackend";
    case ErrorCode::InitCurl:
        return "InitCurl";
    case ErrorCode::NoCurlHandle:
        return "NoCurlHandle";
    case ErrorCode::CurlGeneric:
        return "CurlGeneric";
    case ErrorCode::VerifyGeneric:
        return "VerifyGeneric";
    case ErrorCode::SigProvider:
        return "SigProvider";
    case ErrorCode::SigEmpty:
        return "SigEmpty";
    case ErrorCode::SigHeaderMissing:
        return "SigHeaderMissing";
    case ErrorCode::SigCompute:
        return "SigCompute";
    case ErrorCode::SigMismatch:
        return "SigMismatch";
    case ErrorCode::BootstrapConfig:
        return "BootstrapConfig";
    case ErrorCode::BootstrapAddDir:
        return "BootstrapAddDir";
    case ErrorCode::BootstrapLoad:
        return "BootstrapLoad";
    case ErrorCode::BootstrapSkip:
        return "BootstrapSkip";
    case ErrorCode::BootstrapLoaded:
        return "BootstrapLoaded";
    case ErrorCode::BootstrapWinOnly:
        return "BootstrapWinOnly";
    case ErrorCode::BootstrapIntegrityCfg:
        return "BootstrapIntegrityCfg";
    case ErrorCode::BootstrapIntegrityMissing:
        return "BootstrapIntegrityMissing";
    case ErrorCode::BootstrapIntegrityCompute:
        return "BootstrapIntegrityCompute";
    case ErrorCode::BootstrapIntegrityMismatch:
        return "BootstrapIntegrityMismatch";
    case ErrorCode::BootstrapModulePath:
        return "BootstrapModulePath";
    case ErrorCode::BodyTooLarge:
        return "BodyTooLarge";
    case ErrorCode::InvalidHeader:
        return "InvalidHeader";
    case ErrorCode::RedirectAuth:
        return "RedirectAuth";
    case ErrorCode::BootstrapDllDirs:
        return "BootstrapDllDirs";
    case ErrorCode::RequestBodyTooLarge:
        return "RequestBodyTooLarge";
    case ErrorCode::CurlApiIncomplete:
        return "CurlApiIncomplete";
    case ErrorCode::CurlApiUntrusted:
        return "CurlApiUntrusted";
    case ErrorCode::EnvironmentCompromised:
        return "EnvironmentCompromised";
    case ErrorCode::PreFlightAbort:
        return "PreFlightAbort";
    case ErrorCode::HeartbeatAbort:
        return "HeartbeatAbort";
    case ErrorCode::TransportVerificationFailed:
        return "TransportVerificationFailed";
    case ErrorCode::TlsVerificationFailed:
        return "TlsVerificationFailed";
    default:
        return "Unknown";
    }
#endif
}

} // namespace burner::net
