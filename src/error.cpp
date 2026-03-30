#include "burner/net/error.h"

namespace burner::net {

const char* ErrorCodeDebugString(ErrorCode code) noexcept {
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

std::string ErrorCodeToString(ErrorCode code) {
#if defined(BURNERNET_HARDEN_ERRORS) && BURNERNET_HARDEN_ERRORS
    return ::HOSTILE_CORE_NAMESPACE::harden_error_code(code, detail::ErrorXorKey());
#else
    return ErrorCodeDebugString(code);
#endif
}

} // namespace burner::net
