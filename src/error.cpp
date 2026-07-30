#include "burner/net/error.h"
#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/detail/constexpr_obfuscation.h"

namespace burner::net {

namespace detail {

std::uint32_t ErrorXorKey() noexcept {
    static constinit const std::uint32_t key = ::burner::net::obf::build_error_xor_key();
    return key;
}

} // namespace detail

const char* ErrorCodeDebugString(ErrorCode code) noexcept {
#if !BURNERNET_DIAGNOSTIC_STRINGS
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
        "UnsupportedStreamedMethod",
        "CurlApiIncomplete",
        "CurlApiUntrusted",
        "EnvironmentCompromised",
        "PreFlightAbort",
        "HeartbeatAbort",
        "TransportVerificationFailed",
        "TlsVerificationFailed",
        "HardenedSystemProxyForbidden",
        "HardenedVerifyPeerRequired",
        "HardenedVerifyHostRequired",
        "HardenedStackIsolationRequired",
        "HardenedDohRequired",
        "HardenedSystemDnsOrder",
        "HardenedResponseVerifierRequired",
        "HardenedTrustMountRequired",
        "HardenedPersistentMtlsForbidden",
        "CurlOptionFailed",
        "CredentialProviderFailed",
        "InvalidCredentials",
        "UnsupportedVerifiedStreaming",
        "InvalidHardenedDoh",
        "InvalidBootstrapDependency",
        "NetworkingRuntimeUnavailable",
        "OutOfMemory",
        "InvalidHardenedPin",
        "HardenedRedirectForbidden",
        "RequestGuardRejected",
        "TransferCancelled",
        "CallbackFailed",
        "BootstrapDirectoryRejected",
        "BootstrapBusy",
        "AllocatorHookInstallFailed",
        "DnsResolutionFailed",
        "ConnectFailed",
        "TimedOut",
        "WorkerThreadStartFailed",
        "MaximumGhostRuntimeRequired"
    };
    static_assert(
        (sizeof(kNames) / sizeof(kNames[0])) ==
        static_cast<std::size_t>(ErrorCode::MaximumGhostRuntimeRequired) + 1);

    const auto index = static_cast<std::size_t>(code);
    return index < (sizeof(kNames) / sizeof(kNames[0])) ? kNames[index] : "Unknown";
#endif
}

std::string ErrorCodeToString(ErrorCode code) {
#if !BURNERNET_DIAGNOSTIC_STRINGS
    return "E" + std::to_string(static_cast<std::uint32_t>(code));
#else
    return ErrorCodeDebugString(code);
#endif
}

} // namespace burner::net
