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

#ifndef BURNERNET_DIAGNOSTIC_STRINGS
#if defined(BURNERNET_HARDEN_ERRORS)
#define BURNERNET_DIAGNOSTIC_STRINGS (!(BURNERNET_HARDEN_ERRORS))
#elif defined(BURNER_HARDEN_ERRORS)
#define BURNERNET_DIAGNOSTIC_STRINGS (!(BURNER_HARDEN_ERRORS))
#else
#define BURNERNET_DIAGNOSTIC_STRINGS 1
#endif
#endif

// Compatibility alias for 1.2 consumers. New code should configure
// BURNERNET_DIAGNOSTIC_STRINGS directly.
#ifndef BURNERNET_HARDEN_ERRORS
#define BURNERNET_HARDEN_ERRORS (!(BURNERNET_DIAGNOSTIC_STRINGS))
#endif

enum class ErrorCode : uint32_t {
    None = 0,
    DisabledBackend = 1,
    InitCurl = 2,
    NoCurlHandle = 3,
    CurlGeneric = 4,
    VerifyGeneric = 5,
    SigProvider = 6,
    SigEmpty = 7,
    SigHeaderMissing = 8,
    SigCompute = 9,
    SigMismatch = 10,
    BootstrapConfig = 11,
    BootstrapAddDir = 12,
    BootstrapLoad = 13,
    BootstrapSkip = 14,
    BootstrapLoaded = 15,
    BootstrapWinOnly = 16,
    BootstrapIntegrityCfg = 17,
    BootstrapIntegrityMissing = 18,
    BootstrapIntegrityCompute = 19,
    BootstrapIntegrityMismatch = 20,
    BootstrapModulePath = 21,
    BodyTooLarge = 22,
    InvalidHeader = 23,
    RedirectAuth = 24,
    BootstrapDllDirs = 25,
    RequestBodyTooLarge = 26,
    UnsupportedStreamedMethod = 27,
    CurlApiIncomplete = 28,
    CurlApiUntrusted = 29,
    EnvironmentCompromised = 30,
    PreFlightAbort = 31,
    HeartbeatAbort = 32,
    TransportVerificationFailed = 33,
    TlsVerificationFailed = 34,
    HardenedSystemProxyForbidden = 35,
    HardenedVerifyPeerRequired = 36,
    HardenedVerifyHostRequired = 37,
    HardenedStackIsolationRequired = 38,
    HardenedDohRequired = 39,
    HardenedSystemDnsOrder = 40,
    HardenedResponseVerifierRequired = 41,
    HardenedTrustMountRequired = 42,
    HardenedPersistentMtlsForbidden = 43,
    CurlOptionFailed = 44,
    CredentialProviderFailed = 45,
    InvalidCredentials = 46,
    UnsupportedVerifiedStreaming = 47,
    InvalidHardenedDoh = 48,
    InvalidBootstrapDependency = 49,
    NetworkingRuntimeUnavailable = 50,
    OutOfMemory = 51,
    InvalidHardenedPin = 52,
    HardenedRedirectForbidden = 53,
    RequestGuardRejected = 54,
    TransferCancelled = 55,
    CallbackFailed = 56,
    BootstrapDirectoryRejected = 57,
    BootstrapBusy = 58,
    AllocatorHookInstallFailed = 59,
    DnsResolutionFailed = 60,
    ConnectFailed = 61,
    TimedOut = 62,
    WorkerThreadStartFailed = 63
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
