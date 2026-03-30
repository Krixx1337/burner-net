#pragma once

#include "burner/net/detail/constexpr_obfuscation.h"

#include <cstdint>
#include <cstdlib>
#include <string>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct HttpRequest;

} // namespace burner::net

// 1. Include the user's config if they provided one.
// In Visual Studio, add BURNERNET_USER_CONFIG_HEADER="MyConfig.h" to Preprocessor Definitions.
#ifdef BURNERNET_USER_CONFIG_HEADER
#include BURNERNET_USER_CONFIG_HEADER
#endif

// 2. Provide safe defaults for every hook.
// If the developer did not define these in their config, BurnerNet falls back
// to standard, non-obfuscated behavior.

#ifndef BURNER_OBF_LITERAL
#define BURNER_OBF_LITERAL(str) ::burner::hostile_core::ObfuscatedString<sizeof(str), static_cast<std::uint8_t>((__LINE__ ^ __COUNTER__ ^ __TIME__[7]) & 0xFFu)>{str}.resolve()
#endif

#ifndef BURNERNET_ERROR_XOR
#define BURNERNET_ERROR_XOR 0
#endif

#ifndef BURNERNET_HARDEN_IMPORTS
#define BURNERNET_HARDEN_IMPORTS 0
#endif

namespace burner::net::detail {

struct DefaultSecurity {
    static inline bool OnVerifyEnvironment() {
        return true;
    }

    static inline void OnPreRequest(HttpRequest&) {}

    static inline bool OnVerifyTransport(const char* url, const char* remote_ip) {
        (void)(url);
        (void)(remote_ip);
        return true;
    }

    static inline void OnSignatureVerified(bool success, ErrorCode reason) {
        (void)(success);
        (void)(reason);
    }

    static inline void OnTamper() {
        std::abort();
    }

    static inline void OnError(ErrorCode code, const char* url) {
        (void)(code);
        (void)(url);
    }

    static inline std::string GetUserAgent() {
        return "";
    }
};

template <typename TSecurity>
constexpr bool HasVerifyEnvironmentHook = requires {
    TSecurity::OnVerifyEnvironment();
};

template <typename TSecurity>
inline bool CallVerifyEnvironment() {
    if constexpr (HasVerifyEnvironmentHook<TSecurity>) {
        return TSecurity::OnVerifyEnvironment();
    } else {
        return true;
    }
}

template <typename TSecurity>
constexpr bool HasVerifyTransportHook = requires(const char* url, const char* remote_ip) {
    TSecurity::OnVerifyTransport(url, remote_ip);
};

template <typename TSecurity>
inline bool CallVerifyTransport(const char* url, const char* remote_ip) {
    if constexpr (HasVerifyTransportHook<TSecurity>) {
        return TSecurity::OnVerifyTransport(url, remote_ip);
    } else {
        return true;
    }
}

} // namespace burner::net::detail

#ifndef BURNERNET_SECURITY_POLICY
namespace burner::net {
using Security = detail::DefaultSecurity;
}
#else
namespace burner::net {
using Security = BURNERNET_SECURITY_POLICY;
}
#endif
