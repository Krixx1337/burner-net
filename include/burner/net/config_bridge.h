#pragma once

#include "burner/net/export.h"
#include "burner/net/detail/constexpr_obfuscation.h"

#include <cstdint>
#include <cstdlib>
#include <string>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct HttpRequest;

} // namespace burner::net

// Optional advanced hook for source-drop integrations that want a custom policy type.
// Zero-config builds do not need this.
#ifdef BURNERNET_SECURITY_POLICY_HEADER
#include BURNERNET_SECURITY_POLICY_HEADER
#endif

#ifndef BURNERNET_ERROR_XOR
#define BURNERNET_ERROR_XOR (::burner::net::detail::ErrorXorKey())
#endif

#ifndef BURNERNET_HARDEN_IMPORTS
#define BURNERNET_HARDEN_IMPORTS 0
#endif

#ifndef BURNERNET_HARDEN_ERRORS
#if defined(BURNER_HARDEN_ERRORS)
#define BURNERNET_HARDEN_ERRORS BURNER_HARDEN_ERRORS
#elif defined(NDEBUG) && !defined(_DEBUG)
#define BURNERNET_HARDEN_ERRORS 1
#else
#define BURNERNET_HARDEN_ERRORS 0
#endif
#endif

namespace burner::net::detail {

BURNER_API std::uint32_t ErrorXorKey() noexcept;

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
