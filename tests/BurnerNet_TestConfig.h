#pragma once

#include <cstdint>
#include <string>
#include <vector>

#ifndef BURNERNET_HARDEN_IMPORTS
#define BURNERNET_HARDEN_IMPORTS 0
#endif

namespace burnernet_test_config {

struct TestSecurityPolicy {
    static inline void OnPreRequest(burner::net::HttpRequest&) {}

    static inline void OnSignatureVerified(bool success, burner::net::ErrorCode reason) {
        (void)(success);
        (void)(reason);
    }

    static inline void OnTamper() {}

    static inline void OnError(burner::net::ErrorCode code, const char* url) {
        (void)(code);
        (void)(url);
    }

    static inline std::string GetUserAgent() {
        return "";
    }
};

inline const std::vector<std::wstring> GetTrustedDependencies() {
    return {
        L"zlib1.dll",
        L"libcurl.dll"
    };
}

} // namespace burnernet_test_config

#define BURNERNET_SECURITY_POLICY ::burnernet_test_config::TestSecurityPolicy
