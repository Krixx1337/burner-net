#pragma once

#include <cstdint>
#include <string>
#include <vector>

#define BURNERNET_ERROR_XOR 0x000000A5u
#define BURNERNET_SECURITY_SEED 0x13572468u

#ifndef BURNERNET_HARDEN_IMPORTS
#define BURNERNET_HARDEN_IMPORTS 0
#endif

#ifndef BURNER_OBF_LITERAL
#define BURNER_OBF_LITERAL(str) std::string(str)
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
