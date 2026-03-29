#pragma once

// Copy this file into your own project, rename it, and point BurnerNet at it
// with BURNERNET_USER_CONFIG_HEADER="MyConfig.h".
//
// BurnerNet already provides a built-in compile-time literal obfuscation fallback.
// Only define BURNER_OBF_LITERAL here if you want to override that default.

#include <string>

namespace burner_net_example {

inline std::string MyXor(const char* text) {
    return std::string(text);
}

struct MySecurity {
    static void FlagUser() {}
    static void OnError(unsigned int, const char*) {}
};

struct MyProjectSecurity {
    static inline void OnSignatureVerified(bool success, burner::net::ErrorCode reason) {
        (void)(success);
        (void)(reason);
    }

    static inline void OnTamper() {
        MySecurity::FlagUser();
    }

    static inline void OnError(burner::net::ErrorCode code, const char* url) {
        ::burner_net_example::MySecurity::OnError(static_cast<unsigned int>(code), url);
    }

    static inline std::string GetUserAgent() {
        return "";
    }
};

} // namespace burner_net_example

// Optional string hook. Remove this macro to use BurnerNet's built-in BURNER_OBF_LITERAL fallback.
#define BURNER_OBF_LITERAL(x) ::burner_net_example::MyXor(x)

// Optional static security policy. Remove this macro to use BurnerNet's built-in defaults.
#define BURNERNET_SECURITY_POLICY ::burner_net_example::MyProjectSecurity

// Example hardened error mask for polymorphic numeric output.
#define BURNERNET_ERROR_XOR 0x12345678u

// Optional: dynamically resolve sensitive Windows APIs in production builds.
#define BURNERNET_HARDEN_IMPORTS 0
