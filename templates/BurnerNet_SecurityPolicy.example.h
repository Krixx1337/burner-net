#pragma once

#include <string>
#include <string_view>

namespace burner_net_example {

struct MyProjectSecurity {
    static inline bool OnVerifyEnvironment() {
        return true;
    }

    static inline void OnPreRequest(burner::net::HttpRequest&) {}

    static inline bool OnVerifyTransport(const char* url, const char* remote_ip) {
        (void)url;
        return remote_ip != nullptr && std::string_view(remote_ip) != "127.0.0.1";
    }

    static inline void OnSignatureVerified(bool success, burner::net::ErrorCode reason) {
        (void)success;
        (void)reason;
    }

    static inline void OnTamper() {}

    static inline void OnError(burner::net::ErrorCode code, const char* url) {
        (void)code;
        (void)url;
    }

    static inline std::string GetUserAgent() {
        return "";
    }
};

} // namespace burner_net_example

#define BURNERNET_SECURITY_POLICY ::burner_net_example::MyProjectSecurity

// Build note:
// BurnerNet must be compiled with this header visible.
// CMake: set BURNERNET_SECURITY_POLICY_HEADER="BurnerNet_SecurityPolicy.example.h"
// on the BurnerNet target itself and add the templates/ directory to that
// target's include directories.
// Visual Studio: add the templates/ directory to Additional Include
// Directories for the BurnerNet project and add
// BURNERNET_SECURITY_POLICY_HEADER="BurnerNet_SecurityPolicy.example.h"
// to that project's Preprocessor Definitions.
// Do not include burner/net/http.h or burner/net/error.h from this file.
// BurnerNet injects this header before those types are fully defined.
