#pragma once

#include <string>

namespace burner_net_example {

struct MyProjectSecurity {
    static inline bool OnVerifyEnvironment() {
        return true;
    }

    static inline void OnPreRequest(burner::net::HttpRequest&) {}

    static inline bool OnVerifyTransport(const char* url, const char* remote_ip) {
        (void)url;
        (void)remote_ip;
        return true;
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
