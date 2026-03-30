#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/policy.h"

namespace {

class ExampleSecurityPolicy final : public burner::net::ISecurityPolicy {
public:
    bool OnVerifyTransport(const char* url, const char* remote_ip) const override {
        if (remote_ip == nullptr) {
            return false;
        }

        const std::string_view ip(remote_ip);

        // Fail closed on obvious local redirection such as a poisoned hosts file.
        if (ip == "127.0.0.1" || ip == "::1") {
            return false;
        }

        // Example of a host-specific rule: never let the API tier resolve back
        // into RFC1918 space unless your deployment explicitly expects that.
        if (url != nullptr && std::string_view(url).find("api.myapp.com") != std::string_view::npos) {
            if (ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.")) {
                return false;
            }
        }

        return true;
    }

    std::string GetUserAgent() const override {
        return "BurnerNetExampleCustomPolicy/1.0";
    }
};

} // namespace

int RunCustomPolicy() {
    auto build_result = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithSecurityPolicy(std::make_shared<ExampleSecurityPolicy>())
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "failed to build client: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "Runtime security policy example initialized.\n";
    std::cout << "ExampleSecurityPolicy blocks loopback redirects and can reject\n";
    std::cout << "unexpected private-network IPs for sensitive hosts.\n";
    std::cout << "If OnVerifyTransport rejects the connected IP, BurnerNet fails\n";
    std::cout << "the request with TransportVerificationFailed.\n";
    return 0;
}
