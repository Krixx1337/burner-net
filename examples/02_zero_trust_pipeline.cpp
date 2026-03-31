#include <iostream>
#include <string>
#include <string_view>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/policy.h"
#include "burner/net/security_auditor.h"

namespace {

struct ZeroTrustPolicy : burner::net::ISecurityPolicy {
    bool OnVerifyTransport(const char* url, const char* remote_ip) const {
        if (url == nullptr || remote_ip == nullptr) {
            return false;
        }

        const std::string_view host(url);
        const std::string_view ip(remote_ip);
        if (host.find("license") != std::string_view::npos &&
            (ip == "127.0.0.1" || ip == "::1")) {
            return false;
        }

        return true;
    }

    std::string GetUserAgent() const {
        return "BurnerNetExamples/ZeroTrust";
    }
};

} // namespace

int RunZeroTrustPipeline() {
    using namespace burner::net;

    constexpr const char* kPinnedKey = "sha256//replace-with-a-real-pin";
    constexpr const char* kEndpoint = "https://example.com/license";

    auto paranoid = ClientBuilder()
        .WithSecurityPolicy(ZeroTrustPolicy{})
        .WithUseNativeCa(true)
        .WithApiVerification(true)
        .WithPinnedKey(kPinnedKey)
        .Build();

    if (!paranoid.Ok()) {
        std::cerr << "Failed to build paranoid client: "
                  << ErrorCodeToString(paranoid.error) << '\n';
        return 1;
    }

    auto utility = ClientBuilder()
        .WithCasualDefaults()
        .Build();

    if (!utility.Ok()) {
        std::cerr << "Failed to build utility lane: "
                  << ErrorCodeToString(utility.error) << '\n';
        return 2;
    }

    std::cout << "Paranoid lane: auth, licensing, and high-trust business logic.\n";
    std::cout << "Utility lane: telemetry, metadata, and lower-trust traffic.\n";
    std::cout << "The paranoid client uses a concrete policy object plus pinning,\n";
    std::cout << "and transport integrity auditing. Add an app-layer verifier when needed.\n";

    if (!SecurityAuditor::CheckTransportIntegrity(paranoid.client->Raw())) {
        std::cerr << "Transport integrity check failed before the hardened request.\n";
        return 3;
    }

    std::cout << "Transport integrity check passed.\n";
    if (std::string_view(kPinnedKey).find("replace-with-a-real-pin") != std::string_view::npos ||
        std::string_view(kEndpoint).find("example.com") != std::string_view::npos) {
        std::cout << "Hardened request skipped.\n";
        std::cout << "Replace the sample pin and endpoint with your own hardened service\n";
        std::cout << "to exercise the pinned-key and transport-audited path.\n";
        return 0;
    }

    std::cout << "Transport integrity check passed. Sending hardened request...\n";
    const auto response = paranoid.client->Get(kEndpoint).Send();

    if (!response.TransportOk()) {
        std::cerr << "Transport failed: "
                  << ErrorCodeToString(response.transport_error) << '\n';
        return 4;
    }

    std::cout << "Hardened request succeeded.\n";
    return 0;
}
