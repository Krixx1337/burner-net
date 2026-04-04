#include <iostream>
#include <string>
#include <string_view>
#include <vector>

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
    const std::vector<std::string> kTransportCanaries = {
        "https://replace-with-your-expired-canary.example",
        "https://replace-with-your-hostname-canary.example"
    };

    auto paranoid = ClientBuilder()
        .WithSecurityPolicy(ZeroTrustPolicy{})
        .WithUseNativeCa(true)
        .WithPinnedKey(kPinnedKey)
        .WithStackIsolation(true) // <-- Enable the Stack Severing
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
    std::cout << "and transport trust auditing. Add an app-layer verifier when needed.\n";

    bool canaries_configured = true;
    for (const auto& url : kTransportCanaries) {
        if (url.find("replace-with-your-") != std::string::npos) {
            canaries_configured = false;
            break;
        }
    }

    if (!canaries_configured) {
        std::cout << "Transport trust audit skipped.\n";
        std::cout << "Replace the sample canary URLs with your own TLS-failure endpoints to exercise the audit path.\n";
    } else {
        const auto audit = SecurityAuditor::AuditTransportTrust(paranoid.client->Raw(), kTransportCanaries);
        if (audit == AuditResult::Compromised) {
            paranoid.client->Raw()->SecurityPolicy()->OnTamper();
            std::cerr << "Transport trust audit detected an unexpected canary success.\n";
            return 3;
        }
        if (audit == AuditResult::Inconclusive) {
            paranoid.client->Raw()->SecurityPolicy()->OnTamper();
            std::cerr << "Transport trust audit was inconclusive.\n";
            return 3;
        }
    }

    if (canaries_configured) {
        std::cout << "Transport trust audit passed.\n";
    }
    if (std::string_view(kPinnedKey).find("replace-with-a-real-pin") != std::string_view::npos ||
        std::string_view(kEndpoint).find("example.com") != std::string_view::npos) {
        std::cout << "Hardened request skipped.\n";
        std::cout << "Replace the sample pin, endpoint, and canary URLs with your own hardened service\n";
        std::cout << "to exercise the pinned-key and transport-trust-audited path.\n";
        return 0;
    }

    std::cout << "Sending hardened request...\n";
    const auto response = paranoid.client->Get(kEndpoint).Send();

    if (!response.TransportOk()) {
        std::cerr << "Transport failed: "
                  << ErrorCodeToString(response.transport_error) << '\n';
        return 4;
    }

    std::cout << "Hardened request succeeded.\n";
    return 0;
}
