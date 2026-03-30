#include <iostream>
#include <string>
#include <string_view>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/policy.h"
#include "burner/net/security_auditor.h"
#include "burner/net/signature_verifier.h"

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
    constexpr const char* kSharedSecret = "replace-with-a-real-secret";
    constexpr const char* kEndpoint = "https://example.com/license";

    auto paranoid = ClientBuilder()
        .WithSecurityPolicy(ZeroTrustPolicy{})
        .WithUseNativeCa(true)
        .WithApiVerification(true)
        .WithPinnedKey(kPinnedKey)
        .WithResponseVerifier(HmacSha256HeaderVerifier(
            SignatureVerifierConfig{
                .signature_header = "X-Auth-Verify",
                .secret = kSharedSecret,
                .secret_provider = {}
            }))
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
    std::cout << "response verification, and transport integrity auditing.\n";

    if (!SecurityAuditor::CheckTransportIntegrity(paranoid.client->Raw())) {
        std::cerr << "Transport integrity check failed before the hardened request.\n";
        return 3;
    }

    std::cout << "Transport integrity check passed.\n";
    if (std::string_view(kPinnedKey).find("replace-with-a-real-pin") != std::string_view::npos ||
        std::string_view(kSharedSecret).find("replace-with-a-real-secret") != std::string_view::npos ||
        std::string_view(kEndpoint).find("example.com") != std::string_view::npos) {
        std::cout << "Hardened request skipped.\n";
        std::cout << "Replace the sample pin, HMAC secret, and endpoint with your own hardened service\n";
        std::cout << "to exercise the full pinned-key and signed-response path.\n";
        return 0;
    }

    std::cout << "Transport integrity check passed. Sending hardened request...\n";
    const auto response = paranoid.client->Get(kEndpoint).Send();

    if (!response.TransportOk()) {
        std::cerr << "Transport failed: "
                  << ErrorCodeToString(response.transport_error) << '\n';
        return 4;
    }

    if (!response.verified) {
        std::cerr << "Response signature verification failed: "
                  << ErrorCodeToString(response.verification_error) << '\n';
        std::cerr << "Check the configured pin, shared secret, and signed response header.\n";
        return 5;
    }

    std::cout << "Hardened request succeeded with verified response semantics.\n";
    return 0;
}
