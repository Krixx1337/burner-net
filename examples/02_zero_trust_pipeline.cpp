#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "burner/net/builder.h"
#include "burner/net/error.h"

namespace {

burner::net::VerificationResult VerifyExampleResponse(
    const burner::net::HttpRequest&,
    const burner::net::HttpResponseView&) {
    // Replace with an application-owned signature check.
    return {};
}

burner::net::ClientBuilder MakeHardenedBuilder() {
    return burner::net::ClientBuilder(burner::net::ClientProfile::Hardened)
        .WithLoopbackPeerRejection()
        .WithDnsFallback(
            burner::net::DnsMode::Doh,
            "https://cloudflare-dns.com/dns-query",
            "Cloudflare")
        .WithResponseVerifier(&VerifyExampleResponse)
        .WithUserAgent("BurnerNetExamples/ZeroTrust");
}

enum class CanaryResult {
    RejectedAsExpected,
    UnexpectedAcceptance,
    Inconclusive
};

template <typename TClient>
CanaryResult CheckTransportCanaries(
    TClient& client,
    const std::vector<std::string>& canary_urls) {
    if (canary_urls.empty()) {
        return CanaryResult::Inconclusive;
    }

    for (const auto& url : canary_urls) {
        const auto response = client.Get(url)
            .WithTimeoutSeconds(10)
            .WithConnectTimeoutSeconds(5)
            .FollowRedirects(false)
            .Send();

        if (response.transport_error == burner::net::ErrorCode::TlsVerificationFailed) {
            continue;
        }
        return response.TransportOk()
            ? CanaryResult::UnexpectedAcceptance
            : CanaryResult::Inconclusive;
    }

    return CanaryResult::RejectedAsExpected;
}

} // namespace

int RunZeroTrustPipeline() {
    using namespace burner::net;

    constexpr const char* kEndpoint = "https://example.com/license";
    const std::vector<std::string> kTransportCanaries = {
        "https://replace-with-your-expired-canary.example",
        "https://replace-with-your-hostname-canary.example"
    };

    auto paranoid = MakeHardenedBuilder().Build();

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
    std::cout << "Paranoid lane uses TLS identity, loopback rejection, and app verifier.\n";

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
        const auto audit = CheckTransportCanaries(*paranoid.client, kTransportCanaries);
        if (audit == CanaryResult::UnexpectedAcceptance) {
            std::cerr << "Transport trust audit detected an unexpected canary success.\n";
            return 3;
        }
        if (audit == CanaryResult::Inconclusive) {
            std::cerr << "Transport trust audit was inconclusive.\n";
            return 3;
        }
    }

    if (canaries_configured) {
        std::cout << "Transport trust audit passed.\n";
    }
    if (std::string_view(kEndpoint).find("example.com") != std::string_view::npos) {
        std::cout << "Hardened request skipped.\n";
        std::cout << "Replace the sample endpoint and canary URLs with your own hardened service\n";
        std::cout << "to exercise the transport-trust-audited path.\n";
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
