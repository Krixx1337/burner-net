#include <algorithm>
#include <iostream>
#include <string_view>

#include "burner/net/builder.h"

namespace {

bool ContainsCaseInsensitive(std::string_view haystack, std::string_view needle) {
    return std::search(
               haystack.begin(), haystack.end(),
               needle.begin(), needle.end(),
               [](char lhs, char rhs) {
                   return burner::net::detail::ascii_lower(lhs) == burner::net::detail::ascii_lower(rhs);
               }) != haystack.end();
}

struct TelemetryAuditPolicy final : burner::net::ISecurityPolicy {
    bool OnAuditTelemetry(const burner::net::TransportTelemetry& telemetry) const {
        if (telemetry.total_time_seconds > 2.0) {
            return false;
        }

        for (const auto& line : telemetry.tls_chain) {
            if (ContainsCaseInsensitive(line, "Fiddler") ||
                ContainsCaseInsensitive(line, "Charles") ||
                ContainsCaseInsensitive(line, "mitmproxy")) {
                return false;
            }
        }

        return true;
    }
};

} // namespace

int RunTelemetryAuditExample() {
    using namespace burner::net;

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithSecurityPolicy(TelemetryAuditPolicy{})
        .Build();

    if (!build_result.Ok()) {
        std::cerr << "Failed to build BurnerNet client\n";
        return 1;
    }

    const auto response = build_result.client->Get("https://example.com").Send();

    std::cout << "status=" << response.status_code
              << " transport=" << response.transport_code
              << " total_time=" << response.telemetry.total_time_seconds
              << " tls_lines=" << response.telemetry.tls_chain.size() << '\n';

    return response.Ok() ? 0 : 1;
}
