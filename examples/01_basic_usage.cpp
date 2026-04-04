#include <iostream>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/policy.h"
#include "burner/net/version.h"

namespace {

struct ExamplePolicy : burner::net::ISecurityPolicy {
    std::string GetUserAgent() const {
        return "BurnerNetExamples/Basic";
    }
};

} // namespace

int RunBasicUsage() {
    std::cout << "BurnerNet version: " << burner::net::VersionString << '\n';

    auto build_result = burner::net::ClientBuilder()
        .WithSecurityPolicy(ExamplePolicy{})
        .WithUseNativeCa(true)
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "Failed to build client. Error: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "Sending a basic hardened request with the fluent builder...\n";
    std::cout << "Tip: add WithDnsFallback(DnsMode::Doh, <your resolver>, <name>)\n";
    std::cout << "once you have a real DoH endpoint. The out-of-box sample avoids\n";
    std::cout << "placeholder resolvers so it stays runnable by default.\n";
    const auto response = build_result.client
        ->Get("https://example.com")
        .WithHeader("Accept", "text/html")
        .WithTimeoutSeconds(10)
        .Send();
    std::cout << "Response code: " << response.status_code << '\n';
    if (response.TransportOk()) {
        std::cout << "Transport succeeded securely.\n";
        return 0;
    }

    std::cout << "Transport failed: "
              << burner::net::ErrorCodeToString(response.transport_error) << '\n';
    return 1;
}
