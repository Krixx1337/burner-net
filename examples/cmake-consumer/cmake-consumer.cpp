// cmake-consumer.cpp : Defines the entry point for the application.
//

#include <iostream>

#include "cmake-consumer.h"
#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/version.h"

int main()
{
    std::cout << "BurnerNet version: " << burner::net::VersionString << '\n';

    auto build_result = burner::net::ClientBuilder().Build();
    if (build_result.client == nullptr) {
        // ErrorCodeDebugString is intentionally non-descriptive in hardened
        // production builds. Pair it with ErrorCodeToString so this example
        // stays diagnosable in both debug and release configurations.
        std::cerr << "Failed to build client. Error: "
                  << burner::net::ErrorCodeDebugString(build_result.error)
                  << " (" << burner::net::ErrorCodeToString(build_result.error) << ")\n";
        return 1;
    }

    std::cout << "Sending request to https://example.com..." << '\n';
    const auto response = build_result.client->Get("https://example.com").Send();

    std::cout << "Response code: " << response.status_code << '\n';
    if (!response.TransportOk()) {
        std::cerr << "Transport failed: "
                  << burner::net::ErrorCodeToString(response.transport_error) << '\n';
        return 1;
    }

    std::cout << "Transport succeeded securely." << '\n';
    return 0;
}
