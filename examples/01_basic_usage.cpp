#include <iostream>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/version.h"

int RunBasicUsage() {
    std::cout << "BurnerNet version: " << burner::net::VersionString << '\n';

    auto build_result = burner::net::ClientBuilder().Build();

    if (build_result.client == nullptr) {
        std::cerr << "Failed to build client. Error: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "Sending secure DoH request to example.com...\n";
    const auto response = build_result.client->Get("https://example.com").Send();
    std::cout << "Response code: " << response.status_code << '\n';
    if (response.TransportOk()) {
        std::cout << "Transport succeeded securely.\n";
        return 0;
    }

    std::cout << "Transport failed: "
              << burner::net::ErrorCodeToString(response.transport_error) << '\n';
    return 1;
}
