#include <iostream>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/version.h"

int main() {
    std::cout << "BurnerNet version: " << burner::net::VersionString << '\n';

    burner::net::ErrorCode build_error = burner::net::ErrorCode::None;
    auto client = burner::net::ClientBuilder().Build(&build_error);

    if (client == nullptr) {
        std::cerr << "Failed to build client. Error: "
                  << burner::net::ErrorCodeToString(build_error) << '\n';
        return 1;
    }

    std::cout << "Sending secure DoH request to example.com...\n";
    const auto response = client->Get("https://example.com").Send();
    std::cout << "Response code: " << response.status_code << '\n';
    if (response.TransportOk()) {
        std::cout << "Transport succeeded securely.\n";
        return 0;
    }

    std::cout << "Transport failed: "
              << burner::net::ErrorCodeToString(response.transport_error) << '\n';
    return 1;
}
