#include <iostream>

#include "burner/net.h"

int RunBasicUsage() {
    std::cout << "BurnerNet version: " << burner::net::VersionString << '\n';

    burner::net::Client client;

    if (!client.IsReady()) {
        std::cerr << "Failed to initialize client. Error: "
                  << burner::net::ErrorCodeToString(client.InitError()) << '\n';
        return 1;
    }

    std::cout << "Sending a basic Standard request...\n";
    const auto response = client
        .Get("https://example.com")
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
