#include <iostream>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/version.h"

int main() {
    std::cout << "BurnerNet VS Source-Drop Example (v" << burner::net::VersionString << ")\n";

#if BURNERNET_MAXIMUM_GHOST
    burner::net::BootstrapConfig bootstrap{};
    const auto initialized = burner::net::InitializeNetworkingRuntime(bootstrap);
    if (!initialized.success) {
        std::cerr << "Maximum Ghost initialization failed: "
                  << burner::net::ErrorCodeToString(initialized.code) << "\n";
        return 1;
    }
#endif

    auto build_result = burner::net::ClientBuilder().Build();
    if (!build_result.Ok()) {
        std::cerr << "Build failed: " << burner::net::ErrorCodeToString(build_result.error) << "\n";
        return 1;
    }

    std::cout << "Sending request to https://example.com...\n";
    const auto response = build_result.client->Get("https://example.com").Send();

    if (response.Ok()) {
        std::cout << "Success! Status: " << response.status_code << "\n";
    } else {
        std::cerr << "Request failed. Transport Error: "
                  << burner::net::ErrorCodeToString(response.transport_error) << "\n";
    }

    return 0;
}
