#include <iostream>
#include "burner/net/builder.h"
#include "burner/net/error.h"

namespace {

bool ExampleConnectedPeerGuard(const burner::net::ConnectedPeer& peer) {
    // Example consumer policy layered after BurnerNet's built-in loopback
    // rejection. Replace with the port/address rules owned by your service.
    return peer.remote_port == 443;
}

} // namespace

int RunConnectedPeerGuard() {
    auto build_result = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithLoopbackPeerRejection()
        .WithConnectedPeerGuard(&ExampleConnectedPeerGuard)
        .WithUserAgent("BurnerNetExamplePeerGuard/1.0")
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "failed to build client: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "Connected-peer guard example initialized.\n";
    std::cout << "BurnerNet rejects loopback before the custom HTTPS-port guard.\n";
    std::cout << "Rejection fails the request with TransportVerificationFailed.\n";
    return 0;
}
