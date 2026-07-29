#include <iostream>
#include <string>
#include <string_view>

#include "burner/net/builder.h"
#include "burner/net/error.h"

namespace {

bool ExampleConnectedPeerGuard(const burner::net::ConnectedPeer& peer) {
        const std::string_view ip = peer.remote_ip;

        // Fail closed on obvious local redirection such as a poisoned hosts file.
        if (ip == "127.0.0.1" || ip == "::1") {
            return false;
        }

        // Example of a host-specific rule: never let the API tier resolve back
        // into RFC1918 space unless your deployment explicitly expects that.
        if (ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.")) {
            return false;
        }

        return true;
}

} // namespace

int RunConnectedPeerGuard() {
    auto build_result = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithConnectedPeerGuard(&ExampleConnectedPeerGuard)
        .WithUserAgent("BurnerNetExamplePeerGuard/1.0")
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "failed to build client: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "Connected-peer guard example initialized.\n";
    std::cout << "It blocks loopback and unexpected private-network\n";
    std::cout << "IPs for sensitive hosts.\n";
    std::cout << "If guard rejects connected IP, BurnerNet fails request with\n";
    std::cout << "request with TransportVerificationFailed.\n";
    return 0;
}
