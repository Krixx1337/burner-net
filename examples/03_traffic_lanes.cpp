#include <iostream>
#include <memory>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/signature_verifier.h"

int main() {
    using namespace burner::net;

    auto paranoid = ClientBuilder()
        .WithUseNativeCa(true)
        .WithApiVerification(true)
        .WithPinnedKey("sha256//replace-with-a-real-pin")
        .WithResponseVerifier(std::make_shared<HmacSha256HeaderVerifier>(
            SignatureVerifierConfig{
                .signature_header = "X-Auth-Verify",
                .secret = "replace-with-a-real-secret",
                .secret_provider = {}
            }))
        .Build();

    if (paranoid.client == nullptr) {
        std::cerr << "failed to build paranoid client: "
                  << ErrorCodeToString(paranoid.error) << '\n';
        return 1;
    }

    auto utility = ClientBuilder()
        .WithCasualDefaults()
        .Build();

    if (utility.client == nullptr) {
        std::cerr << "failed to build utility client\n";
        return 2;
    }

    std::cout << "Paranoid lane: use for auth, licenses, and logic-seed traffic.\n";
    std::cout << "Utility lane: use for logs, metadata, and other lower-trust requests.\n";
    std::cout << "Keep the clients separate so high-trust and utility traffic never share one transport handle.\n";
    return 0;
}
