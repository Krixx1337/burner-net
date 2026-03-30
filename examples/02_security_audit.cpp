#include <cstdlib>
#include <iostream>
#include <memory>

#include "burner/net/builder.h"
#include "burner/net/security_auditor.h"
#include "burner/net/signature_verifier.h"

int main() {
    auto build_result = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithResponseVerifier(std::make_shared<burner::net::HmacSha256HeaderVerifier>(
            burner::net::SignatureVerifierConfig{
                .signature_header = "X-Auth-Verify",
                .secret = "replace-with-a-real-secret",
                .secret_provider = {}
            }))
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "failed to initialize BurnerNet client\n";
        return 1;
    }

    if (!burner::net::SecurityAuditor::CheckTransportIntegrity(build_result.client->Raw())) {
        std::cerr << "transport integrity check failed; TLS interception or inconclusive environment detected\n";
        return 2;
    }

    std::cout << "transport integrity check passed\n";
    return 0;
}
