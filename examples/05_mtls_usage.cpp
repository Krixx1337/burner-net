#include <iostream>
#include <string>
#include <string_view>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"

namespace {

bool ProvideEphemeralMtlsCredentials(burner::net::MtlsCredentials& out) {
    burner::net::SecureString cert_pem =
        "-----BEGIN CERTIFICATE-----\n"
        "replace-with-short-lived-client-cert\n"
        "-----END CERTIFICATE-----\n";
    burner::net::SecureString key_pem =
        "-----BEGIN PRIVATE KEY-----\n"
        "replace-with-short-lived-client-key\n"
        "-----END PRIVATE KEY-----\n";
    burner::net::SecureString key_password = "replace-with-short-lived-passphrase";

    out.enabled = true;
    out.cert_pem = cert_pem;
    out.key_pem = key_pem;
    out.key_password = key_password;
    return true;
}

} // namespace

int RunMtlsUsage() {
    using namespace burner::net;

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithMtlsProvider(&ProvideEphemeralMtlsCredentials)
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "Failed to build mTLS client: "
                  << ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    constexpr std::string_view kEndpoint = "https://mtls.example.com/session";
    std::cout << "mTLS provider installed. Credentials are materialized only when a request starts.\n";
    std::cout << "Endpoint placeholder: " << kEndpoint << '\n';

    if (kEndpoint.find("example.com") != std::string_view::npos) {
        std::cout << "Replace the placeholder endpoint and provider body with your certificate source.\n";
        return 0;
    }

    const auto response = build_result.client->Post(std::string(kEndpoint))
        .WithBody(R"({"grant":"session"})")
        .Send();

    if (!response.TransportOk()) {
        std::cerr << "mTLS request failed: "
                  << ErrorCodeToString(response.transport_error) << '\n';
        return 2;
    }

    std::cout << "mTLS request completed with status " << response.status_code << ".\n";
    return 0;
}
