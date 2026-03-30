#include <doctest/doctest.h>

#include <chrono>
#include <string>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/security_auditor.h"

TEST_CASE("Zero-Trust Research: badssl.com rejection patterns") {
    using namespace burner::net;

    auto client = ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(client.client != nullptr);

    auto check_tls_rejection = [&](const char* url) {
        const auto resp = client.client->Get(url).Send();
        MESSAGE("Testing: " << std::string(url) << " | ErrorCode: "
                            << std::string(ErrorCodeToString(resp.transport_error)));
        CHECK_FALSE(resp.TransportOk());
        CHECK_FALSE(resp.Ok());
        CHECK(resp.transport_error == ErrorCode::TlsVerificationFailed);
    };

    SUBCASE("Certificate Validation Rejections") {
        check_tls_rejection("https://expired.badssl.com");
        check_tls_rejection("https://wrong.host.badssl.com");
        check_tls_rejection("https://self-signed.badssl.com");
        check_tls_rejection("https://untrusted-root.badssl.com");
    }

    SUBCASE("Protocol Downgrade Rejections (Enforcing TLS 1.2+)") {
        const auto resp = client.client->Get("https://tls-v1-0.badssl.com:1010").Send();
        MESSAGE("Testing: TLS 1.0 | ErrorCode: "
                << std::string(ErrorCodeToString(resp.transport_error)));
        CHECK_FALSE(resp.TransportOk());
        CHECK(resp.transport_code != 0);
    }

    SUBCASE("Weak Cipher Rejections") {
        const auto resp = client.client->Get("https://rc4.badssl.com").Send();
        MESSAGE("Testing: RC4 | ErrorCode: "
                << std::string(ErrorCodeToString(resp.transport_error)));
        CHECK_FALSE(resp.TransportOk());
        CHECK(resp.transport_code != 0);
    }

    SUBCASE("Valid Certificate Acceptance") {
        const auto resp = client.client->Get("https://sha256.badssl.com").Send();
        MESSAGE("Testing: Valid SHA256 Cert | Status: " << resp.status_code);
        CHECK(resp.TransportOk());
        CHECK(resp.Ok());
        CHECK(resp.status_code == 200);
    }
}

TEST_CASE("security auditor rejects compromised or inconclusive transport") {
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(client.client != nullptr);
    CHECK(burner::net::SecurityAuditor::CheckTransportIntegrity(client.client->Raw()));
}

TEST_CASE("max_body_bytes aborts oversized responses mid-stream") {
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(client.client != nullptr);

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.max_body_bytes = 10;
    request.timeout_seconds = 15;
    request.connect_timeout_seconds = 10;
    request.dns_fallback.enabled = false;

    const auto response = client.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::BodyTooLarge);
    CHECK(response.body.empty());
    CHECK(response.streamed_body_bytes > request.max_body_bytes);
}

TEST_CASE("timeouts fail closed for slow or unroutable endpoints") {
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(client.client != nullptr);

    SUBCASE("connect timeout against unroutable address") {
        burner::net::HttpRequest request{};
        request.method = burner::net::HttpMethod::Get;
        request.url = "https://10.255.255.1";
        request.timeout_seconds = 3;
        request.connect_timeout_seconds = 1;
        request.dns_fallback.enabled = false;

        const auto started = std::chrono::steady_clock::now();
        const auto response = client.client->Send(request);
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started);

        CHECK_FALSE(response.TransportOk());
        CHECK(response.transport_code != 0);
        CHECK(elapsed.count() < 5);
    }

    SUBCASE("overall timeout against slow endpoint") {
        burner::net::HttpRequest request{};
        request.method = burner::net::HttpMethod::Get;
        request.url = "https://httpstat.us/200?sleep=5000";
        request.timeout_seconds = 1;
        request.connect_timeout_seconds = 3;
        request.dns_fallback.enabled = false;

        const auto started = std::chrono::steady_clock::now();
        const auto response = client.client->Send(request);
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started);

        CHECK_FALSE(response.TransportOk());
        CHECK(response.transport_code != 0);
        CHECK(elapsed.count() < 5);
    }
}
