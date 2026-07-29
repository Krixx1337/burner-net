#include <doctest/doctest.h>

#include <chrono>
#include <string>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"

TEST_CASE("Zero-Trust Research: badssl.com rejection patterns") {
    using namespace burner::net;

    auto client = ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(static_cast<bool>(client.client));

    auto check_tls_rejection = [&](const char* url) {
        const auto resp = client.client->Get(url).Send();
        MESSAGE("Testing: " << std::string(url) << " | ErrorCode: "
                            << std::string(ErrorCodeDebugString(resp.transport_error)));
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
                << std::string(ErrorCodeDebugString(resp.transport_error)));
        CHECK_FALSE(resp.TransportOk());
        CHECK(resp.transport_code != 0);
    }

    SUBCASE("Weak Cipher Rejections") {
        const auto resp = client.client->Get("https://rc4.badssl.com").Send();
        MESSAGE("Testing: RC4 | ErrorCode: "
                << std::string(ErrorCodeDebugString(resp.transport_error)));
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

TEST_CASE("max_body_bytes aborts oversized responses mid-stream") {
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(static_cast<bool>(client.client));

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

TEST_CASE("global max body limit caps requests even without a per-request limit") {
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithGlobalMaxBodyLimit(10)
        .Build();

    REQUIRE(static_cast<bool>(client.client));

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.timeout_seconds = 15;
    request.connect_timeout_seconds = 10;
    request.dns_fallback.enabled = false;

    const auto response = client.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::BodyTooLarge);
    CHECK(response.body.empty());
    CHECK(response.streamed_body_bytes > 10);
}

TEST_CASE("timeouts fail closed for slow or unroutable endpoints") {
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(static_cast<bool>(client.client));

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

TEST_CASE("isolated transport preserves response data integrity") {
    using namespace burner::net;

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithStackIsolation(true)
        .Build();

    REQUIRE(build_result.Ok());

    // Execute against a real endpoint to verify the HttpResponse moves
    // cleanly across the thread boundary back to the caller.
    const auto response = build_result.client->Get("https://example.com").Send();

    CHECK(response.TransportOk());
    CHECK(response.status_code == 200);
    CHECK_FALSE(response.body.empty());
    CHECK(response.body.find("Example Domain") != std::string::npos);
}

TEST_CASE("successful https requests expose timing and tls telemetry") {
    using namespace burner::net;

    auto client = ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    REQUIRE(static_cast<bool>(client.client));

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.timeout_seconds = 15;
    request.connect_timeout_seconds = 10;
    request.dns_fallback.enabled = false;

    const auto response = client.client->Send(request);

    CHECK(response.TransportOk());
    CHECK(response.status_code == 200);
    CHECK(response.telemetry.total_time_seconds >= 0.0);
    CHECK_FALSE(response.telemetry.tls_chain.empty());
}

TEST_CASE("failed response verification wipes staged data") {
    using namespace burner::net;

    bool verifier_saw_body = false;

    auto client = ClientBuilder()
        .WithUseNativeCa(true)
        .WithResponseVerifier([&](
            const HttpRequest&,
            const HttpResponseView& response) {
            verifier_saw_body = !response.body.empty();
            return VerificationResult{ErrorCode::SigMismatch};
        })
        .Build();

    REQUIRE(client.Ok());
    const auto response = client.client->Get("https://example.com").Send();

    CHECK(response.TransportOk());
    CHECK(response.verification_status == VerificationStatus::Failed);
    CHECK(response.verification_error == ErrorCode::SigMismatch);
    CHECK(verifier_saw_body);
    CHECK(response.body.empty());
    CHECK(response.headers.empty());
    CHECK(response.telemetry.tls_chain.empty());
    CHECK(response.telemetry.total_time_seconds == 0.0);
}

TEST_CASE("response verifier exception becomes a wiping terminal failure") {
    using namespace burner::net;

    auto client = ClientBuilder()
        .WithUseNativeCa(true)
        .WithResponseVerifier(
            [](const HttpRequest&, const HttpResponseView&) -> VerificationResult {
                throw 7;
            })
        .Build();

    REQUIRE(client.Ok());
    const auto response = client.client->Get("https://example.com").Send();

    CHECK(response.TransportOk());
    CHECK(response.verification_status == VerificationStatus::Failed);
    CHECK(response.verification_error == ErrorCode::CallbackFailed);
    CHECK(response.body.empty());
    CHECK(response.headers.empty());
    CHECK(response.telemetry.tls_chain.empty());
}

TEST_CASE("chunk callback exception aborts transfer without publication") {
    using namespace burner::net;

    auto client = ClientBuilder().WithUseNativeCa(true).Build();
    REQUIRE(client.Ok());

    const auto response = client.client
        ->Get("https://example.com")
        .OnChunkReceived([](const std::uint8_t*, std::size_t) { throw 7; })
        .Send();

    CHECK(response.transport_error == ErrorCode::CallbackFailed);
    CHECK(response.body.empty());
    CHECK(response.headers.empty());
}
