#include <doctest/doctest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"
#include "burner/net/policy.h"
#include "burner/net/security_auditor.h"
#include "burner/net/signature_verifier.h"
#include "curl/curl_http_client.h"
#include "internal/import_pointer_trust.h"
#include "internal/header_validation.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

class RejectPreFlightPolicy final : public burner::net::ISecurityPolicy {
public:
    bool OnPreRequest(burner::net::HttpRequest&) const override {
        return false;
    }
};

class RejectHeartbeatPolicy final : public burner::net::ISecurityPolicy {
public:
    bool OnHeartbeat() const override {
        return false;
    }
};

class AllowAllPolicy final : public burner::net::ISecurityPolicy {};

class RecordingPolicy final : public burner::net::ISecurityPolicy {
public:
    bool transport_allowed = true;
    mutable int tamper_count = 0;

    bool OnVerifyTransport(const char*, const char*) const override {
        return transport_allowed;
    }

    void OnTamper() const override {
        ++tamper_count;
    }
};

class SecurityAuditorStubClient final : public burner::net::IHttpClient {
public:
    explicit SecurityAuditorStubClient(const burner::net::ISecurityPolicy* policy)
        : m_policy(policy) {}

    burner::net::HttpResponse Send(const burner::net::HttpRequest&) override {
        burner::net::HttpResponse response{};
        response.transport_code = 1;
        response.transport_error =
            m_call_count++ == 0
                ? burner::net::ErrorCode::TlsVerificationFailed
                : burner::net::ErrorCode::CurlGeneric;
        return response;
    }

    const burner::net::ISecurityPolicy* SecurityPolicy() const override {
        return m_policy;
    }

private:
    const burner::net::ISecurityPolicy* m_policy = nullptr;
    int m_call_count = 0;
};

} // namespace

TEST_CASE("header validation rejects CRLF injection") {
    CHECK_FALSE(burner::net::internal::IsValidHeaderName("Content-Type\r\nSet-Cookie: pwned=1"));
    CHECK_FALSE(burner::net::internal::IsValidHeaderValue("Bearer abc\nX-Injected: true"));
}

TEST_CASE("header validation accepts ordinary header tokens") {
    CHECK(burner::net::internal::IsValidHeaderName("X-Custom-Header"));
    CHECK(burner::net::internal::IsValidHeaderName("Authorization"));
    CHECK(burner::net::internal::IsValidHeaderValue("Bearer abc.def"));
}

TEST_CASE("obfuscation helper returns expected plaintext") {
    const std::string value = BURNER_OBF_LITERAL("test");
    CHECK(value == "test");

#if BURNERNET_OBFUSCATE_STRINGS
    std::string wiped = value;
    burner::net::SecureWipe(wiped);
    CHECK(wiped.empty());
#endif
}

TEST_CASE("hmac verifier accepts known valid signature") {
    burner::net::HttpResponse response{};
    response.body = "payload";
    response.headers["x-signature"] =
        "b82fcb791acec57859b989b430a826488ce2e479fdf92326bd0a2e8375a42ba4";

    burner::net::SignatureVerifierConfig config{};
    config.signature_header = "x-signature";
    config.secret = "secret";
    burner::net::HmacSha256HeaderVerifier verifier(config);

    burner::net::ErrorCode reason = burner::net::ErrorCode::None;
    CHECK(verifier.Verify(burner::net::HttpRequest{}, response, &reason));
    CHECK(reason == burner::net::ErrorCode::None);
}

TEST_CASE("hmac verifier rejects mismatched signature") {
    burner::net::HttpResponse response{};
    response.body = "payload";
    response.headers["x-signature"] = "deadbeef";

    burner::net::SignatureVerifierConfig config{};
    config.signature_header = "x-signature";
    config.secret = "secret";
    burner::net::HmacSha256HeaderVerifier verifier(config);

    burner::net::ErrorCode reason = burner::net::ErrorCode::None;
    CHECK_FALSE(verifier.Verify(burner::net::HttpRequest{}, response, &reason));
    CHECK(reason == burner::net::ErrorCode::SigMismatch);
}

TEST_CASE("header map preserves unique keys and treats names as case-insensitive") {
    burner::net::HeaderMap headers;
    headers["Authorization"] = "Bearer one";
    headers.insert_or_assign("Authorization", "Bearer two");
    headers.insert_or_assign("X-Test", "value");
    headers.insert_or_assign("content-type", "application/json");
    headers.insert_or_assign("Content-Type", "text/plain");

    CHECK(headers.size() == 3);

    auto it = headers.begin();
    REQUIRE(it != headers.end());
    CHECK(it->first == "Authorization");
    CHECK(it->second == "Bearer two");
    CHECK(headers["CONTENT-TYPE"] == "text/plain");
}

TEST_CASE("body limit helper rejects chunks that exceed max body bytes") {
    CHECK_FALSE(burner::net::detail::WouldExceedBodyLimit(0, 10, 10));
    CHECK(burner::net::detail::WouldExceedBodyLimit(10, 1, 10));
    CHECK(burner::net::detail::WouldExceedBodyLimit(5, 6, 10));
}

TEST_CASE("SecureWipe clears active string bytes before emptying the buffer") {
    std::string secret = "sensitive-token";
    secret.reserve(64);
    char* raw = secret.data();
    const std::size_t bytes = secret.size();

    REQUIRE(raw != nullptr);
    REQUIRE(bytes > 0);

    burner::net::SecureWipe(secret);

    CHECK(secret.empty());
    for (std::size_t i = 0; i < bytes; ++i) {
        CHECK(raw[i] == '\0');
    }
}

TEST_CASE("SecureWipe clears active vector bytes before emptying the buffer") {
    std::vector<std::uint8_t> secret = {0xde, 0xad, 0xbe, 0xef};
    secret.reserve(32);
    std::uint8_t* raw = secret.data();
    const std::size_t bytes = secret.size();

    REQUIRE(raw != nullptr);
    REQUIRE(bytes > 0);

    burner::net::SecureWipe(secret);

    CHECK(secret.empty());
    for (std::size_t i = 0; i < bytes; ++i) {
        CHECK(raw[i] == 0);
    }
}

TEST_CASE("client aborts immediately when security policy rejects preflight") {
    auto build_result = burner::net::ClientBuilder()
        .WithSecurityPolicy(std::make_shared<RejectPreFlightPolicy>())
        .Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::PreFlightAbort);
    CHECK(response.transport_code != 0);
}

TEST_CASE("builder preflight callback layers on top of an existing custom security policy") {
    bool callback_invoked = false;

    auto build_result = burner::net::ClientBuilder()
        .WithSecurityPolicy(std::make_shared<RejectPreFlightPolicy>())
        .WithPreFlight([&](const burner::net::HttpRequest&) {
            callback_invoked = true;
            return true;
        })
        .Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();

    CHECK(callback_invoked);
    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::PreFlightAbort);
    CHECK(response.transport_code != 0);
}

TEST_CASE("custom security policy layers on top of an existing builder preflight callback") {
    auto build_result = burner::net::ClientBuilder()
        .WithPreFlight([](const burner::net::HttpRequest&) {
            return false;
        })
        .WithSecurityPolicy(std::make_shared<AllowAllPolicy>())
        .Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::PreFlightAbort);
    CHECK(response.transport_code != 0);
}

TEST_CASE("builder environment check fails build closed") {
    auto build_result = burner::net::ClientBuilder()
        .WithEnvironmentCheck([] {
            return false;
        })
        .Build();

    CHECK_FALSE(build_result.Ok());
    CHECK(build_result.error == burner::net::ErrorCode::EnvironmentCompromised);
}

TEST_CASE("builder transport check layers on top of an existing custom security policy") {
    auto build_result = burner::net::ClientBuilder()
        .WithSecurityPolicy(std::make_shared<AllowAllPolicy>())
        .WithTransportCheck([](const char*, const char*) {
            return false;
        })
        .Build();

    REQUIRE(build_result.Ok());

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.dns_fallback.enabled = false;

    const auto response = build_result.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::TransportVerificationFailed);
    CHECK(response.transport_code != 0);
}

TEST_CASE("response-received callback can fail closed with HeartbeatAbort") {
    auto build_result = burner::net::ClientBuilder()
        .WithResponseReceived([](const burner::net::HttpRequest&, const burner::net::HttpResponse&) {
            return false;
        })
        .Build();

    REQUIRE(build_result.Ok());

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.dns_fallback.enabled = false;

    const auto response = build_result.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::HeartbeatAbort);
    CHECK(response.transport_code != 0);
}

TEST_CASE("transport retry budget is honored through the public client API") {
    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.headers["Bad\r\nHeader"] = "boom";
    request.retry.max_attempts = 3;
    request.retry.backoff_ms = 0;
    request.retry.retry_on_transport_error = true;
    request.retry.retry_on_5xx = false;

    int preflight_calls = 0;
    burner::net::ClientBuilder builder;
    builder.WithPreFlight([&](const burner::net::HttpRequest&) {
        ++preflight_calls;
        return true;
    });
    auto build_result = builder.Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::InvalidHeader);
    CHECK(preflight_calls == 3);

    request.retry.retry_on_transport_error = false;
    preflight_calls = 0;

    const auto single_attempt_response = build_result.client->Send(request);

    CHECK_FALSE(single_attempt_response.TransportOk());
    CHECK(single_attempt_response.transport_error == burner::net::ErrorCode::InvalidHeader);
    CHECK(preflight_calls == 1);
}

TEST_CASE("security auditor triggers tamper callback on transport audit failure") {
    RecordingPolicy policy{};
    SecurityAuditorStubClient client(&policy);

    CHECK_FALSE(burner::net::SecurityAuditor::CheckTransportIntegrity(&client));
    CHECK(policy.tamper_count == 1);
}

TEST_CASE("builder tamper action layers on top of wrapped policy tamper handling") {
    auto policy = std::make_shared<RecordingPolicy>();
    bool tamper_action_called = false;

    auto build_result = burner::net::ClientBuilder()
        .WithTamperAction([&] {
            tamper_action_called = true;
        })
        .WithSecurityPolicy(policy)
        .Build();

    REQUIRE(build_result.Ok());
    REQUIRE(build_result.client != nullptr);

    CHECK_FALSE(burner::net::SecurityAuditor::CheckTransportIntegrity(build_result.client->Raw()));
    CHECK(tamper_action_called);
    CHECK(policy->tamper_count == 1);
}

TEST_CASE("import pointer trust accepts allowed system module and rejects wrong one") {
#ifdef _WIN32
    const auto* fn_ptr = reinterpret_cast<const void*>(&GetModuleHandleA);

    CHECK(burner::net::internal::IsFunctionPointerInAllowedModules(
        fn_ptr,
        {L"kernel32.dll"}));
    CHECK_FALSE(burner::net::internal::IsFunctionPointerInAllowedModules(
        fn_ptr,
        {L"malicious.dll"}));
    CHECK(burner::net::internal::IsFunctionPointerExecutable(fn_ptr));
    CHECK(burner::net::internal::IsFunctionPointerTrusted(
        fn_ptr,
        {L"kernel32.dll"}));
    CHECK_FALSE(burner::net::internal::IsFunctionPointerTrusted(
        fn_ptr,
        {L"malicious.dll"}));
#else
    MESSAGE("Import pointer trust is Windows-only.");
    CHECK(true);
#endif
}

TEST_CASE("error codes map to expected output based on hardening") {
#if BURNERNET_HARDEN_ERRORS
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::DisabledBackend) ==
          std::to_string(static_cast<uint32_t>(burner::net::ErrorCode::DisabledBackend) ^
                         burner::net::detail::ErrorXorKey()));
#else
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::DisabledBackend) == "DisabledBackend");
#endif
}

TEST_CASE("selected error code strings are stable") {
    const burner::net::ErrorCode codes[] = {
        burner::net::ErrorCode::PreFlightAbort,
        burner::net::ErrorCode::EnvironmentCompromised,
        burner::net::ErrorCode::TransportVerificationFailed,
    };

    for (const auto code : codes) {
#if BURNERNET_HARDEN_ERRORS
        CHECK(burner::net::ErrorCodeToString(code) ==
              std::to_string(static_cast<uint32_t>(code) ^ burner::net::detail::ErrorXorKey()));
#else
        if (code == burner::net::ErrorCode::PreFlightAbort) {
            CHECK(burner::net::ErrorCodeToString(code) == "PreFlightAbort");
        } else if (code == burner::net::ErrorCode::EnvironmentCompromised) {
            CHECK(burner::net::ErrorCodeToString(code) == "EnvironmentCompromised");
        } else if (code == burner::net::ErrorCode::TransportVerificationFailed) {
            CHECK(burner::net::ErrorCodeToString(code) == "TransportVerificationFailed");
        } else {
            FAIL("Unexpected error code in stability test");
        }
#endif
    }
}
