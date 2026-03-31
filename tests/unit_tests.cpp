#include <doctest/doctest.h>

#include <cstdint>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"
#include "burner/net/policy.h"
#include "burner/net/security_auditor.h"
#include "burner/net/detail/pointer_mangling.h"
#include "curl/curl_http_client.h"
#include "internal/header_validation.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

struct RejectPreFlightPolicy final : burner::net::ISecurityPolicy {
    bool OnPreRequest(burner::net::HttpRequest&) const {
        return false;
    }
};

struct RejectHeartbeatPolicy final : burner::net::ISecurityPolicy {
    bool OnHeartbeat(const burner::net::TransferProgress&) const {
        return false;
    }
};

struct AllowAllPolicy final : burner::net::ISecurityPolicy {};

struct RecordingPolicy final : burner::net::ISecurityPolicy {
public:
    bool transport_allowed = true;
    std::shared_ptr<int> tamper_count = std::make_shared<int>(0);

    bool OnVerifyTransport(const char*, const char*) const {
        return transport_allowed;
    }

    void OnTamper() const {
        ++(*tamper_count);
    }
};

class SecurityAuditorStubClient final {
public:
    explicit SecurityAuditorStubClient(const burner::net::SecurityPolicy* policy)
        : m_policy(policy) {}

    burner::net::HttpResponse Send(const burner::net::HttpRequest&) {
        burner::net::HttpResponse response{};
        response.transport_code = 1;
        response.transport_error =
            m_call_count++ == 0
                ? burner::net::ErrorCode::TlsVerificationFailed
                : burner::net::ErrorCode::CurlGeneric;
        return response;
    }

    const burner::net::SecurityPolicy* SecurityPolicy() const {
        return m_policy;
    }

private:
    const burner::net::SecurityPolicy* m_policy = nullptr;
    int m_call_count = 0;
};

class RecordingTransport final {
public:
    burner::net::HttpResponse Send(const burner::net::HttpRequest& request) {
        last_request = request;
        return {};
    }

    burner::net::HttpRequest last_request{};
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

TEST_CASE("response verifier accepts lambda callbacks") {
    burner::net::ResponseVerifier verifier(
        [](const burner::net::HttpRequest&, const burner::net::HttpResponse& response, burner::net::ErrorCode* reason) {
            if (reason != nullptr) {
                *reason = response.body == "payload"
                    ? burner::net::ErrorCode::None
                    : burner::net::ErrorCode::VerifyGeneric;
            }
            return response.body == "payload";
        });

    burner::net::HttpResponse good_response{};
    good_response.body = "payload";
    burner::net::ErrorCode reason = burner::net::ErrorCode::VerifyGeneric;
    CHECK(verifier.Verify(burner::net::HttpRequest{}, good_response, &reason));
    CHECK(reason == burner::net::ErrorCode::None);

    burner::net::HttpResponse bad_response{};
    bad_response.body = "tampered";
    CHECK_FALSE(verifier.Verify(burner::net::HttpRequest{}, bad_response, &reason));
    CHECK(reason == burner::net::ErrorCode::VerifyGeneric);
}

TEST_CASE("client builder accepts lambda response verifiers") {
    burner::net::ClientBuilder builder;
    auto& chained = builder.WithResponseVerifier(
        [](const burner::net::HttpRequest&, const burner::net::HttpResponse&, burner::net::ErrorCode* reason) {
            if (reason != nullptr) {
                *reason = burner::net::ErrorCode::None;
            }
            return true;
        });

    CHECK(&chained == &builder);
}

TEST_CASE("client builder accepts explicit curl module names") {
    burner::net::ClientBuilder builder;
    auto& chained = builder.WithCurlModuleName("utility_32.dll");

    CHECK(&chained == &builder);
}

TEST_CASE("dns strategy defaults to an empty display name") {
    burner::net::DnsStrategy strategy{};
    CHECK(strategy.name.empty());
}

TEST_CASE("http response resolves an empty dns strategy name lazily") {
    burner::net::HttpResponse response{};
    CHECK(response.dns_strategy_used.empty());
    CHECK(response.DnsStrategyDisplayName() == "Default");

    response.dns_strategy_used = "Cloudflare";
    CHECK(response.DnsStrategyDisplayName() == "Cloudflare");
}

TEST_CASE("dns fallback policy defaults to an empty strategy list") {
    burner::net::DnsFallbackPolicy policy{};
    CHECK(policy.strategies.empty());
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

TEST_CASE("SecureString behaves like std::string for public request fields") {
    burner::net::HttpRequest request{};
    request.body = "payload";
    request.body.append("-extra");

    CHECK(request.body.str() == "payload-extra");
    CHECK(request.body.size() == 13);
}

TEST_CASE("request builder switches between owned bodies and body views") {
    RecordingTransport transport{};
    burner::net::FluentClient<RecordingTransport> client(std::move(transport), {});

    std::string borrowed = "borrowed-payload";
    const auto first_response = client.Post("https://example.com")
        .WithBody("owned-payload")
        .WithBodyView(borrowed)
        .Send();
    (void)first_response;

    CHECK(client.Raw()->last_request.body.empty());
    CHECK(std::string(client.Raw()->last_request.body_view) == borrowed);

    const auto second_response = client.Post("https://example.com")
        .WithBodyView(borrowed)
        .WithBody("owned-again")
        .Send();
    (void)second_response;

    CHECK(client.Raw()->last_request.body.str() == "owned-again");
    CHECK(client.Raw()->last_request.body_view.empty());
}

namespace {

int IncrementValue(int value) {
    return value + 1;
}

} // namespace

TEST_CASE("EncodedPointer decodes and invokes function pointers") {
    burner::net::EncodedPointer<int (*)(int)> pointer = &IncrementValue;

    REQUIRE(pointer);
    CHECK(pointer.get() != nullptr);
    CHECK(pointer(41) == 42);
}

TEST_CASE("client aborts immediately when security policy rejects preflight") {
    auto build_result = burner::net::ClientBuilder()
        .WithSecurityPolicy(RejectPreFlightPolicy{})
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
        .WithSecurityPolicy(RejectPreFlightPolicy{})
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
        .WithSecurityPolicy(AllowAllPolicy{})
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
        .WithSecurityPolicy(AllowAllPolicy{})
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
    burner::net::SecurityPolicy erased_policy = policy;
    SecurityAuditorStubClient client(&erased_policy);

    CHECK_FALSE(burner::net::SecurityAuditor::CheckTransportIntegrity(
        &client,
        {"https://canary-one.invalid", "https://canary-two.invalid"}));
    CHECK(*policy.tamper_count == 1);
}

TEST_CASE("security auditor treats an empty canary set as a no-op") {
    SecurityAuditorStubClient client(nullptr);
    CHECK(burner::net::SecurityAuditor::CheckTransportIntegrity(&client, {}));
}

TEST_CASE("builder tamper action layers on top of wrapped policy tamper handling") {
    RecordingPolicy policy{};
    bool tamper_action_called = false;

    auto build_result = burner::net::ClientBuilder()
        .WithTamperAction([&] {
            tamper_action_called = true;
        })
        .WithSecurityPolicy(policy)
        .Build();

    REQUIRE(build_result.Ok());
    REQUIRE(static_cast<bool>(build_result.client));

    build_result.client->Raw()->SecurityPolicy()->OnTamper();
    CHECK(tamper_action_called);
    CHECK(*policy.tamper_count == 1);
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
