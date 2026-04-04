#include <doctest/doctest.h>

#include <algorithm>
#include <filesystem>
#include <cstdint>
#include <ostream>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"
#include "burner/net/policy.h"
#include "burner/net/security_auditor.h"
#include "burner/net/detail/dark_allocator.h"
#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/detail/dark_callables.h"
#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/detail/dark_simd.h"
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

struct HandleProbe {
    explicit HandleProbe(int* count)
        : destroy_count(count) {}

    ~HandleProbe() {
        if (destroy_count != nullptr) {
            ++(*destroy_count);
        }
    }

    int* destroy_count = nullptr;
};

#ifdef _WIN32
std::filesystem::path CurrentExecutablePath() {
    wchar_t buffer[MAX_PATH] = {};
    const DWORD length = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (length == 0 || length == MAX_PATH) {
        return {};
    }

    return std::filesystem::path(buffer);
}

std::wstring TestCurlRuntimeName() {
#if defined(_DEBUG)
    return L"libcurl-d.dll";
#else
    return L"libcurl.dll";
#endif
}
#endif

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

TEST_CASE("dark hashing supports case-sensitive and case-insensitive FNV-1a") {
    constexpr std::uint32_t content_type_a = burner::net::detail::fnv1a_ci("Content-Type");
    constexpr std::uint32_t content_type_b = burner::net::detail::fnv1a_ci("content-type");
    constexpr std::uint32_t content_type_cs = burner::net::detail::fnv1a("Content-Type");

    static_assert(content_type_a == content_type_b);
    static_assert(content_type_a != content_type_cs);

    CHECK(content_type_a == burner::net::detail::fnv1a_runtime_ci("CONTENT-TYPE"));
    CHECK(content_type_cs == burner::net::detail::fnv1a_runtime("Content-Type"));
}

TEST_CASE("dark arithmetic restores masked constants through MBA identities") {
    static_assert(burner::net::detail::DarkIntegral<std::uint64_t>);
    static_assert(!burner::net::detail::DarkIntegral<bool>);

    const auto curlopt_url = BURNER_MASK_INT(10002L);
    const auto http_ok = BURNER_MASK_INT(200);

    CHECK(curlopt_url == 10002L);
    CHECK(http_ok == 200);
    CHECK(burner::net::detail::add_deep(17u, 25u) == 42u);
    CHECK(burner::net::detail::add_deep_alt(17u, 25u) == 42u);
    CHECK(burner::net::detail::sub_deep(100u, 58u) == 42u);
    CHECK(burner::net::detail::mba_xor<std::uint32_t>(0x12345678u, 0x00FF00FFu) ==
          (0x12345678u ^ 0x00FF00FFu));
}

TEST_CASE("kernel resolver can locate signatures inside executable system modules") {
#ifdef _WIN32
    void* const kernel32 = burner::net::detail::KernelResolver::GetSystemModule(
        burner::net::detail::fnv1a_ci("kernel32.dll"));
    REQUIRE(kernel32 != nullptr);

    void* const ret_opcode = burner::net::detail::KernelResolver::FindModuleSignature(kernel32, 0xC3u);
    CHECK(ret_opcode != nullptr);
    CHECK(burner::net::detail::KernelResolver::FindModuleSignature(nullptr, 0xC3u) == nullptr);
#else
    CHECK(true); // nothing to assert on non-Windows; test passes vacuously
#endif
}

TEST_CASE("dark simd literal restores plaintext") {
    const std::string value =
        ::burner::net::detail::DarkLiteral<sizeof("https://api.internal/v1"),
            0x12345678ABCDEF01ull>{"https://api.internal/v1"}.resolve();

    CHECK(value == "https://api.internal/v1");
}

TEST_CASE("secure handle destroys its payload without shared ownership") {
    int destroy_count = 0;

    {
        auto handle = burner::net::detail::SecureHandle<HandleProbe>::make<HandleProbe>(&destroy_count);
        REQUIRE(static_cast<bool>(handle));
        CHECK(handle->destroy_count == &destroy_count);
    }

    CHECK(destroy_count == 1);
}

TEST_CASE("compact callable stores and clones lambdas without std function") {
    burner::net::detail::CompactCallable<int(int)> callable = [](int value) {
        return value + 7;
    };

    burner::net::detail::CompactCallable<int(int)> copy = callable;
    REQUIRE(static_cast<bool>(copy));

    CHECK(callable(35) == 42);
    CHECK(copy(35) == 42);
}

TEST_CASE("wiping allocator satisfies allocator usage for containers") {
    std::basic_string<char, std::char_traits<char>, burner::net::detail::WipingAllocator<char>> secret(
        "classified");
    std::vector<std::uint8_t, burner::net::detail::WipingAllocator<std::uint8_t>> bytes = {1, 2, 3, 4};

    CHECK(secret == "classified");
    CHECK(bytes.size() == 4);
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

TEST_CASE("bootstrap runtime rejects missing integrity provider in fail-closed mode") {
#ifdef _WIN32
    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = std::filesystem::current_path();
    boot.dependency_dlls.push_back(TestCurlRuntimeName());
    boot.integrity_policy.enabled = true;
    boot.integrity_policy.fail_closed = true;

    const burner::net::BootstrapResult init = burner::net::InitializeNetworkingRuntime(boot);

    INFO("BURNERNET_HARDEN_IMPORTS=" << BURNERNET_HARDEN_IMPORTS);
    CHECK_FALSE(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapIntegrityCfg);
#else
    const burner::net::BootstrapResult init =
        burner::net::InitializeNetworkingRuntime(burner::net::BootstrapConfig{});
    CHECK(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapWinOnly);
#endif
}

TEST_CASE("bootstrap runtime loads packaged redist like the bootstrap example") {
#ifdef _WIN32
    const std::filesystem::path executable_path = CurrentExecutablePath();
    REQUIRE(!executable_path.empty());

    const std::filesystem::path redist_dir = executable_path.parent_path() / "redist";
    const std::wstring curl_name = TestCurlRuntimeName();
    const std::filesystem::path curl_path = redist_dir / std::filesystem::path(curl_name);

    if (!std::filesystem::exists(curl_path)) {
        MESSAGE("Skipping packaged bootstrap test because runtime dependency is missing: "
                << curl_path.string());
        return;
    }

    bool integrity_called = false;
    std::filesystem::path seen_path;
    std::wstring seen_name;

    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = redist_dir;
    boot.dependency_dlls.push_back(curl_name);
    boot.integrity_policy.enabled = true;
    boot.integrity_policy.fail_closed = true;
    boot.integrity_policy.integrity_provider =
        [&](const std::filesystem::path& dll_path, const std::wstring& dll_name) {
            integrity_called = true;
            seen_path = dll_path;
            seen_name = dll_name;
            return std::filesystem::exists(dll_path);
        };

    const burner::net::BootstrapResult init = burner::net::InitializeNetworkingRuntime(boot);

    INFO("BURNERNET_HARDEN_IMPORTS=" << BURNERNET_HARDEN_IMPORTS);
    CHECK(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapLoaded);
    CHECK(integrity_called);
    CHECK(seen_path == curl_path);
    CHECK(seen_name == curl_name);
#else
    const burner::net::BootstrapResult init =
        burner::net::InitializeNetworkingRuntime(burner::net::BootstrapConfig{});
    CHECK(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapWinOnly);
#endif
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

TEST_CASE("request builder switches cleanly between streamed and static bodies") {
    RecordingTransport transport{};
    burner::net::FluentClient<RecordingTransport> client(std::move(transport), {});

    std::size_t first_cursor = 0;
    const auto first_response = client.Post("https://example.com")
        .WithBody("owned-payload")
        .WithStreamedBody(3, [&first_cursor](std::span<char> dest) -> std::size_t {
            const char payload[] = {'a', 'b', 'c'};
            const std::size_t remaining = sizeof(payload) - first_cursor;
            const std::size_t chunk = (std::min)(dest.size(), remaining);
            for (std::size_t i = 0; i < chunk; ++i) {
                dest[i] = payload[first_cursor + i];
            }
            first_cursor += chunk;
            return chunk;
        })
        .Send();
    (void)first_response;

    CHECK(client.Raw()->last_request.body.empty());
    CHECK(client.Raw()->last_request.body_view.empty());
    CHECK(client.Raw()->last_request.stream_payload_provider);
    CHECK(client.Raw()->last_request.streamed_payload_size == 3);

    char first_buffer[8] = {};
    const auto first_bytes = client.Raw()->last_request.stream_payload_provider(std::span<char>(first_buffer, 8));
    CHECK(first_bytes == 3);
    CHECK(std::string_view(first_buffer, first_bytes) == "abc");

    const auto second_response = client.Post("https://example.com")
        .WithStreamedBody(4, [](std::span<char>) -> std::size_t { return 0; })
        .WithBodyView("borrowed")
        .Send();
    (void)second_response;

    CHECK_FALSE(client.Raw()->last_request.stream_payload_provider);
    CHECK(client.Raw()->last_request.streamed_payload_size == 0);
    CHECK(std::string(client.Raw()->last_request.body_view) == "borrowed");

    const auto third_response = client.Post("https://example.com")
        .WithStreamedBody(4, [](std::span<char>) -> std::size_t { return 0; })
        .WithBody("owned-again")
        .Send();
    (void)third_response;

    CHECK_FALSE(client.Raw()->last_request.stream_payload_provider);
    CHECK(client.Raw()->last_request.streamed_payload_size == 0);
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

TEST_CASE("EncodedPointer remains valid after copy and move") {
    burner::net::EncodedPointer<int (*)(int)> original = &IncrementValue;
    burner::net::EncodedPointer<int (*)(int)> copy = original;
    burner::net::EncodedPointer<int (*)(int)> moved = std::move(original);

    REQUIRE(copy);
    REQUIRE(moved);
    CHECK(copy(41) == 42);
    CHECK(moved(41) == 42);
    CHECK_FALSE(original);
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

TEST_CASE("security auditor accepts empty canary set when policy is present and module health is intact") {
    RecordingPolicy policy{};
    burner::net::SecurityPolicy erased_policy = policy;
    SecurityAuditorStubClient client(&erased_policy);

    CHECK(burner::net::SecurityAuditor::CheckTransportIntegrity(&client, &erased_policy, {}));
    CHECK(*policy.tamper_count == 0);
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

TEST_CASE("stack isolation executes transport on a distinct thread") {
    using namespace burner::net;

    const std::thread::id caller_thread_id = std::this_thread::get_id();
    std::thread::id transport_thread_id;

    // WithTransportCheck maps to OnVerifyTransport, called inside PerformOnceInternal
    // after a successful curl_easy_perform — i.e. on the worker thread.
    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithStackIsolation(true)
        .WithTransportCheck([&](const char*, const char*) {
            transport_thread_id = std::this_thread::get_id();
            return true;
        })
        .Build();

    REQUIRE(build_result.Ok());

    (void)build_result.client->Get("https://example.com").Send();

    CHECK(transport_thread_id != std::thread::id{}); // Ensure the callback ran
    CHECK(transport_thread_id != caller_thread_id);  // PROOF OF SEVERED STACK
}

TEST_CASE("transport stays on caller thread when isolation is disabled") {
    using namespace burner::net;

    const std::thread::id caller_thread_id = std::this_thread::get_id();
    std::thread::id transport_thread_id;

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithStackIsolation(false)
        .WithTransportCheck([&](const char*, const char*) {
            transport_thread_id = std::this_thread::get_id();
            return true;
        })
        .Build();

    REQUIRE(build_result.Ok());

    (void)build_result.client->Get("https://example.com").Send();

    CHECK(transport_thread_id == caller_thread_id); // No thread hop
}
