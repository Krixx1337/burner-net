#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <cstdint>
#include <limits>
#include <ostream>
#include <span>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "burner/net/bootstrap.h"
#include "burner/net.h"
#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"
#include "burner/net/detail/dark_allocator.h"
#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/detail/dark_callables.h"
#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/detail/dark_simd.h"
#include "burner/net/detail/pointer_mangling.h"
#include "burner/net/detail/wiping_alloc_engine.h"
#include "curl/curl_http_client.h"
#include "curl/curl_http_client_internal.h"
#include "curl/curl_session.h"
#include "internal/header_validation.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace burner::net {

struct CurlHttpClientTestAccess final {
    static CurlApi* MutableApi(CurlHttpClient& client) noexcept {
        return client.m_session != nullptr ? &client.m_session->m_api : nullptr;
    }

    static std::size_t WriteHeader(
        std::string_view line,
        HeaderWriteContext* context) {
        return CurlHttpClient::WriteHeaderCallback(
            const_cast<char*>(line.data()), 1, line.size(), context);
    }

    static int CheckPeer(CurlHttpClient& client, char* remote_ip) {
        return CurlHttpClient::PrereqCallback(
            &client, remote_ip, nullptr, 443, 0);
    }

    static bool ConnectedPeerRejected(const CurlHttpClient& client) noexcept {
        return client.m_connected_peer_rejected;
    }

    static bool IsRetryable(
        const CurlHttpClient& client,
        ErrorCode error) noexcept {
        return client.IsRetryable(error);
    }
};

} // namespace burner::net

namespace {

CURLcode FailEverySetopt(CURL*, CURLoption, ...) {
    return CURLE_UNKNOWN_OPTION;
}

curl_slist* FailEverySlistAppend(curl_slist*, const char*) {
    return nullptr;
}

struct NeverCalledTransport final {
    burner::net::HttpResponse Send(burner::net::HttpRequest) {
        ++calls;
        return {};
    }

    int calls = 0;
};

void AddHardenedDohAndVerifier(burner::net::ClientBuilder& builder) {
    builder
        .WithDnsFallback(
            burner::net::DnsMode::Doh,
            "https://resolver.example/dns-query",
            "Test DoH",
            "resolver.example:443:192.0.2.53")
        .WithResponseVerifier([](
            const burner::net::HttpRequest&,
            const burner::net::HttpResponseView&) {
            return burner::net::VerificationResult{};
        });
}

constexpr const char* kValidTestPin =
    "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

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

TEST_CASE("header and bearer validation reject controls") {
    CHECK_FALSE(burner::net::internal::IsValidHeaderValue(std::string_view("abc\0def", 7)));
    CHECK_FALSE(burner::net::internal::IsValidHeaderValue("abc\x1f"));
    CHECK_FALSE(burner::net::internal::IsValidBearerToken("token value"));
    CHECK_FALSE(burner::net::internal::IsValidBearerToken(std::string_view("abc\0def", 7)));
    CHECK(burner::net::internal::IsValidBearerToken("abc.def-_~+/="));
}

TEST_CASE("HTTPS URL validation requires a non-empty authority") {
    CHECK(burner::net::internal::IsValidHttpsUrl("https://resolver.example/dns-query"));
    CHECK_FALSE(burner::net::internal::IsValidHttpsUrl(""));
    CHECK_FALSE(burner::net::internal::IsValidHttpsUrl("http://resolver.example/dns-query"));
    CHECK_FALSE(burner::net::internal::IsValidHttpsUrl("https:///dns-query"));
    CHECK_FALSE(burner::net::internal::IsValidHttpsUrl("https://user@resolver.example/dns-query"));
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

TEST_CASE("legacy dark arithmetic remains valid for unsigned inputs") {
    static_assert(burner::net::detail::DarkIntegral<std::uint64_t>);
    static_assert(!burner::net::detail::DarkIntegral<bool>);

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

TEST_CASE("dark allocator returns 16-byte-aligned user pointers") {
    void* ptr = burner::net::detail::alloc::dark_malloc(64);
    REQUIRE(ptr != nullptr);
    CHECK((reinterpret_cast<std::uintptr_t>(ptr) % 16u) == 0u);
    burner::net::detail::alloc::dark_free(ptr);
}

TEST_CASE("wiping allocator rejects arithmetic overflow") {
    CHECK(
        burner::net::detail::alloc::dark_malloc(
            (std::numeric_limits<std::size_t>::max)()) == nullptr);
    CHECK(
        burner::net::detail::alloc::dark_calloc(
            (std::numeric_limits<std::size_t>::max)(),
            2) == nullptr);
}

TEST_CASE("generic secure wipe preserves non-trivial object lifetimes") {
    std::vector<std::string> values{"alpha", "beta"};
    burner::net::SecureWipe(values);
    CHECK(values.empty());
}

TEST_CASE("response verifier accepts lambda callbacks") {
    burner::net::ResponseVerifyFn verifier(
        [](const burner::net::HttpRequest&, const burner::net::HttpResponseView& response) {
            return burner::net::VerificationResult{
                response.body == "payload"
                    ? burner::net::ErrorCode::None
                    : burner::net::ErrorCode::VerifyGeneric};
        });

    burner::net::HttpResponse good_response{};
    good_response.body = "payload";
    CHECK(verifier(
        burner::net::HttpRequest{},
        burner::net::HttpResponseView(good_response)).Passed());

    burner::net::HttpResponse bad_response{};
    bad_response.body = "tampered";
    CHECK(
        verifier(
            burner::net::HttpRequest{},
            burner::net::HttpResponseView(bad_response)).error ==
        burner::net::ErrorCode::VerifyGeneric);
}

TEST_CASE("client builder accepts lambda response verifiers") {
    burner::net::ClientBuilder builder;
    auto& chained = builder.WithResponseVerifier(
        [](const burner::net::HttpRequest&, const burner::net::HttpResponseView&) {
            return burner::net::VerificationResult{};
        });

    CHECK(&chained == &builder);
}

TEST_CASE("client builder accepts explicit curl module names") {
    burner::net::ClientBuilder builder;
    auto& chained = builder.WithCurlModuleName("utility_32.dll");

    CHECK(&chained == &builder);
}

TEST_CASE("bootstrap directory guard fails closed") {
#ifdef _WIN32
    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = std::filesystem::current_path();
    boot.dependency_dlls.push_back(TestCurlRuntimeName());
    boot.dependency_directory_guard =
        [](const std::filesystem::path&) { return false; };

    const burner::net::BootstrapResult init = burner::net::InitializeNetworkingRuntime(boot);

    INFO("BURNERNET_HARDEN_IMPORTS=" << BURNERNET_HARDEN_IMPORTS);
#if BURNERNET_HARDEN_IMPORTS
    CHECK(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapSkip);
#else
    CHECK_FALSE(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapDirectoryRejected);
#endif
#else
    const burner::net::BootstrapResult init =
        burner::net::InitializeNetworkingRuntime(burner::net::BootstrapConfig{});
    CHECK(init.success);
    CHECK(init.code == burner::net::ErrorCode::BootstrapWinOnly);
#endif
}

TEST_CASE("bootstrap runtime rejects non-basename dependency entries") {
#ifdef _WIN32
    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = std::filesystem::current_path();
    boot.dependency_dlls.push_back(L"..\\untrusted.dll");

    const burner::net::BootstrapResult init = burner::net::InitializeNetworkingRuntime(boot);
    CHECK_FALSE(init.success);
    CHECK(init.code == burner::net::ErrorCode::InvalidBootstrapDependency);
#else
    CHECK(true);
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
    boot.integrity_provider =
        [&](const std::filesystem::path& dll_path, const std::wstring& dll_name) {
            integrity_called = true;
            seen_path = dll_path;
            seen_name = dll_name;
            return std::filesystem::exists(dll_path);
        };

    const burner::net::BootstrapResult init = burner::net::InitializeNetworkingRuntime(boot);

    INFO("BURNERNET_HARDEN_IMPORTS=" << BURNERNET_HARDEN_IMPORTS);
    CHECK(init.success);
#if BURNERNET_HARDEN_IMPORTS
    CHECK(init.code == burner::net::ErrorCode::BootstrapSkip);
#else
    CHECK(init.code == burner::net::ErrorCode::BootstrapLoaded);
    CHECK(integrity_called);
    CHECK(seen_path == curl_path);
    CHECK(seen_name == curl_name);
#endif
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
    CHECK(strategy.bootstrap_resolve_entry.empty());
}

TEST_CASE("dns strategy owns its pinned bootstrap resolve entry") {
    burner::net::DnsStrategy strategy{};
    strategy.mode = burner::net::DnsMode::Doh;
    strategy.doh_url = "https://dns.example/dns-query";
    strategy.bootstrap_resolve_entry = "dns.example:443:192.0.2.1";

    const burner::net::DnsStrategy copy = strategy;
    strategy.bootstrap_resolve_entry = "changed";

    CHECK(copy.bootstrap_resolve_entry == "dns.example:443:192.0.2.1");
}

TEST_CASE("bootstrap resolve entries expire with curl's configured DNS timeout") {
    CHECK(
        burner::net::detail::MakeCacheExpiringResolveEntry(
            "dns.example:443:192.0.2.1") ==
        "+dns.example:443:192.0.2.1");
    CHECK(
        burner::net::detail::MakeCacheExpiringResolveEntry(
            "+dns.example:443:192.0.2.1") ==
        "+dns.example:443:192.0.2.1");
    CHECK(burner::net::detail::MakeCacheExpiringResolveEntry("").empty());
}

TEST_CASE("http response resolves an empty dns strategy name lazily") {
    burner::net::HttpResponse response{};
    CHECK(response.dns_strategy_used.empty());
    CHECK(response.DnsStrategyDisplayName() == "Default");

    response.dns_strategy_used = "Cloudflare";
    CHECK(response.DnsStrategyDisplayName() == "Cloudflare");
}

TEST_CASE("transport telemetry preserves raw certificate lines") {
    burner::net::TransportTelemetry telemetry{};
    telemetry.tls_chain.emplace_back("Issuer: O = Example Org, CN = Edge Root");
    telemetry.tls_chain.emplace_back("Subject: CN = api.internal");

    CHECK(telemetry.total_time_seconds == doctest::Approx(0.0));
    REQUIRE(telemetry.tls_chain.size() == 2);
    CHECK(telemetry.tls_chain[0] == "Issuer: O = Example Org, CN = Edge Root");
    CHECK(telemetry.tls_chain[1] == "Subject: CN = api.internal");
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

    burner::net::SecureWipe(secret);

    CHECK(secret.empty());
}

TEST_CASE("header callback publishes final response headers only") {
    burner::net::HeaderMap headers;
    burner::net::HeaderWriteContext context{&headers, nullptr};

    CHECK(
        burner::net::CurlHttpClientTestAccess::WriteHeader(
            "HTTP/1.1 401 Unauthorized\r\n", &context) > 0);
    CHECK(
        burner::net::CurlHttpClientTestAccess::WriteHeader(
            "X-Interim: stale\r\n", &context) > 0);
    CHECK(
        burner::net::CurlHttpClientTestAccess::WriteHeader(
            "HTTP/1.1 200 OK\r\n", &context) > 0);
    CHECK(
        burner::net::CurlHttpClientTestAccess::WriteHeader(
            "X-Final: current\r\n", &context) > 0);

    bool saw_interim = false;
    bool saw_final = false;
    for (const auto& [name, value] : headers) {
        saw_interim = saw_interim || burner::net::HeaderNameEquals(name, "X-Interim");
        saw_final = saw_final ||
            (burner::net::HeaderNameEquals(name, "X-Final") && value == "current");
    }
    CHECK_FALSE(saw_interim);
    CHECK(saw_final);
}

TEST_CASE("SecureWipe clears active vector bytes before emptying the buffer") {
    std::vector<std::uint8_t> secret = {0xde, 0xad, 0xbe, 0xef};
    secret.reserve(32);

    burner::net::SecureWipe(secret);

    CHECK(secret.empty());
}

TEST_CASE("raw secure wipe zeroes the requested span") {
    std::array<std::uint8_t, 4> secret = {0xde, 0xad, 0xbe, 0xef};
    burner::net::obf::secure_wipe(secret.data(), secret.size());
    CHECK(std::all_of(secret.begin(), secret.end(), [](std::uint8_t value) {
        return value == 0;
    }));
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

TEST_CASE("request guard rejects before transport") {
    int provider_calls = 0;
    auto build_result = burner::net::ClientBuilder()
        .WithRequestGuard([](const burner::net::HttpRequest&) { return false; })
        .WithBearerTokenProvider([&](burner::net::DarkString&) {
            ++provider_calls;
            return true;
        })
        .Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::RequestGuardRejected);
    CHECK(response.transport_code != 0);
    CHECK(provider_calls == 0);
}

TEST_CASE("request guard exception fails closed") {
    auto build_result = burner::net::ClientBuilder()
        .WithRequestGuard([](const burner::net::HttpRequest&) -> bool {
            throw 7;
        })
        .Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::CallbackFailed);
    CHECK(response.transport_code != 0);
}

TEST_CASE("connected peer guard fails closed") {
    int guard_calls = 0;
    auto build_result = burner::net::ClientBuilder()
        .WithConnectedPeerGuard([&](const burner::net::ConnectedPeer&) {
            ++guard_calls;
            return false;
        })
        .Build();

    REQUIRE(build_result.Ok());

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.dns_fallback.enabled = false;
    request.retry.max_attempts = 3;
    request.retry.backoff_ms = 0;

    const auto response = build_result.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::TransportVerificationFailed);
    CHECK(response.transport_code != 0);
    CHECK(guard_calls == 1);
}

TEST_CASE("connected peer guard exception fails closed") {
    auto build_result = burner::net::ClientBuilder()
        .WithConnectedPeerGuard([](const burner::net::ConnectedPeer&) -> bool {
            throw 7;
        })
        .Build();
    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();
    CHECK(response.transport_error == burner::net::ErrorCode::CallbackFailed);
}

TEST_CASE("loopback peer classification handles binary IPv4 and IPv6 forms") {
    using burner::net::ConnectedPeer;
    using burner::net::ConnectedPeerAddressFamily;
    using burner::net::detail::ClassifyConnectedPeerAddress;
    using burner::net::detail::PeerAddressClassification;

    const auto classify = [](std::string_view address,
                             ConnectedPeerAddressFamily family) {
        return ClassifyConnectedPeerAddress(ConnectedPeer{
            .remote_ip = address,
            .address_family = family,
            .remote_port = 443,
        });
    };

    CHECK(classify("127.0.0.1", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::Loopback);
    CHECK(classify("127.255.255.255", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::Loopback);
    CHECK(classify("::1", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Loopback);
    CHECK(classify("0:0:0:0:0:0:0:1", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Loopback);
    CHECK(classify("::ffff:127.0.0.1", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Loopback);
    CHECK(classify("::ffff:7f00:1", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Loopback);
    CHECK(classify("::127.0.0.1", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Loopback);

    CHECK(classify("126.255.255.255", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::NonLoopback);
    CHECK(classify("128.0.0.1", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::NonLoopback);
    CHECK(classify("1.1.1.1", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::NonLoopback);
    CHECK(classify("2606:4700:4700::1111", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::NonLoopback);
}

TEST_CASE("loopback peer classification fails closed on invalid identity") {
    using burner::net::ConnectedPeer;
    using burner::net::ConnectedPeerAddressFamily;
    using burner::net::detail::ClassifyConnectedPeerAddress;
    using burner::net::detail::PeerAddressClassification;

    const auto classify = [](std::string_view address,
                             ConnectedPeerAddressFamily family) {
        return ClassifyConnectedPeerAddress(ConnectedPeer{
            .remote_ip = address,
            .address_family = family,
            .remote_port = 443,
        });
    };

    const std::string embedded_nul("127.0.0.1\0evil", 14);
    const std::string oversized(64, '1');

    CHECK(classify("", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::Invalid);
    CHECK(classify("not-an-ip", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::Invalid);
    CHECK(classify(embedded_nul, ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::Invalid);
    CHECK(classify(oversized, ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Invalid);
    CHECK(classify("127.0.0.1", ConnectedPeerAddressFamily::IPv6) ==
          PeerAddressClassification::Invalid);
    CHECK(classify("::1", ConnectedPeerAddressFamily::IPv4) ==
          PeerAddressClassification::Invalid);
    CHECK(classify("127.0.0.1", ConnectedPeerAddressFamily::Unknown) ==
          PeerAddressClassification::Invalid);
}

TEST_CASE("built-in loopback rejection precedes custom peer guard") {
    int custom_guard_calls = 0;
    auto build_result = burner::net::ClientBuilder()
        .WithLoopbackPeerRejection()
        .WithConnectedPeerGuard(
            [&](const burner::net::ConnectedPeer&) {
                ++custom_guard_calls;
                return true;
            })
        .Build();
    REQUIRE(build_result.Ok());

    std::string loopback = "127.0.0.1";
    auto& transport = *build_result.client->Raw();
    CHECK(
        burner::net::CurlHttpClientTestAccess::CheckPeer(
            transport, loopback.data()) == CURL_PREREQFUNC_ABORT);
    CHECK(custom_guard_calls == 0);
    CHECK(
        burner::net::CurlHttpClientTestAccess::ConnectedPeerRejected(
            transport));
    CHECK_FALSE(
        burner::net::CurlHttpClientTestAccess::IsRetryable(
            transport,
            burner::net::ErrorCode::TransportVerificationFailed));
}

TEST_CASE("built-in loopback rejection accepts public peer before custom guard") {
    int custom_guard_calls = 0;
    auto build_result = burner::net::ClientBuilder()
        .WithLoopbackPeerRejection()
        .WithConnectedPeerGuard(
            [&](const burner::net::ConnectedPeer&) {
                ++custom_guard_calls;
                return true;
            })
        .Build();
    REQUIRE(build_result.Ok());

    std::string public_peer = "1.1.1.1";
    CHECK(
        burner::net::CurlHttpClientTestAccess::CheckPeer(
            *build_result.client->Raw(),
            public_peer.data()) == CURL_PREREQFUNC_OK);
    CHECK(custom_guard_calls == 1);
}

TEST_CASE("loopback rejection is opt-in and fails closed on missing peer") {
    auto default_result = burner::net::ClientBuilder().Build();
    REQUIRE(default_result.Ok());
    CHECK(
        burner::net::CurlHttpClientTestAccess::CheckPeer(
            *default_result.client->Raw(),
            nullptr) == CURL_PREREQFUNC_OK);

    int custom_guard_calls = 0;
    auto disabled_result = burner::net::ClientBuilder()
        .WithLoopbackPeerRejection(false)
        .WithConnectedPeerGuard(
            [&](const burner::net::ConnectedPeer&) {
                ++custom_guard_calls;
                return true;
            })
        .Build();
    REQUIRE(disabled_result.Ok());
    std::string loopback = "::1";
    CHECK(
        burner::net::CurlHttpClientTestAccess::CheckPeer(
            *disabled_result.client->Raw(),
            loopback.data()) == CURL_PREREQFUNC_OK);
    CHECK(custom_guard_calls == 1);

    auto enabled_result = burner::net::ClientBuilder()
        .WithLoopbackPeerRejection()
        .Build();
    REQUIRE(enabled_result.Ok());
    CHECK(
        burner::net::CurlHttpClientTestAccess::CheckPeer(
            *enabled_result.client->Raw(),
            nullptr) == CURL_PREREQFUNC_ABORT);
    CHECK(
        burner::net::CurlHttpClientTestAccess::ConnectedPeerRejected(
            *enabled_result.client->Raw()));
}

TEST_CASE("transfer cancellation fails closed") {
    auto build_result = burner::net::ClientBuilder()
        .WithTransferCancellation([](const burner::net::TransferProgress&) {
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
    CHECK(response.transport_error == burner::net::ErrorCode::TransferCancelled);
    CHECK(response.transport_code != 0);
}

TEST_CASE("transfer cancellation exception fails closed") {
    auto build_result = burner::net::ClientBuilder()
        .WithTransferCancellation(
            [](const burner::net::TransferProgress&) -> bool { throw 7; })
        .Build();
    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Get("https://example.com").Send();
    CHECK(response.transport_error == burner::net::ErrorCode::CallbackFailed);
}

TEST_CASE("terminal request errors do not retry and guard runs once") {
    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Get;
    request.url = "https://example.com";
    request.headers["Bad\r\nHeader"] = "boom";
    request.retry.max_attempts = 3;
    request.retry.backoff_ms = 0;
    request.retry.retry_on_transport_error = true;
    request.retry.retry_on_5xx = false;

    int guard_calls = 0;
    burner::net::ClientBuilder builder;
    builder.WithRequestGuard([&](const burner::net::HttpRequest&) {
        ++guard_calls;
        return true;
    });
    auto build_result = builder.Build();

    REQUIRE(build_result.Ok());

    const auto response = build_result.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::InvalidHeader);
    CHECK(guard_calls == 1);

    request.retry.retry_on_transport_error = false;
    guard_calls = 0;

    const auto single_attempt_response = build_result.client->Send(request);

    CHECK_FALSE(single_attempt_response.TransportOk());
    CHECK(single_attempt_response.transport_error == burner::net::ErrorCode::InvalidHeader);
    CHECK(guard_calls == 1);
}

TEST_CASE("error codes map to expected output based on hardening") {
#if BURNERNET_DIAGNOSTIC_STRINGS
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::DisabledBackend) == "DisabledBackend");
#else
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::DisabledBackend) == "E1");
#endif
}

TEST_CASE("selected error code strings are stable") {
    const burner::net::ErrorCode codes[] = {
        burner::net::ErrorCode::PreFlightAbort,
        burner::net::ErrorCode::EnvironmentCompromised,
        burner::net::ErrorCode::TransportVerificationFailed,
        burner::net::ErrorCode::UnsupportedStreamedMethod,
    };

    for (const auto code : codes) {
#if BURNERNET_DIAGNOSTIC_STRINGS
        if (code == burner::net::ErrorCode::PreFlightAbort) {
            CHECK(burner::net::ErrorCodeToString(code) == "PreFlightAbort");
        } else if (code == burner::net::ErrorCode::EnvironmentCompromised) {
            CHECK(burner::net::ErrorCodeToString(code) == "EnvironmentCompromised");
        } else if (code == burner::net::ErrorCode::TransportVerificationFailed) {
            CHECK(burner::net::ErrorCodeToString(code) == "TransportVerificationFailed");
        } else if (code == burner::net::ErrorCode::UnsupportedStreamedMethod) {
            CHECK(burner::net::ErrorCodeToString(code) == "UnsupportedStreamedMethod");
        } else {
            FAIL("Unexpected error code in stability test");
        }
#else
        CHECK(burner::net::ErrorCodeToString(code) ==
              "E" + std::to_string(static_cast<std::uint32_t>(code)));
#endif
    }
}

TEST_CASE("stack Client is disposable, non-copyable, and supports every fluent method") {
    using burner::net::Client;
    using burner::net::ErrorCode;

    static_assert(!std::is_copy_constructible_v<Client>);
    static_assert(!std::is_copy_assignable_v<Client>);
    static_assert(!std::is_move_constructible_v<Client>);

    Client client;
    REQUIRE(client.IsReady());
    CHECK(client.InitError() == ErrorCode::None);

    const auto expect_local_header_rejection = [](const burner::net::HttpResponse& response) {
        CHECK(response.transport_error == ErrorCode::InvalidHeader);
    };
    expect_local_header_rejection(client.Get("https://example.com").WithHeader("Bad\r\nHeader", "x").Send());
    expect_local_header_rejection(client.Post("https://example.com").WithHeader("Bad\r\nHeader", "x").Send());
    expect_local_header_rejection(client.Put("https://example.com").WithHeader("Bad\r\nHeader", "x").Send());
    expect_local_header_rejection(client.Delete("https://example.com").WithHeader("Bad\r\nHeader", "x").Send());
    expect_local_header_rejection(client.Patch("https://example.com").WithHeader("Bad\r\nHeader", "x").Send());
}

TEST_CASE("failed fluent client initialization propagates through Send") {
    burner::net::FluentClient<NeverCalledTransport> client(
        NeverCalledTransport{},
        burner::net::DnsFallbackPolicy{},
        burner::net::ErrorCode::InitCurl);

    const auto response = client.Get("https://example.com").Send();
    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_error == burner::net::ErrorCode::InitCurl);
    CHECK(client.Raw()->calls == 0);
}

TEST_CASE("verification status separates absent, passed, and failed app verification") {
    burner::net::HttpResponse response{};
    CHECK(response.verification_status == burner::net::VerificationStatus::NotConfigured);
    CHECK_FALSE(response.WasResponseVerified());

    response.verification_status = burner::net::VerificationStatus::Passed;
    CHECK(response.WasResponseVerified());
    CHECK(response.Ok() == (response.TransportOk() && response.HttpOk()));

    response.verification_status = burner::net::VerificationStatus::Failed;
    CHECK_FALSE(response.WasResponseVerified());
    CHECK_FALSE(response.Ok());
}

TEST_CASE("Hardened profile reports one stable error per missing control") {
    using namespace burner::net;

    SUBCASE("system proxy") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        const auto result = builder.WithCasualDefaults().Build();
        CHECK(result.error == ErrorCode::HardenedSystemProxyForbidden);
    }
    SUBCASE("peer verification") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        const auto result = builder.WithVerifyPeer(false).Build();
        CHECK(result.error == ErrorCode::HardenedVerifyPeerRequired);
    }
    SUBCASE("hostname verification") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        const auto result = builder.WithVerifyHost(false).Build();
        CHECK(result.error == ErrorCode::HardenedVerifyHostRequired);
    }
    SUBCASE("stack isolation") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        const auto result = builder.WithStackIsolation(false).Build();
        CHECK(result.error == ErrorCode::HardenedStackIsolationRequired);
    }
    SUBCASE("DoH") {
        ClientBuilder builder(ClientProfile::Hardened);
        builder.WithResponseVerifier([](
            const HttpRequest&, const HttpResponseView&) { return VerificationResult{}; });
        CHECK(builder.Build().error == ErrorCode::HardenedDohRequired);
    }
    SUBCASE("invalid DoH URL") {
        ClientBuilder builder(ClientProfile::Hardened);
        builder
            .WithDnsFallback(DnsMode::Doh, "http://resolver.example/dns-query", "DoH")
            .WithResponseVerifier([](
                const HttpRequest&,
                const HttpResponseView&) { return VerificationResult{}; });
        CHECK(builder.Build().error == ErrorCode::InvalidHardenedDoh);
    }
    SUBCASE("system DNS must use explicit fallback API") {
        ClientBuilder builder(ClientProfile::Hardened);
        builder
            .WithDnsFallback(DnsMode::Doh, "https://resolver.example/dns-query", "DoH")
            .WithDnsFallback(DnsMode::System, "", "System")
            .WithResponseVerifier([](const HttpRequest&, const HttpResponseView&) { return VerificationResult{}; });
        CHECK(builder.Build().error == ErrorCode::HardenedSystemDnsOrder);
    }
    SUBCASE("system DNS must follow DoH") {
        ClientBuilder builder(ClientProfile::Hardened);
        builder
            .AllowSystemDns(true)
            .WithDnsFallback(DnsMode::Doh, "https://resolver.example/dns-query", "DoH")
            .AllowSystemDns(true)
            .WithDnsFallback(DnsMode::Doh, "https://backup.example/dns-query", "Backup DoH")
            .WithResponseVerifier([](const HttpRequest&, const HttpResponseView&) { return VerificationResult{}; });
        CHECK(builder.Build().error == ErrorCode::HardenedSystemDnsOrder);
    }
    SUBCASE("response verifier") {
        ClientBuilder builder(ClientProfile::Hardened);
        builder.WithDnsFallback(
            DnsMode::Doh, "https://resolver.example/dns-query", "DoH");
        CHECK(builder.Build().error == ErrorCode::HardenedResponseVerifierRequired);
    }
    SUBCASE("certificate pin is optional") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        CHECK(builder.Build().Ok());
    }
    SUBCASE("malformed pin") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        CHECK(builder.WithPinnedKey("sha256//test").Build().error == ErrorCode::InvalidHardenedPin);
    }
    SUBCASE("empty pin") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        CHECK(builder.WithPinnedKey("").Build().error == ErrorCode::InvalidHardenedPin);
    }
    SUBCASE("decoded pin has wrong size") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        CHECK(
            builder.WithPinnedKey("sha256//QUJDRA==").Build().error ==
            ErrorCode::InvalidHardenedPin);
    }
    SUBCASE("filesystem pin") {
        ClientBuilder builder(ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        CHECK(builder.WithPinnedKey("server.pem").Build().error == ErrorCode::InvalidHardenedPin);
    }
}

TEST_CASE("AuthProtocol-style recipe qualifies for Hardened without certificate pinning") {
    using namespace burner::net;

    const auto result = ClientBuilder(ClientProfile::Hardened)
        .WithUseNativeCa(true)
        .WithStackIsolation(true)
        .WithMtlsProvider([](MtlsCredentials& out) {
            out.enabled = true;
            return true;
        })
        .WithConnectedPeerGuard([](const ConnectedPeer&) { return true; })
        .WithDnsFallback(DnsMode::Doh, "https://cloudflare-dns.com/dns-query", "Cloudflare")
        .WithDnsFallback(DnsMode::Doh, "https://dns.google/dns-query", "Google")
        .WithDnsFallback(DnsMode::Doh, "https://dns.quad9.net/dns-query", "Quad9")
        .AllowSystemDns(true)
        .WithResponseVerifier([](const HttpRequest&, const HttpResponseView&) { return VerificationResult{}; })
        .Build();

    CHECK(result.Ok());
    CHECK(result.error == ErrorCode::None);
    const auto failed_transport = result.client
        ->Get("https://example.com")
        .WithHeader("Bad\r\nHeader", "x")
        .Send();
    CHECK(failed_transport.verification_status == VerificationStatus::Failed);
    CHECK_FALSE(failed_transport.WasResponseVerified());
}

TEST_CASE("Hardened redirect rejection precedes credential providers") {
    using namespace burner::net;

    int provider_calls = 0;
    ClientBuilder builder(ClientProfile::Hardened);
    AddHardenedDohAndVerifier(builder);
    auto result = builder
        .WithBearerTokenProvider([&](DarkString&) {
            ++provider_calls;
            return true;
        })
        .Build();
    REQUIRE(result.Ok());

    const auto response = result.client
        ->Get("https://example.com")
        .FollowRedirects(true)
        .Send();
    CHECK(response.transport_error == ErrorCode::HardenedRedirectForbidden);
    CHECK(provider_calls == 0);
}

TEST_CASE("Standard rejects verified redirects before networking") {
    using namespace burner::net;

    auto result = ClientBuilder()
        .WithResponseVerifier(
            [](const HttpRequest&, const HttpResponseView&) {
                return VerificationResult{};
            })
        .Build();
    REQUIRE(result.Ok());

    const auto response = result.client
        ->Get("https://example.com")
        .FollowRedirects(true)
        .Send();
    CHECK(response.transport_error == ErrorCode::RedirectAuth);
}

TEST_CASE("AuthReporter-style Standard builder remains source compatible") {
    const auto result = burner::net::ClientBuilder()
        .WithCasualDefaults()
        .WithUseNativeCa(true)
        .WithStackIsolation(true)
        .WithGlobalMaxBodyLimit(64 * 1024)
        .WithUserAgent("AuthReporter/1.0")
        .Build();

    CHECK(result.Ok());
    const auto failed_transport = result.client
        ->Get("https://example.com")
        .WithHeader("Bad\r\nHeader", "x")
        .Send();
    CHECK(failed_transport.verification_status == burner::net::VerificationStatus::NotConfigured);
}

TEST_CASE("streamed bodies fail closed for non-post methods") {
    auto build_result = burner::net::ClientBuilder()
        .Build();

    REQUIRE(build_result.Ok());

    burner::net::HttpRequest request{};
    request.method = burner::net::HttpMethod::Put;
    request.url = "https://example.com";
    request.dns_fallback.enabled = false;
    request.streamed_payload_size = 4;
    request.stream_payload_provider = [](std::span<char> dest) -> std::size_t {
        if (dest.size() < 4) {
            return 0;
        }
        dest[0] = 't';
        dest[1] = 'e';
        dest[2] = 's';
        dest[3] = 't';
        return 4;
    };

    const auto response = build_result.client->Send(request);

    CHECK_FALSE(response.TransportOk());
    CHECK(response.transport_code == static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT));
    CHECK(response.transport_error == burner::net::ErrorCode::UnsupportedStreamedMethod);
}

TEST_CASE("verified streaming is rejected before preflight and transport") {
    int guard_calls = 0;
    auto build_result = burner::net::ClientBuilder()
        .WithRequestGuard([&](const burner::net::HttpRequest&) {
            ++guard_calls;
            return true;
        })
        .WithResponseVerifier([](
            const burner::net::HttpRequest&,
            const burner::net::HttpResponseView&) {
            return burner::net::VerificationResult{};
        })
        .Build();
    REQUIRE(build_result.Ok());

    const auto response = build_result.client
        ->Get("https://example.com")
        .OnChunkReceived([](const std::uint8_t*, std::size_t) {})
        .Send();

    CHECK(response.transport_error == burner::net::ErrorCode::UnsupportedVerifiedStreaming);
    CHECK(response.verification_error == burner::net::ErrorCode::UnsupportedVerifiedStreaming);
    CHECK(guard_calls == 0);
}

TEST_CASE("credential providers fail closed before transport") {
    SUBCASE("mTLS provider failure") {
        auto result = burner::net::ClientBuilder()
            .WithMtlsProvider([](burner::net::MtlsCredentials&) { return false; })
            .Build();
        REQUIRE(result.Ok());
        const auto response = result.client->Get("https://example.com").Send();
        CHECK(response.transport_error == burner::net::ErrorCode::CredentialProviderFailed);
    }
    SUBCASE("mTLS provider exception") {
        auto result = burner::net::ClientBuilder()
            .WithMtlsProvider([](burner::net::MtlsCredentials&) -> bool {
                throw 7;
            })
            .Build();
        REQUIRE(result.Ok());
        const auto response = result.client->Get("https://example.com").Send();
        CHECK(response.transport_error == burner::net::ErrorCode::CredentialProviderFailed);
    }
    SUBCASE("mTLS provider can coexist with Hardened response verification") {
        burner::net::ClientBuilder builder(burner::net::ClientProfile::Hardened);
        AddHardenedDohAndVerifier(builder);
        builder.WithMtlsProvider([](burner::net::MtlsCredentials& out) {
            out.enabled = true;
            out.cert_pem = "certificate";
            out.key_pem = "key";
            return true;
        });
        CHECK(builder.Build().Ok());
    }

    SUBCASE("empty bearer token") {
        auto result = burner::net::ClientBuilder()
            .WithBearerTokenProvider([](burner::net::DarkString& out) {
                out.clear();
                return true;
            })
            .Build();
        REQUIRE(result.Ok());
        const auto response = result.client->Get("https://example.com").Send();
        CHECK(response.transport_error == burner::net::ErrorCode::InvalidCredentials);
    }
    SUBCASE("bearer provider exception") {
        auto result = burner::net::ClientBuilder()
            .WithBearerTokenProvider([](burner::net::DarkString&) -> bool {
                throw 7;
            })
            .Build();
        REQUIRE(result.Ok());
        const auto response = result.client->Get("https://example.com").Send();
        CHECK(response.transport_error == burner::net::ErrorCode::CredentialProviderFailed);
    }
}

TEST_CASE("curl option and header allocation failures fail closed") {
    SUBCASE("setopt failure") {
        auto result = burner::net::ClientBuilder().Build();
        REQUIRE(result.Ok());
        auto* api = burner::net::CurlHttpClientTestAccess::MutableApi(
            *result.client->Raw());
        REQUIRE(api != nullptr);
        const auto original = api->easy_setopt.get();
        api->easy_setopt = &FailEverySetopt;

        const auto response = result.client->Get("https://example.com").Send();
        api->easy_setopt = original;

        CHECK(response.transport_error == burner::net::ErrorCode::CurlOptionFailed);
    }

    SUBCASE("slist append failure") {
        auto result = burner::net::ClientBuilder().Build();
        REQUIRE(result.Ok());
        auto* api = burner::net::CurlHttpClientTestAccess::MutableApi(
            *result.client->Raw());
        REQUIRE(api != nullptr);
        const auto original = api->slist_append.get();
        api->slist_append = &FailEverySlistAppend;

        const auto response = result.client
            ->Get("https://example.com")
            .WithHeader("X-Test", "value")
            .Send();
        api->slist_append = original;

        CHECK(response.transport_error == burner::net::ErrorCode::OutOfMemory);
    }
}

TEST_CASE("stack isolation executes transport on a distinct thread") {
    using namespace burner::net;

    const std::thread::id caller_thread_id = std::this_thread::get_id();
    std::thread::id transport_thread_id;

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithStackIsolation(true)
        .WithConnectedPeerGuard([&](const ConnectedPeer&) {
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
        .WithConnectedPeerGuard([&](const ConnectedPeer&) {
            transport_thread_id = std::this_thread::get_id();
            return true;
        })
        .Build();

    REQUIRE(build_result.Ok());

    (void)build_result.client->Get("https://example.com").Send();

    CHECK(transport_thread_id == caller_thread_id); // No thread hop
}
