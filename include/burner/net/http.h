#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "detail/dark_callables.h"
#include "detail/dark_hashing.h"
#include "detail/memory_hygiene.h"
#include "export.h"
#include "error.h"
#include "obfuscation.h"

namespace burner::net {

inline bool HeaderNameEquals(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    if (detail::fnv1a_runtime_ci(lhs) != detail::fnv1a_runtime_ci(rhs)) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (detail::ascii_lower(lhs[i]) != detail::ascii_lower(rhs[i])) {
            return false;
        }
    }
    return true;
}

enum class HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch
};

class HeaderMap {
public:
    using key_type = DarkString;
    using mapped_type = DarkString;
    using value_type = std::pair<key_type, mapped_type>;
    using storage_type = DarkVector<value_type>;
    using iterator = storage_type::iterator;
    using const_iterator = storage_type::const_iterator;

    HeaderMap() = default;
    HeaderMap(const HeaderMap&) = default;
    HeaderMap(HeaderMap&& other) noexcept
        : m_items(std::move(other.m_items)) {}

    HeaderMap& operator=(const HeaderMap& other) {
        if (this != &other) {
            storage_type replacement(other.m_items);
            clear();
            m_items = std::move(replacement);
        }
        return *this;
    }
    HeaderMap& operator=(HeaderMap&& other) noexcept {
        if (this != &other) {
            clear();
            m_items = std::move(other.m_items);
        }
        return *this;
    }

    ~HeaderMap() {
        clear();
    }

    mapped_type& operator[](key_type key) {
        if (auto* existing = find_value(key)) {
            return *existing;
        }

        m_items.emplace_back(std::move(key), DarkString{});
        return m_items.back().second;
    }

    mapped_type& operator[](const std::string& key) { return (*this)[std::string_view(key)]; }
    mapped_type& operator[](const char* key) { return (*this)[std::string_view(key == nullptr ? "" : key)]; }
    mapped_type& operator[](std::string_view key) { return (*this)[key_type(key)]; }

    void insert_or_assign(key_type key, mapped_type value) {
        if (auto* existing = find_value(key)) {
            ::burner::net::obf::secure_wipe(*existing);
            *existing = std::move(value);
            return;
        }

        m_items.emplace_back(std::move(key), std::move(value));
    }

    [[nodiscard]] bool empty() const noexcept { return m_items.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return m_items.size(); }

    iterator begin() noexcept { return m_items.begin(); }
    iterator end() noexcept { return m_items.end(); }
    const_iterator begin() const noexcept { return m_items.begin(); }
    const_iterator end() const noexcept { return m_items.end(); }
    const_iterator cbegin() const noexcept { return m_items.cbegin(); }
    const_iterator cend() const noexcept { return m_items.cend(); }

    void clear() noexcept;

private:
    mapped_type* find_value(const key_type& key) noexcept {
        for (auto& [existing_key, existing_value] : m_items) {
            if (HeaderNameEquals(existing_key, key)) {
                return &existing_value;
            }
        }
        return nullptr;
    }

    storage_type m_items;
};

inline void HeaderMap::clear() noexcept {
    for (auto& [key, value] : m_items) {
        ::burner::net::obf::secure_wipe(key);
        ::burner::net::obf::secure_wipe(value);
    }
    m_items.clear();
}
using TokenProvider = detail::CompactCallable<bool(DarkString& out)>;
using ChunkCallback = detail::CompactCallable<void(const uint8_t*, size_t)>;
using StreamPayloadCallback = detail::CompactCallable<std::size_t(std::span<char> dest_buffer)>;
using RequestGuard = detail::CompactCallable<bool(const struct HttpRequest& request)>;

enum class ConnectedPeerAddressFamily : std::uint8_t {
    Unknown,
    IPv4,
    IPv6
};

struct ConnectedPeer {
    std::string_view remote_ip;
    ConnectedPeerAddressFamily address_family = ConnectedPeerAddressFamily::Unknown;
    int remote_port = 0;
};

using ConnectedPeerGuard = detail::CompactCallable<bool(const ConnectedPeer& peer)>;

struct TransferProgress {
    long long dl_total = 0;
    long long dl_now = 0;
    long long ul_total = 0;
    long long ul_now = 0;
};

using TransferCancellation = detail::CompactCallable<bool(const TransferProgress&)>;

enum class DnsMode {
    System,
    Doh
};

struct DnsStrategy {
    DnsMode mode = DnsMode::System;
    DarkString name;
    DarkString doh_url;
    DarkString bootstrap_resolve_entry;
};

struct DnsFallbackPolicy {
    bool enabled = true;
    DarkVector<DnsStrategy> strategies;
};

struct RetryPolicy {
    int max_attempts = 1;
    int backoff_ms = 250;
    bool retry_on_transport_error = true;
    bool retry_on_5xx = true;
};

struct MtlsCredentials {
    bool enabled = false;
    SecureString cert_pem;
    SecureString key_pem;
    SecureString key_password;
};

struct HttpRequest {
    HttpRequest() = default;
    HttpRequest(const HttpRequest&) = default;
    HttpRequest(HttpRequest&&) noexcept = default;
    HttpRequest& operator=(HttpRequest&& other) noexcept {
        if (this != &other) {
            SecureWipe(url);
            SecureWipe(body);
            method = other.method;
            url = std::move(other.url);
            body = std::move(other.body);
            body_view = other.body_view;
            stream_payload_provider = std::move(other.stream_payload_provider);
            streamed_payload_size = other.streamed_payload_size;
            headers = std::move(other.headers);
            bearer_token_provider = std::move(other.bearer_token_provider);
            on_chunk_received = std::move(other.on_chunk_received);
            max_body_bytes = other.max_body_bytes;
            timeout_seconds = other.timeout_seconds;
            connect_timeout_seconds = other.connect_timeout_seconds;
            follow_redirects = other.follow_redirects;
            retry = other.retry;
            dns_fallback = std::move(other.dns_fallback);
        }
        return *this;
    }
    HttpRequest& operator=(const HttpRequest& other) {
        if (this != &other) {
            SecureWipe(url);
            SecureWipe(body);
            method = other.method;
            url = other.url;
            body = other.body;
            body_view = other.body_view;
            stream_payload_provider = other.stream_payload_provider;
            streamed_payload_size = other.streamed_payload_size;
            headers = other.headers;
            bearer_token_provider = other.bearer_token_provider;
            on_chunk_received = other.on_chunk_received;
            max_body_bytes = other.max_body_bytes;
            timeout_seconds = other.timeout_seconds;
            connect_timeout_seconds = other.connect_timeout_seconds;
            follow_redirects = other.follow_redirects;
            retry = other.retry;
            dns_fallback = other.dns_fallback;
        }
        return *this;
    }
    ~HttpRequest() {
        SecureWipe(url);
        SecureWipe(body);
    }

    HttpMethod method = HttpMethod::Get;
    DarkString url;
    SecureString body;
    std::string_view body_view;
    StreamPayloadCallback stream_payload_provider;
    std::size_t streamed_payload_size = 0;
    HeaderMap headers;
    TokenProvider bearer_token_provider;
    ChunkCallback on_chunk_received;
    // 0 means "no limit".
    std::size_t max_body_bytes = 0;
    long timeout_seconds = 15;
    long connect_timeout_seconds = 10;
    bool follow_redirects = false;
    RetryPolicy retry{};
    DnsFallbackPolicy dns_fallback{};
};

struct TransportTelemetry {
    double total_time_seconds = 0.0;
    DarkVector<DarkString> tls_chain;
};

enum class VerificationStatus : std::uint8_t {
    NotConfigured,
    Passed,
    Failed
};

struct HttpResponse {
    HttpResponse() = default;
    HttpResponse(const HttpResponse&) = default;
    HttpResponse& operator=(const HttpResponse& other) {
        if (this != &other) {
            ClearSensitiveData();
            status_code = other.status_code;
            body = other.body;
            headers = other.headers;
            telemetry = other.telemetry;
            transport_code = other.transport_code;
            transport_error = other.transport_error;
            verification_status = other.verification_status;
            verification_error = other.verification_error;
            dns_strategy_used = other.dns_strategy_used;
            streamed_body_bytes = other.streamed_body_bytes;
        }
        return *this;
    }
    HttpResponse(HttpResponse&& other) noexcept
        : status_code(other.status_code),
          body(std::move(other.body)),
          headers(std::move(other.headers)),
          telemetry(std::move(other.telemetry)),
          transport_code(other.transport_code),
          transport_error(other.transport_error),
          verification_status(other.verification_status),
          verification_error(other.verification_error),
          dns_strategy_used(std::move(other.dns_strategy_used)),
          streamed_body_bytes(other.streamed_body_bytes) {
        other.ClearSensitiveData();
    }
    HttpResponse& operator=(HttpResponse&& other) noexcept {
        if (this != &other) {
            ClearSensitiveData();
            status_code = other.status_code;
            body = std::move(other.body);
            headers = std::move(other.headers);
            telemetry = std::move(other.telemetry);
            transport_code = other.transport_code;
            transport_error = other.transport_error;
            verification_status = other.verification_status;
            verification_error = other.verification_error;
            dns_strategy_used = std::move(other.dns_strategy_used);
            streamed_body_bytes = other.streamed_body_bytes;
            other.ClearSensitiveData();
        }
        return *this;
    }
    ~HttpResponse() {
        ClearSensitiveData();
    }

    long status_code = 0;
    DarkString body;
    HeaderMap headers;
    TransportTelemetry telemetry;

    int transport_code = 0;
    ErrorCode transport_error = ErrorCode::None;

    VerificationStatus verification_status = VerificationStatus::NotConfigured;
    ErrorCode verification_error = ErrorCode::None;
    DarkString dns_strategy_used;
    std::size_t streamed_body_bytes = 0;

    bool TransportOk() const { return transport_code == 0 && transport_error == ErrorCode::None; }
    bool HttpOk() const { return status_code >= 200 && status_code < 400; }
    bool Ok() const {
        return TransportOk() && HttpOk() &&
            verification_status != VerificationStatus::Failed;
    }
    bool WasResponseVerified() const { return verification_status == VerificationStatus::Passed; }
    DarkString DnsStrategyDisplayName() const {
        return dns_strategy_used.empty() ? DarkString(BURNER_OBF_LITERAL("Default")) : dns_strategy_used;
    }

    void ClearSensitiveData() noexcept {
        SecureWipe(body);
        headers.clear();
        for (auto& line : telemetry.tls_chain) {
            SecureWipe(line);
        }
        telemetry.tls_chain.clear();
        telemetry.total_time_seconds = 0.0;
        SecureWipe(dns_strategy_used);
        streamed_body_bytes = 0;
    }
};

struct VerificationResult {
    ErrorCode error = ErrorCode::None;

    [[nodiscard]] bool Passed() const noexcept {
        return error == ErrorCode::None;
    }
};

struct HttpResponseView {
    explicit HttpResponseView(const HttpResponse& response) noexcept
        : status_code(response.status_code),
          body(response.body),
          headers(response.headers),
          telemetry(response.telemetry),
          transport_code(response.transport_code),
          transport_error(response.transport_error),
          dns_strategy_used(response.dns_strategy_used),
          streamed_body_bytes(response.streamed_body_bytes) {}

    long status_code = 0;
    std::string_view body;
    const HeaderMap& headers;
    const TransportTelemetry& telemetry;
    int transport_code = 0;
    ErrorCode transport_error = ErrorCode::None;
    std::string_view dns_strategy_used;
    std::size_t streamed_body_bytes = 0;
};

using ResponseVerifyFn =
    detail::CompactCallable<VerificationResult(const HttpRequest&, const HttpResponseView&)>;

struct ClientConfig {
    DarkString user_agent;
    bool verify_peer = true;
    bool verify_host = true;
    bool use_native_ca = true;
    bool use_system_proxy = false;

    HeaderMap default_headers;
    detail::CompactCallable<bool(MtlsCredentials& out)> mtls_provider;
    TokenProvider bearer_token_provider;
    RequestGuard request_guard;
    bool reject_loopback_peers = false;
    ConnectedPeerGuard connected_peer_guard;
    TransferCancellation transfer_cancellation;
    ResponseVerifyFn response_verifier;
    bool require_response_verification = false;
    std::size_t global_max_body_bytes = 0;
    DarkVector<DarkString> pinned_public_keys;
    DarkString curl_module_name;
    bool enable_stack_isolation = false;
};

} // namespace burner::net
