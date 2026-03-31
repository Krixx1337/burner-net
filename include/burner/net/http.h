#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "concepts.h"
#include "detail/dark_callables.h"
#include "detail/dark_hashing.h"
#include "detail/memory_hygiene.h"
#include "export.h"
#include "error.h"
#include "obfuscation.h"
#include "policy.h"

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

    HeaderMap& operator=(const HeaderMap&) = default;
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
using PreFlightCallback = detail::CompactCallable<bool(const struct HttpRequest& request)>;
using EnvironmentCheckCallback = detail::CompactCallable<bool()>;
using TransportCheckCallback = detail::CompactCallable<bool(const char* url, const char* remote_ip)>;
using ResponseReceivedCallback = detail::CompactCallable<bool(const struct HttpRequest& request, const struct HttpResponse& response)>;
using ResponseVerifyFn = detail::CompactCallable<bool(const struct HttpRequest& request, const struct HttpResponse& response, ErrorCode* reason)>;
using PostVerificationCallback = detail::CompactCallable<void(bool verified, ErrorCode reason)>;
using TamperActionCallback = detail::CompactCallable<void()>;

struct TransferProgress {
    long long dl_total = 0;
    long long dl_now = 0;
    long long ul_total = 0;
    long long ul_now = 0;
};

using HeartbeatCallback = detail::CompactCallable<bool(const TransferProgress&)>;

enum class DnsMode {
    System,
    Doh
};

struct DnsStrategy {
    DnsMode mode = DnsMode::System;
    DarkString name;
    DarkString doh_url;
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
    HttpMethod method = HttpMethod::Get;
    DarkString url;
    SecureString body;
    std::string_view body_view;
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

struct HttpResponse {
    long status_code = 0;
    DarkString body;
    HeaderMap headers;

    int transport_code = 0;
    ErrorCode transport_error = ErrorCode::None;

    bool verified = true;
    ErrorCode verification_error = ErrorCode::None;
    DarkString dns_strategy_used;
    std::size_t streamed_body_bytes = 0;

    bool TransportOk() const { return transport_code == 0 && transport_error == ErrorCode::None; }
    bool HttpOk() const { return status_code >= 200 && status_code < 400; }
    bool Ok() const { return TransportOk() && HttpOk() && verified; }
    DarkString DnsStrategyDisplayName() const {
        return dns_strategy_used.empty() ? DarkString(BURNER_OBF_LITERAL("Default")) : dns_strategy_used;
    }
};

struct BURNER_API IResponseVerifier {
    bool Verify(const HttpRequest&, const HttpResponse&, ErrorCode* reason) const {
        if (reason != nullptr) {
            *reason = ErrorCode::VerifyGeneric;
        }
        return false;
    }
};

class BURNER_API ResponseVerifier {
public:
    ResponseVerifier() = default;
    ResponseVerifier(ResponseVerifyFn verifier) {
        emplace_lambda(std::move(verifier));
    }

    template <ResponseVerifierConcept TVerifier>
    ResponseVerifier(TVerifier verifier) {
        emplace(std::move(verifier));
    }

    [[nodiscard]] bool Enabled() const noexcept {
        return static_cast<bool>(m_state);
    }

    [[nodiscard]] bool Verify(const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) const {
        return m_verify(m_state.get(), request, response, reason);
    }

private:
    struct LambdaVerifier final {
        ResponseVerifyFn fn;

        bool Verify(const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) const {
            return fn(request, response, reason);
        }
    };

    void emplace_lambda(ResponseVerifyFn verifier) {
        emplace(LambdaVerifier{std::move(verifier)});
    }

    template <ResponseVerifierConcept TVerifier>
    void emplace(TVerifier verifier) {
        using VerifierType = std::decay_t<TVerifier>;

        m_state = detail::SecureHandle<const void>::template make<VerifierType>(std::move(verifier));
        m_verify = [](const void* raw, const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) {
            return static_cast<const VerifierType*>(raw)->Verify(request, response, reason);
        };
    }

    detail::SecureHandle<const void> m_state;
    bool (*m_verify)(const void*, const HttpRequest&, const HttpResponse&, ErrorCode*) = nullptr;
};

struct ClientConfig {
    DarkString user_agent;
    bool verify_peer = true;
    bool verify_host = true;
    bool use_native_ca = true;
    bool use_system_proxy = false;

    HeaderMap default_headers;
    MtlsCredentials mtls{};
    detail::CompactCallable<bool(MtlsCredentials& out)> mtls_provider;
    TokenProvider bearer_token_provider;
    ResponseVerifier response_verifier;
    SecurityPolicy security_policy;
    std::size_t global_max_body_bytes = 0;
    DarkVector<DarkString> pinned_public_keys;
    DarkString curl_module_name;
};

} // namespace burner::net
