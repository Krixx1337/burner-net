#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "concepts.h"
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

    for (std::size_t i = 0; i < lhs.size(); ++i) {
        const auto lhs_ch = static_cast<unsigned char>(lhs[i]);
        const auto rhs_ch = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(lhs_ch) != std::tolower(rhs_ch)) {
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
    using value_type = std::pair<std::string, std::string>;
    using storage_type = std::vector<value_type>;
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

    std::string& operator[](std::string key) {
        if (auto* existing = find_value(key)) {
            return *existing;
        }

        m_items.emplace_back(std::move(key), std::string{});
        return m_items.back().second;
    }

    void insert_or_assign(std::string key, std::string value) {
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
    std::string* find_value(const std::string& key) noexcept {
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
using TokenProvider = std::function<bool(std::string& out)>;
using ChunkCallback = std::function<void(const uint8_t*, size_t)>;
using PreFlightCallback = std::function<bool(const struct HttpRequest& request)>;
using EnvironmentCheckCallback = std::function<bool()>;
using TransportCheckCallback = std::function<bool(const char* url, const char* remote_ip)>;
using ResponseReceivedCallback = std::function<bool(const struct HttpRequest& request, const struct HttpResponse& response)>;
using ResponseVerifyFn = std::function<bool(const struct HttpRequest& request, const struct HttpResponse& response, ErrorCode* reason)>;
using PostVerificationCallback = std::function<void(bool verified, ErrorCode reason)>;
using TamperActionCallback = std::function<void()>;

struct TransferProgress {
    long long dl_total = 0;
    long long dl_now = 0;
    long long ul_total = 0;
    long long ul_now = 0;
};

using HeartbeatCallback = std::function<bool(const TransferProgress&)>;

enum class DnsMode {
    System,
    Doh
};

struct DnsStrategy {
    DnsMode mode = DnsMode::System;
    std::string name = BURNER_OBF_LITERAL("System DNS");
    std::string doh_url;
};

struct DnsFallbackPolicy {
    bool enabled = true;
    std::vector<DnsStrategy> strategies;
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
    std::string url;
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
    std::string body;
    HeaderMap headers;

    int transport_code = 0;
    ErrorCode transport_error = ErrorCode::None;

    bool verified = true;
    ErrorCode verification_error = ErrorCode::None;
    std::string dns_strategy_used;
    std::size_t streamed_body_bytes = 0;

    bool TransportOk() const { return transport_code == 0 && transport_error == ErrorCode::None; }
    bool HttpOk() const { return status_code >= 200 && status_code < 400; }
    bool Ok() const { return TransportOk() && HttpOk() && verified; }
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
        return m_state != nullptr;
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

        auto state = std::make_shared<VerifierType>(std::move(verifier));
        m_state = state;
        m_verify = [](const void* raw, const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) {
            return static_cast<const VerifierType*>(raw)->Verify(request, response, reason);
        };
    }

    std::shared_ptr<const void> m_state;
    bool (*m_verify)(const void*, const HttpRequest&, const HttpResponse&, ErrorCode*) = nullptr;
};

struct ClientConfig {
    std::string user_agent;
    bool verify_peer = true;
    bool verify_host = true;
    bool use_native_ca = true;
    bool use_system_proxy = false;

    HeaderMap default_headers;
    MtlsCredentials mtls{};
    std::function<bool(MtlsCredentials& out)> mtls_provider;
    TokenProvider bearer_token_provider;
    ResponseVerifier response_verifier;
    SecurityPolicy security_policy;
    std::size_t global_max_body_bytes = 0;
    std::vector<std::string> pinned_public_keys;
    bool verify_curl_api_pointers = false;
    std::vector<std::wstring> trusted_curl_module_basenames = {
        L"libcurl.dll",
        L"libcurl-d.dll",
        L"libcurl-x64.dll",
        L"libcurl-x86.dll"
    };
};

} // namespace burner::net
