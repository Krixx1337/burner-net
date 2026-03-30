#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "export.h"
#include "error.h"
#include "obfuscation.h"
#include "policy.h"

namespace burner::net {

enum class HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch
};

using HeaderMap = std::map<std::string, std::string>;
using TokenProvider = std::function<bool(std::string& out)>;
using ChunkCallback = std::function<void(const uint8_t*, size_t)>;
using HeartbeatCallback = std::function<bool()>;
using BeforeRequestCallback = std::function<bool(const struct HttpRequest& request)>;
using PreFlightCallback = std::function<bool(const struct HttpRequest& request)>;
using ResponseReceivedCallback = std::function<bool(const struct HttpRequest& request, const struct HttpResponse& response)>;
using PostVerificationCallback = std::function<void(bool verified, ErrorCode reason)>;

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
    std::vector<DnsStrategy> strategies = {
        {DnsMode::Doh, BURNER_OBF_LITERAL("Cloudflare DoH (Strict)"), BURNER_OBF_LITERAL("https://1.1.1.1/dns-query")},
        {DnsMode::Doh, BURNER_OBF_LITERAL("Cloudflare DoH (Strict Secondary)"), BURNER_OBF_LITERAL("https://1.0.0.1/dns-query")}
    };
};

struct RetryPolicy {
    int max_attempts = 1;
    int backoff_ms = 250;
    bool retry_on_transport_error = true;
    bool retry_on_5xx = true;
};

struct MtlsCredentials {
    bool enabled = false;
    std::string cert_pem;
    std::string key_pem;
    std::string key_password;
};

struct HttpRequest {
    HttpMethod method = HttpMethod::Get;
    std::string url;
    std::string body;
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

class BURNER_API IResponseVerifier {
public:
    virtual ~IResponseVerifier() = default;
    virtual bool Verify(const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) = 0;
};

class BURNER_API IHttpClient {
public:
    virtual ~IHttpClient() = default;

    virtual HttpResponse Send(const HttpRequest& request) = 0;
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
    std::shared_ptr<IResponseVerifier> response_verifier;
    std::shared_ptr<ISecurityPolicy> security_policy;
    std::vector<std::string> pinned_public_keys;
    bool verify_curl_api_pointers = false;
    std::vector<std::wstring> trusted_curl_module_basenames = {
        L"libcurl.dll",
        L"libcurl-d.dll",
        L"libcurl-x64.dll",
        L"libcurl-x86.dll"
    };
};

struct ClientCreateResult {
    std::unique_ptr<IHttpClient> client;
    ErrorCode error = ErrorCode::None;

    bool Ok() const { return client != nullptr; }
};

BURNER_API ClientCreateResult CreateHttpClient(const ClientConfig& config);

} // namespace burner::net
