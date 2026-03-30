#include "burner/net/builder.h"
#include "burner/net/obfuscation.h"
#include "burner/net/detail/constexpr_obfuscation.h"

namespace burner::net {

namespace detail {

class BuilderSecurityPolicy final : public DefaultSecurityPolicy {
public:
    BeforeRequestCallback before_request;
    PreFlightCallback pre_flight;
    HeartbeatCallback heartbeat;
    ResponseReceivedCallback response_received;
    PostVerificationCallback post_verification;

    bool OnPreRequest(HttpRequest& request) const override {
        if (pre_flight && !pre_flight(request)) {
            return false;
        }
        if (before_request && !before_request(request)) {
            return false;
        }
        return true;
    }

    bool OnHeartbeat() const override {
        return !heartbeat || heartbeat();
    }

    bool OnResponseReceived(const HttpRequest& request, const HttpResponse& response) const override {
        return !response_received || response_received(request, response);
    }

    void OnSignatureVerified(bool success, ErrorCode reason) const override {
        if (post_verification) {
            post_verification(success, reason);
        }
    }
};

std::uint32_t ErrorXorKey() noexcept {
    static constinit const std::uint32_t key = ::burner::net::obf::build_error_xor_key();
    return key;
}

BuilderSecurityPolicy& EnsureBuilderSecurityPolicy(ClientConfig& config) {
    if (auto* existing = dynamic_cast<BuilderSecurityPolicy*>(config.security_policy.get())) {
        return *existing;
    }

    auto policy = std::make_shared<BuilderSecurityPolicy>();
    config.security_policy = policy;
    return *policy;
}

} // namespace detail

RequestBuilder::RequestBuilder(FluentClient& client, HttpMethod method, std::string url)
    : m_client(&client) {
    m_request.method = method;
    m_request.url = std::move(url);
    // Fluent requests inherit the client policy unless the caller later sets a per-request policy explicitly.
    m_request.dns_fallback.enabled = false;
    m_request.dns_fallback.strategies.clear();
}

RequestBuilder& RequestBuilder::WithHeader(std::string name, std::string value) {
    m_request.headers[std::move(name)] = std::move(value);
    return *this;
}

RequestBuilder& RequestBuilder::WithBody(std::string body) {
    m_request.body = std::move(body);
    return *this;
}

RequestBuilder& RequestBuilder::WithEphemeralToken(TokenProvider provider) {
    m_request.bearer_token_provider = std::move(provider);
    return *this;
}

RequestBuilder& RequestBuilder::OnChunkReceived(ChunkCallback callback) {
    m_request.on_chunk_received = std::move(callback);
    return *this;
}

RequestBuilder& RequestBuilder::WithTimeoutSeconds(long seconds) {
    m_request.timeout_seconds = seconds;
    return *this;
}

RequestBuilder& RequestBuilder::WithConnectTimeoutSeconds(long seconds) {
    m_request.connect_timeout_seconds = seconds;
    return *this;
}

RequestBuilder& RequestBuilder::FollowRedirects(bool enabled) {
    m_request.follow_redirects = enabled;
    return *this;
}

HttpResponse RequestBuilder::Send() {
    return m_client->Send(std::move(m_request));
}

FluentClient::FluentClient(std::unique_ptr<IHttpClient> transport, DnsFallbackPolicy default_dns_fallback)
    : m_transport(std::move(transport)),
      m_default_dns_fallback(std::move(default_dns_fallback)) {}

RequestBuilder FluentClient::Get(std::string url) {
    return RequestBuilder(*this, HttpMethod::Get, std::move(url));
}

RequestBuilder FluentClient::Post(std::string url) {
    return RequestBuilder(*this, HttpMethod::Post, std::move(url));
}

RequestBuilder FluentClient::Put(std::string url) {
    return RequestBuilder(*this, HttpMethod::Put, std::move(url));
}

RequestBuilder FluentClient::Delete(std::string url) {
    return RequestBuilder(*this, HttpMethod::Delete, std::move(url));
}

RequestBuilder FluentClient::Patch(std::string url) {
    return RequestBuilder(*this, HttpMethod::Patch, std::move(url));
}

HttpResponse FluentClient::Send(HttpRequest request) {
    if (!request.dns_fallback.enabled && !m_default_dns_fallback.strategies.empty()) {
        request.dns_fallback = m_default_dns_fallback;
        request.dns_fallback.enabled = true;
    }
    return m_transport->Send(request);
}

ClientBuilder& ClientBuilder::WithUserAgent(std::string user_agent) {
    m_config.user_agent = std::move(user_agent);
    return *this;
}

ClientBuilder& ClientBuilder::WithVerifyPeer(bool enabled) {
    m_config.verify_peer = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithVerifyHost(bool enabled) {
    m_config.verify_host = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithUseNativeCa(bool enabled) {
    m_config.use_native_ca = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithMtls(MtlsCredentials creds) {
    m_config.mtls = std::move(creds);
    return *this;
}

ClientBuilder& ClientBuilder::WithMtlsProvider(std::function<bool(MtlsCredentials&)> provider) {
    m_config.mtls_provider = std::move(provider);
    return *this;
}

ClientBuilder& ClientBuilder::WithBearerTokenProvider(TokenProvider provider) {
    m_config.bearer_token_provider = std::move(provider);
    return *this;
}

ClientBuilder& ClientBuilder::WithBeforeRequest(BeforeRequestCallback callback) {
    detail::EnsureBuilderSecurityPolicy(m_config).before_request = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithPreFlight(PreFlightCallback callback) {
    detail::EnsureBuilderSecurityPolicy(m_config).pre_flight = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithResponseVerifier(std::shared_ptr<IResponseVerifier> verifier) {
    m_config.response_verifier = std::move(verifier);
    return *this;
}

ClientBuilder& ClientBuilder::WithHeartbeat(HeartbeatCallback heartbeat) {
    detail::EnsureBuilderSecurityPolicy(m_config).heartbeat = std::move(heartbeat);
    return *this;
}

ClientBuilder& ClientBuilder::WithResponseReceived(ResponseReceivedCallback callback) {
    detail::EnsureBuilderSecurityPolicy(m_config).response_received = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithPostVerification(PostVerificationCallback callback) {
    detail::EnsureBuilderSecurityPolicy(m_config).post_verification = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithSecurityPolicy(std::shared_ptr<ISecurityPolicy> policy) {
    m_config.security_policy = std::move(policy);
    return *this;
}

ClientBuilder& ClientBuilder::WithApiVerification(bool enabled) {
#if BURNER_ENABLE_CURL
    m_config.verify_curl_api_pointers = enabled;
#else
    (void)enabled;
#endif
    return *this;
}

ClientBuilder& ClientBuilder::WithTrustedCurlModules(std::vector<std::wstring> modules) {
    m_config.trusted_curl_module_basenames = std::move(modules);
    return *this;
}

ClientBuilder& ClientBuilder::WithCasualDefaults() {
    m_config.use_system_proxy = true;
    m_config.use_native_ca = true;
    m_config.verify_peer = true;
    m_config.verify_host = true;

    m_default_dns_fallback.enabled = true;
    m_default_dns_fallback.strategies.clear();
    m_default_dns_fallback.strategies.push_back({DnsMode::System, BURNER_OBF_LITERAL("System DNS"), {}});
    m_custom_dns_fallback = true;
    return *this;
}

ClientBuilder& ClientBuilder::AllowSystemDns(bool fallback_allowed) {
    if (!fallback_allowed) {
        return *this;
    }

    bool has_system = false;
    for (const auto& strategy : m_default_dns_fallback.strategies) {
        if (strategy.mode == DnsMode::System) {
            has_system = true;
            break;
        }
    }

    if (!has_system) {
        m_default_dns_fallback.strategies.push_back(
            {DnsMode::System, BURNER_OBF_LITERAL("System DNS Insecure"), {}});
    }
    m_default_dns_fallback.enabled = true;
    return *this;
}

ClientBuilder& ClientBuilder::WithDnsFallback(DnsMode mode, std::string value, std::string name) {
    if (!m_custom_dns_fallback) {
        m_default_dns_fallback.strategies.clear();
        m_custom_dns_fallback = true;
    }

    DnsStrategy strategy{};
    strategy.mode = mode;
    strategy.doh_url = std::move(value);
    if (!name.empty()) {
        strategy.name = std::move(name);
    } else if (mode == DnsMode::Doh) {
        strategy.name = BURNER_OBF_LITERAL("DoH Custom");
    } else {
        strategy.name = BURNER_OBF_LITERAL("System DNS Insecure");
    }
    m_default_dns_fallback.enabled = true;
    m_default_dns_fallback.strategies.push_back(std::move(strategy));
    return *this;
}

ClientBuilder& ClientBuilder::WithPinnedKey(std::string pin) {
    m_config.pinned_public_keys.push_back(std::move(pin));
    return *this;
}

ClientBuilder::ClientBuildResult ClientBuilder::Build() {
    m_config.security_policy = ResolveSecurityPolicy(std::move(m_config.security_policy));
    ClientCreateResult created = CreateHttpClient(m_config);
    if (!created.Ok()) {
        return {nullptr, created.error};
    }
    return {std::make_unique<FluentClient>(std::move(created.client), m_default_dns_fallback), ErrorCode::None};
}

} // namespace burner::net
