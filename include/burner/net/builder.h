#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "curl/curl_http_client.h"
#include "export.h"
#include "http.h"

namespace burner::net {

template <typename TTransport>
class FluentClient;

template <typename TTransport>
class BURNER_API RequestBuilder {
public:
    RequestBuilder(FluentClient<TTransport>& client, HttpMethod method, std::string url)
        : m_client(&client) {
        m_request.method = method;
        m_request.url = std::move(url);
        m_request.dns_fallback.enabled = false;
        m_request.dns_fallback.strategies.clear();
    }

    RequestBuilder& WithHeader(std::string name, std::string value) {
        m_request.headers[std::move(name)] = std::move(value);
        return *this;
    }

    RequestBuilder& WithBody(std::string body) {
        m_request.body = std::move(body);
        return *this;
    }

    RequestBuilder& WithEphemeralToken(TokenProvider provider) {
        m_request.bearer_token_provider = std::move(provider);
        return *this;
    }

    RequestBuilder& OnChunkReceived(ChunkCallback callback) {
        m_request.on_chunk_received = std::move(callback);
        return *this;
    }

    RequestBuilder& WithTimeoutSeconds(long seconds) {
        m_request.timeout_seconds = seconds;
        return *this;
    }

    RequestBuilder& WithConnectTimeoutSeconds(long seconds) {
        m_request.connect_timeout_seconds = seconds;
        return *this;
    }

    RequestBuilder& FollowRedirects(bool enabled) {
        m_request.follow_redirects = enabled;
        return *this;
    }

    [[nodiscard]] HttpResponse Send() {
        return m_client->Send(std::move(m_request));
    }

private:
    FluentClient<TTransport>* m_client = nullptr;
    HttpRequest m_request;
};

template <typename TTransport>
class BURNER_API FluentClient {
public:
    FluentClient(TTransport transport, DnsFallbackPolicy default_dns_fallback)
        : m_transport(std::move(transport)),
          m_default_dns_fallback(std::move(default_dns_fallback)) {}

    [[nodiscard]] RequestBuilder<TTransport> Get(std::string url) {
        return RequestBuilder<TTransport>(*this, HttpMethod::Get, std::move(url));
    }

    [[nodiscard]] RequestBuilder<TTransport> Post(std::string url) {
        return RequestBuilder<TTransport>(*this, HttpMethod::Post, std::move(url));
    }

    [[nodiscard]] RequestBuilder<TTransport> Put(std::string url) {
        return RequestBuilder<TTransport>(*this, HttpMethod::Put, std::move(url));
    }

    [[nodiscard]] RequestBuilder<TTransport> Delete(std::string url) {
        return RequestBuilder<TTransport>(*this, HttpMethod::Delete, std::move(url));
    }

    [[nodiscard]] RequestBuilder<TTransport> Patch(std::string url) {
        return RequestBuilder<TTransport>(*this, HttpMethod::Patch, std::move(url));
    }

    [[nodiscard]] TTransport* Raw() { return &m_transport; }
    [[nodiscard]] const TTransport* Raw() const { return &m_transport; }

    [[nodiscard]] HttpResponse Send(HttpRequest request) {
        if (!request.dns_fallback.enabled && !m_default_dns_fallback.strategies.empty()) {
            request.dns_fallback = m_default_dns_fallback;
            request.dns_fallback.enabled = true;
        }
        return m_transport.Send(request);
    }

private:
    TTransport m_transport;
    DnsFallbackPolicy m_default_dns_fallback;
};

class BURNER_API ClientBuilder {
public:
    template <SecurityPolicyConcept TPolicy>
    ClientBuilder& WithSecurityPolicy(TPolicy policy) {
        m_security_policy = SecurityPolicy(std::move(policy));
        return *this;
    }

    template <ResponseVerifierConcept TVerifier>
    ClientBuilder& WithResponseVerifier(TVerifier verifier) {
        m_response_verifier = ResponseVerifier(std::move(verifier));
        return *this;
    }

    ClientBuilder& WithUserAgent(std::string user_agent);
    ClientBuilder& WithVerifyPeer(bool enabled);
    ClientBuilder& WithVerifyHost(bool enabled);
    ClientBuilder& WithUseNativeCa(bool enabled);
    ClientBuilder& WithMtls(MtlsCredentials creds);
    ClientBuilder& WithMtlsProvider(std::function<bool(MtlsCredentials&)> provider);
    ClientBuilder& WithBearerTokenProvider(TokenProvider provider);
    ClientBuilder& WithPreFlight(PreFlightCallback callback);
    ClientBuilder& WithEnvironmentCheck(EnvironmentCheckCallback callback);
    ClientBuilder& WithTransportCheck(TransportCheckCallback callback);
    ClientBuilder& WithHeartbeat(HeartbeatCallback heartbeat);
    ClientBuilder& WithResponseReceived(ResponseReceivedCallback callback);
    ClientBuilder& WithPostVerification(PostVerificationCallback callback);
    ClientBuilder& WithTamperAction(TamperActionCallback callback);
    ClientBuilder& WithGlobalMaxBodyLimit(std::size_t max_body_bytes);
    ClientBuilder& WithApiVerification(bool enabled);
    ClientBuilder& WithTrustedCurlModules(std::vector<std::wstring> modules);
    ClientBuilder& WithCasualDefaults();
    ClientBuilder& AllowSystemDns(bool fallback_allowed = true);
    ClientBuilder& WithDnsFallback(DnsMode mode, std::string value, std::string name = {});
    ClientBuilder& WithPinnedKey(std::string pin);

    struct ClientBuildResult {
        std::shared_ptr<FluentClient<CurlHttpClient>> client;
        ErrorCode error = ErrorCode::None;

        [[nodiscard]] bool Ok() const { return client != nullptr; }
    };

    [[nodiscard]] ClientBuildResult Build();

private:
    ClientConfig m_config;
    SecurityPolicy m_security_policy;
    ResponseVerifier m_response_verifier;
    PreFlightCallback m_pre_flight;
    EnvironmentCheckCallback m_environment_check;
    TransportCheckCallback m_transport_check;
    HeartbeatCallback m_heartbeat;
    ResponseReceivedCallback m_response_received;
    PostVerificationCallback m_post_verification;
    TamperActionCallback m_tamper_action;
    DnsFallbackPolicy m_default_dns_fallback;
    bool m_custom_dns_fallback = false;
};

} // namespace burner::net
