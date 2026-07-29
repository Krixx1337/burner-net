#pragma once

#include <memory>
#include <string>
#include <string_view>
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
        m_request.body_view = {};
        m_request.stream_payload_provider = {};
        m_request.streamed_payload_size = 0;
        return *this;
    }

    RequestBuilder& WithBodyView(std::string_view view) {
        m_request.body_view = view;
        m_request.body.clear();
        m_request.stream_payload_provider = {};
        m_request.streamed_payload_size = 0;
        return *this;
    }

    RequestBuilder& WithStreamedBody(std::size_t total_size, StreamPayloadCallback provider) {
        m_request.streamed_payload_size = total_size;
        m_request.stream_payload_provider = std::move(provider);
        m_request.body.clear();
        m_request.body_view = {};
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

    FluentClient(TTransport transport, DnsFallbackPolicy default_dns_fallback, ErrorCode unavailable_error)
        : m_transport(std::move(transport)),
          m_default_dns_fallback(std::move(default_dns_fallback)),
          m_unavailable_error(unavailable_error) {}

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
        if (m_unavailable_error != ErrorCode::None) {
            HttpResponse response{};
            response.transport_code = static_cast<int>(CURLE_FAILED_INIT);
            response.transport_error = m_unavailable_error;
            return response;
        }
        if (!request.dns_fallback.enabled && !m_default_dns_fallback.strategies.empty()) {
            request.dns_fallback = m_default_dns_fallback;
            request.dns_fallback.enabled = true;
        }
        return m_transport.Send(request);
    }

private:
    TTransport m_transport;
    DnsFallbackPolicy m_default_dns_fallback;
    ErrorCode m_unavailable_error = ErrorCode::None;
};

enum class ClientProfile {
    Standard,
    Hardened
};

class BURNER_API ClientBuilder {
public:
    using ResponseVerifyFn = burner::net::ResponseVerifyFn;

    ClientBuilder& WithResponseVerifier(ResponseVerifyFn verifier) {
        m_config.response_verifier = std::move(verifier);
        return *this;
    }

    ClientBuilder& WithUserAgent(std::string user_agent);
    ClientBuilder& WithVerifyPeer(bool enabled);
    ClientBuilder& WithVerifyHost(bool enabled);
    ClientBuilder& WithUseNativeCa(bool enabled);
    ClientBuilder& WithMtlsProvider(detail::CompactCallable<bool(MtlsCredentials&)> provider);
    ClientBuilder& WithBearerTokenProvider(TokenProvider provider);
    ClientBuilder& WithRequestGuard(RequestGuard guard);
    ClientBuilder& WithLoopbackPeerRejection(bool enabled = true);
    ClientBuilder& WithConnectedPeerGuard(ConnectedPeerGuard guard);
    ClientBuilder& WithTransferCancellation(TransferCancellation cancellation);
    ClientBuilder& WithGlobalMaxBodyLimit(std::size_t max_body_bytes);
    ClientBuilder& WithCurlModuleName(std::string name);
    ClientBuilder& WithCasualDefaults();
    ClientBuilder& AllowSystemDns(bool fallback_allowed = true);
    ClientBuilder& WithDnsFallback(
        DnsMode mode,
        std::string value,
        std::string name = {},
        std::string bootstrap_resolve_entry = {});
    ClientBuilder& WithPinnedKey(std::string pin);
    ClientBuilder& WithStackIsolation(bool enabled);

    struct ClientBuildResult {
        std::unique_ptr<FluentClient<CurlHttpClient>> client;
        ErrorCode error = ErrorCode::None;

        [[nodiscard]] bool Ok() const { return client != nullptr; }
    };

    ClientBuilder();
    explicit ClientBuilder(ClientProfile profile);

    [[nodiscard]] ClientBuildResult Build();

private:
    ClientConfig m_config;
    DnsFallbackPolicy m_default_dns_fallback;
    ClientProfile m_profile = ClientProfile::Standard;
    bool m_custom_dns_fallback = false;
    bool m_system_dns_explicit = false;
};

} // namespace burner::net
