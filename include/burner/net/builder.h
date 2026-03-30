#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "export.h"
#include "http.h"

namespace burner::net {

class FluentClient;

class BURNER_API RequestBuilder {
public:
    RequestBuilder(FluentClient& client, HttpMethod method, std::string url);

    RequestBuilder& WithHeader(std::string name, std::string value);
    RequestBuilder& WithBody(std::string body);
    RequestBuilder& WithEphemeralToken(TokenProvider provider);
    RequestBuilder& OnChunkReceived(ChunkCallback callback);
    RequestBuilder& WithTimeoutSeconds(long seconds);
    RequestBuilder& WithConnectTimeoutSeconds(long seconds);
    RequestBuilder& FollowRedirects(bool enabled);

    HttpResponse Send();

private:
    FluentClient* m_client = nullptr;
    HttpRequest m_request;
};

class BURNER_API FluentClient {
public:
    FluentClient(std::unique_ptr<IHttpClient> transport, DnsFallbackPolicy default_dns_fallback);

    RequestBuilder Get(std::string url);
    RequestBuilder Post(std::string url);
    RequestBuilder Put(std::string url);
    RequestBuilder Delete(std::string url);
    RequestBuilder Patch(std::string url);

    IHttpClient* Raw() const { return m_transport.get(); }
    HttpResponse Send(HttpRequest request);

private:
    std::unique_ptr<IHttpClient> m_transport;
    DnsFallbackPolicy m_default_dns_fallback;
};

class BURNER_API ClientBuilder {
public:
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
    ClientBuilder& WithResponseVerifier(std::shared_ptr<IResponseVerifier> verifier);
    ClientBuilder& WithHeartbeat(HeartbeatCallback heartbeat);
    ClientBuilder& WithResponseReceived(ResponseReceivedCallback callback);
    ClientBuilder& WithPostVerification(PostVerificationCallback callback);
    ClientBuilder& WithSecurityPolicy(std::shared_ptr<ISecurityPolicy> policy);
    ClientBuilder& WithGlobalMaxBodyLimit(std::size_t max_body_bytes);
    ClientBuilder& WithApiVerification(bool enabled);
    ClientBuilder& WithTrustedCurlModules(std::vector<std::wstring> modules);
    ClientBuilder& WithCasualDefaults();
    ClientBuilder& AllowSystemDns(bool fallback_allowed = true);
    ClientBuilder& WithDnsFallback(DnsMode mode, std::string value, std::string name = {});
    ClientBuilder& WithPinnedKey(std::string pin);

    struct ClientBuildResult {
        std::unique_ptr<FluentClient> client;
        ErrorCode error = ErrorCode::None;

        bool Ok() const { return client != nullptr; }
    };

    ClientBuildResult Build();

private:
    ClientConfig m_config;
    DnsFallbackPolicy m_default_dns_fallback;
    bool m_custom_dns_fallback = false;
};

} // namespace burner::net
