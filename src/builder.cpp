#include "burner/net/builder.h"

#include "curl/curl_http_client.h"

namespace burner::net {

namespace detail {

struct BuilderSecurityPolicy final {
    SecurityPolicy wrapped_policy;
    PreFlightCallback pre_flight;
    EnvironmentCheckCallback environment_check;
    TransportCheckCallback transport_check;
    HeartbeatCallback heartbeat;
    ResponseReceivedCallback response_received;
    PostVerificationCallback post_verification;
    TamperActionCallback tamper_action;

    bool OnVerifyEnvironment() const {
        if (environment_check && !environment_check()) {
            return false;
        }
        return wrapped_policy.OnVerifyEnvironment();
    }

    bool OnPreRequest(HttpRequest& request) const {
        if (pre_flight && !pre_flight(request)) {
            return false;
        }
        return wrapped_policy.OnPreRequest(request);
    }

    bool OnVerifyTransport(const char* url, const char* remote_ip) const {
        if (transport_check && !transport_check(url, remote_ip)) {
            return false;
        }
        return wrapped_policy.OnVerifyTransport(url, remote_ip);
    }

    bool OnHeartbeat(const TransferProgress& progress) const {
        if (heartbeat && !heartbeat(progress)) {
            return false;
        }
        return wrapped_policy.OnHeartbeat(progress);
    }

    bool OnResponseReceived(const HttpRequest& request, const HttpResponse& response) const {
        if (response_received && !response_received(request, response)) {
            return false;
        }
        return wrapped_policy.OnResponseReceived(request, response);
    }

    void OnSignatureVerified(bool success, ErrorCode reason) const {
        if (post_verification) {
            post_verification(success, reason);
        }
        wrapped_policy.OnSignatureVerified(success, reason);
    }

    void OnTamper() const {
        if (tamper_action) {
            tamper_action();
        }
        wrapped_policy.OnTamper();
    }

    void OnError(ErrorCode code, const char* url) const {
        wrapped_policy.OnError(code, url);
    }

    std::string GetUserAgent() const {
        return wrapped_policy.GetUserAgent();
    }
};

} // namespace detail

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

ClientBuilder& ClientBuilder::WithPreFlight(PreFlightCallback callback) {
    m_pre_flight = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithEnvironmentCheck(EnvironmentCheckCallback callback) {
    m_environment_check = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithTransportCheck(TransportCheckCallback callback) {
    m_transport_check = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithHeartbeat(HeartbeatCallback heartbeat) {
    m_heartbeat = std::move(heartbeat);
    return *this;
}

ClientBuilder& ClientBuilder::WithResponseReceived(ResponseReceivedCallback callback) {
    m_response_received = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithPostVerification(PostVerificationCallback callback) {
    m_post_verification = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithTamperAction(TamperActionCallback callback) {
    m_tamper_action = std::move(callback);
    return *this;
}

ClientBuilder& ClientBuilder::WithGlobalMaxBodyLimit(std::size_t max_body_bytes) {
    m_config.global_max_body_bytes = max_body_bytes;
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
    ClientConfig config = m_config;
    config.security_policy = SecurityPolicy(detail::BuilderSecurityPolicy{
        .wrapped_policy = m_security_policy,
        .pre_flight = m_pre_flight,
        .environment_check = m_environment_check,
        .transport_check = m_transport_check,
        .heartbeat = m_heartbeat,
        .response_received = m_response_received,
        .post_verification = m_post_verification,
        .tamper_action = m_tamper_action,
    });
    config.response_verifier = m_response_verifier;

    if (!config.security_policy.OnVerifyEnvironment()) {
        return {nullptr, ErrorCode::EnvironmentCompromised};
    }

    CurlHttpClient transport(config);
    if (!transport.IsInitialized()) {
        return {nullptr, transport.InitError()};
    }

    return {std::make_shared<FluentClient<CurlHttpClient>>(std::move(transport), m_default_dns_fallback), ErrorCode::None};
}

} // namespace burner::net

