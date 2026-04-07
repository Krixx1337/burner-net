#if BURNER_ENABLE_CURL

#include "curl_http_client.h"

#include "curl_session.h"
#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/obfuscation.h"

namespace burner::net {
namespace {

DarkString ToCurlMethod(HttpMethod method) {
    switch (method) {
    case HttpMethod::Get: return DarkString(BURNER_OBF_LITERAL("GET"));
    case HttpMethod::Post: return DarkString(BURNER_OBF_LITERAL("POST"));
    case HttpMethod::Put: return DarkString(BURNER_OBF_LITERAL("PUT"));
    case HttpMethod::Delete: return DarkString(BURNER_OBF_LITERAL("DELETE"));
    case HttpMethod::Patch: return DarkString(BURNER_OBF_LITERAL("PATCH"));
    default: return DarkString(BURNER_OBF_LITERAL("GET"));
    }
}

void SetPostBody(const CurlApi& curl_api, CURL* easy, const char* body_data, std::size_t body_size) {
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDS))), body_data);
#ifdef CURLOPT_POSTFIELDSIZE_LARGE
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE_LARGE))), static_cast<curl_off_t>(body_size));
#else
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE))), static_cast<long>(body_size));
#endif
}

} // namespace

void CurlHttpClient::ApplyCommonOptions(
    const HttpRequest& request,
    HttpResponse& response,
    char* error_buffer,
    void* body_ctx,
    DarkString* protocol_scheme,
    DarkString* redirect_protocol_scheme,
    DarkString* user_agent_storage,
    const std::optional<DnsStrategy>& strategy) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    const CurlApi& curl_api = m_session->Api();
#ifndef CURLOPT_PROTOCOLS_STR
    (void)protocol_scheme;
#endif
#ifndef CURLOPT_REDIR_PROTOCOLS_STR
    (void)redirect_protocol_scheme;
#endif

    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_URL))), request.url.c_str());
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_ERRORBUFFER))), error_buffer);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_WRITEFUNCTION))), &CurlHttpClient::WriteBodyCallback);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_WRITEDATA))), body_ctx);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HEADERFUNCTION))), &CurlHttpClient::WriteHeaderCallback);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HEADERDATA))), &response.headers);
#ifdef CURLOPT_XFERINFOFUNCTION
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_XFERINFOFUNCTION))), &CurlHttpClient::ProgressCallback);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_XFERINFODATA))), this);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOPROGRESS))), 0L);
#endif
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_FOLLOWLOCATION))), request.follow_redirects ? 1L : 0L);
    if (!m_config.use_system_proxy) {
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PROXY))), "");
#ifdef CURLOPT_NOPROXY
        // Force all hosts to bypass proxies, including any inherited environment configuration.
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOPROXY))), "*");
#endif
    }
#ifdef CURLOPT_PROTOCOLS_STR
    if (protocol_scheme != nullptr) {
        *protocol_scheme = BURNER_OBF_LITERAL("https");
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PROTOCOLS_STR))), protocol_scheme->c_str());
    }
#elif defined(CURLOPT_PROTOCOLS)
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PROTOCOLS))), CURLPROTO_HTTPS);
#endif
#ifdef CURLOPT_DISALLOW_USERNAME_IN_URL
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DISALLOW_USERNAME_IN_URL))), 1L);
#endif
    if (request.follow_redirects) {
#ifdef CURLOPT_REDIR_PROTOCOLS_STR
        if (redirect_protocol_scheme != nullptr) {
            *redirect_protocol_scheme = BURNER_OBF_LITERAL("https");
            curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_REDIR_PROTOCOLS_STR))), redirect_protocol_scheme->c_str());
        }
#elif defined(CURLOPT_REDIR_PROTOCOLS)
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_REDIR_PROTOCOLS))), CURLPROTO_HTTPS);
#endif
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_MAXREDIRS))), 10L);
    }
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_TIMEOUT))), request.timeout_seconds);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CONNECTTIMEOUT))), request.connect_timeout_seconds);

    if (user_agent_storage != nullptr) {
        *user_agent_storage = m_config.security_policy.GetUserAgent();
    }
    if (user_agent_storage != nullptr && !user_agent_storage->empty()) {
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_USERAGENT))), user_agent_storage->c_str());
    } else if (!m_config.user_agent.empty()) {
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_USERAGENT))), m_config.user_agent.c_str());
    }

    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_VERIFYPEER))), m_config.verify_peer ? 1L : 0L);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_VERIFYHOST))), m_config.verify_host ? 2L : 0L);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLVERSION))), CURL_SSLVERSION_TLSv1_2);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CERTINFO))), 1L);
#ifdef CURLOPT_NOSIGNAL
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOSIGNAL))), 1L);
#endif
#ifdef CURLOPT_SSL_SESSIONID_CACHE
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_SESSIONID_CACHE))), 0L);
#endif
#ifdef CURLOPT_DNS_CACHE_TIMEOUT
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DNS_CACHE_TIMEOUT))), 0L);
#endif
#ifdef CURLOPT_CA_CACHE_TIMEOUT
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CA_CACHE_TIMEOUT))), 0L);
#endif
#ifdef CURLSSLOPT_NATIVE_CA
    if (m_config.use_native_ca) {
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_OPTIONS))), CURLSSLOPT_NATIVE_CA);
    }
#endif
    if (!m_config.pinned_public_keys.empty()) {
        DarkString pinned_keys;
        pinned_keys.reserve(m_config.pinned_public_keys.size() * 64);
        for (size_t i = 0; i < m_config.pinned_public_keys.size(); ++i) {
            pinned_keys += m_config.pinned_public_keys[i];
            if (i + 1 < m_config.pinned_public_keys.size()) {
                pinned_keys.push_back(';');
            }
        }
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PINNEDPUBLICKEY))), pinned_keys.c_str());
        SecureWipe(pinned_keys);
    }

    ClearDnsStrategy();
    if (strategy.has_value()) {
        ApplyDnsStrategy(*strategy);
    }
}

void CurlHttpClient::ApplyMethodAndBody(
    const HttpRequest& request,
    DarkString* custom_method_storage,
    BodyReadContext* read_ctx) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    const CurlApi& curl_api = m_session->Api();
    const bool has_streamed_body = static_cast<bool>(request.stream_payload_provider);
    const bool has_body_view = !request.body_view.empty();
    const char* body_data = has_body_view ? request.body_view.data() : request.body.c_str();
    const auto body_size = has_body_view ? request.body_view.size() : request.body.size();
    const bool has_body = has_streamed_body || has_body_view || !request.body.empty();

    auto apply_request_body = [&]() {
        if (has_streamed_body) {
            curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_READFUNCTION))), &CurlHttpClient::ReadBodyCallback);
            curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_READDATA))), read_ctx);
#ifdef CURLOPT_POSTFIELDSIZE_LARGE
            curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE_LARGE))), static_cast<curl_off_t>(request.streamed_payload_size));
#else
            curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE))), static_cast<long>(request.streamed_payload_size));
#endif
        } else if (has_body_view || !request.body.empty()) {
            SetPostBody(curl_api, easy, body_data, body_size);
        }
    };

    switch (request.method) {
    case HttpMethod::Get:
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HTTPGET))), 1L);
        break;
    case HttpMethod::Post:
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POST))), 1L);
        apply_request_body();
        break;
    case HttpMethod::Put:
    case HttpMethod::Delete:
    case HttpMethod::Patch:
        if (custom_method_storage != nullptr) {
            *custom_method_storage = ToCurlMethod(request.method);
            curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CUSTOMREQUEST))), custom_method_storage->c_str());
        }
        if (has_body) {
            apply_request_body();
        }
        break;
    }
}

void CurlHttpClient::ApplyTlsOptions(DarkString* cert_type_storage, DarkString* key_type_storage) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    MtlsCredentials credentials{};
    if (m_config.mtls_provider) {
        if (!m_config.mtls_provider(credentials)) {
            return;
        }
    } else {
        credentials = m_config.mtls;
    }

    if (!credentials.enabled) {
        return;
    }

    curl_blob cert_blob = {
        reinterpret_cast<void*>(const_cast<char*>(credentials.cert_pem.data())),
        credentials.cert_pem.size(),
        CURL_BLOB_COPY
    };
    curl_blob key_blob = {
        reinterpret_cast<void*>(const_cast<char*>(credentials.key_pem.data())),
        credentials.key_pem.size(),
        CURL_BLOB_COPY
    };

    const CurlApi& curl_api = m_session->Api();
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLCERT_BLOB))), &cert_blob);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLKEY_BLOB))), &key_blob);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_KEYPASSWD))), credentials.key_password.c_str());
    if (cert_type_storage != nullptr) {
        *cert_type_storage = BURNER_OBF_LITERAL("PEM");
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLCERTTYPE))), cert_type_storage->c_str());
    }
    if (key_type_storage != nullptr) {
        *key_type_storage = BURNER_OBF_LITERAL("PEM");
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLKEYTYPE))), key_type_storage->c_str());
    }
}

void CurlHttpClient::ApplyDnsStrategy(const DnsStrategy& strategy) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    if (strategy.mode == DnsMode::Doh) {
        const CurlApi& curl_api = m_session->Api();
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_URL))), strategy.doh_url.c_str());
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_SSL_VERIFYPEER))), m_config.verify_peer ? 1L : 0L);
        curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_SSL_VERIFYHOST))), m_config.verify_host ? 2L : 0L);
    }
}

void CurlHttpClient::ClearDnsStrategy() {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    m_session->Api().easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_URL))), nullptr);
}

void CurlHttpClient::ResetMethodState() {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    const CurlApi& curl_api = m_session->Api();
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HTTPGET))), 0L);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POST))), 0L);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CUSTOMREQUEST))), nullptr);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_READFUNCTION))), nullptr);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_READDATA))), nullptr);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDS))), nullptr);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE))), 0L);
#ifdef CURLOPT_POSTFIELDSIZE_LARGE
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE_LARGE))), static_cast<curl_off_t>(0));
#endif
#ifdef CURLOPT_XFERINFOFUNCTION
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_XFERINFOFUNCTION))), nullptr);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_XFERINFODATA))), nullptr);
    curl_api.easy_setopt(easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOPROGRESS))), 1L);
#endif
}

} // namespace burner::net

#endif
