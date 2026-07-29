#if BURNER_ENABLE_CURL

#include "curl_http_client.h"

#include "curl_session.h"
#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/obfuscation.h"

#include <limits>

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

template <typename TValue>
bool SetCurlOption(const CurlApi& curl_api, CURL* easy, CURLoption option, TValue value) {
    return curl_api.easy_setopt(easy, option, value) == CURLE_OK;
}

ErrorCode SetPostBody(const CurlApi& curl_api, CURL* easy, const char* body_data, std::size_t body_size) {
    if (!SetCurlOption(
            curl_api,
            easy,
            static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDS))),
            body_data) ||
        !SetCurlOption(
            curl_api,
            easy,
            static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE_LARGE))),
            static_cast<curl_off_t>(body_size))) {
        return ErrorCode::CurlOptionFailed;
    }
    return ErrorCode::None;
}

} // namespace

ErrorCode CurlHttpClient::ApplyCommonOptions(
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
        return ErrorCode::NoCurlHandle;
    }

    const CurlApi& curl_api = m_session->Api();

    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_URL))), request.url.c_str()) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_ERRORBUFFER))), error_buffer)) {
        return ErrorCode::CurlOptionFailed;
    }
    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_WRITEFUNCTION))), &CurlHttpClient::WriteBodyCallback) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_WRITEDATA))), body_ctx) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HEADERFUNCTION))), &CurlHttpClient::WriteHeaderCallback) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HEADERDATA))), &response.headers) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_XFERINFOFUNCTION))), &CurlHttpClient::ProgressCallback) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_XFERINFODATA))), this) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOPROGRESS))), 0L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_FRESH_CONNECT))), 1L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_FORBID_REUSE))), 1L)) {
        return ErrorCode::CurlOptionFailed;
    }
    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_FOLLOWLOCATION))), request.follow_redirects ? 1L : 0L)) {
        return ErrorCode::CurlOptionFailed;
    }
    if (!m_config.use_system_proxy) {
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PROXY))), "") ||
        // Force all hosts to bypass proxies, including any inherited environment configuration.
            !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOPROXY))), "*")) {
            return ErrorCode::CurlOptionFailed;
        }
    }
    if (protocol_scheme != nullptr) {
        *protocol_scheme = BURNER_OBF_LITERAL("https");
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PROTOCOLS_STR))), protocol_scheme->c_str())) {
            return ErrorCode::CurlOptionFailed;
        }
    }
    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DISALLOW_USERNAME_IN_URL))), 1L)) {
        return ErrorCode::CurlOptionFailed;
    }
    if (request.follow_redirects) {
        if (redirect_protocol_scheme != nullptr) {
            *redirect_protocol_scheme = BURNER_OBF_LITERAL("https");
            if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_REDIR_PROTOCOLS_STR))), redirect_protocol_scheme->c_str())) {
                return ErrorCode::CurlOptionFailed;
            }
        }
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_MAXREDIRS))), 10L)) {
            return ErrorCode::CurlOptionFailed;
        }
    }
    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_TIMEOUT))), request.timeout_seconds) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CONNECTTIMEOUT))), request.connect_timeout_seconds)) {
        return ErrorCode::CurlOptionFailed;
    }

    if (user_agent_storage != nullptr) {
        *user_agent_storage = m_config.security_policy.GetUserAgent();
    }
    if (user_agent_storage != nullptr && !user_agent_storage->empty()) {
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_USERAGENT))), user_agent_storage->c_str())) {
            return ErrorCode::CurlOptionFailed;
        }
    } else if (!m_config.user_agent.empty()) {
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_USERAGENT))), m_config.user_agent.c_str())) {
            return ErrorCode::CurlOptionFailed;
        }
    }

    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_VERIFYPEER))), m_config.verify_peer ? 1L : 0L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_VERIFYHOST))), m_config.verify_host ? 2L : 0L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLVERSION))), CURL_SSLVERSION_TLSv1_2)) {
        return ErrorCode::CurlOptionFailed;
    }
    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CERTINFO))), 1L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_NOSIGNAL))), 1L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_SESSIONID_CACHE))), 0L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DNS_CACHE_TIMEOUT))), 0L) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CA_CACHE_TIMEOUT))), 0L)) {
        return ErrorCode::CurlOptionFailed;
    }
#ifdef CURLSSLOPT_NATIVE_CA
    if (m_config.use_native_ca) {
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSL_OPTIONS))), CURLSSLOPT_NATIVE_CA)) {
            return ErrorCode::CurlOptionFailed;
        }
    }
#endif
    if (!m_config.pinned_public_keys.empty()) {
        if (m_config.pinned_public_keys.size() >
            (std::numeric_limits<std::size_t>::max)() / 64u) {
            return ErrorCode::OutOfMemory;
        }
        DarkString pinned_keys;
        pinned_keys.reserve(m_config.pinned_public_keys.size() * 64);
        for (size_t i = 0; i < m_config.pinned_public_keys.size(); ++i) {
            pinned_keys += m_config.pinned_public_keys[i];
            if (i + 1 < m_config.pinned_public_keys.size()) {
                pinned_keys.push_back(';');
            }
        }
        const bool pin_set = SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PINNEDPUBLICKEY))), pinned_keys.c_str());
        SecureWipe(pinned_keys);
        if (!pin_set) {
            return ErrorCode::CurlOptionFailed;
        }
    }

    ErrorCode result = ClearDnsStrategy();
    if (strategy.has_value()) {
        result = result == ErrorCode::None ? ApplyDnsStrategy(*strategy) : result;
    }
    return result;
}

ErrorCode CurlHttpClient::ApplyMethodAndBody(
    const HttpRequest& request,
    DarkString* custom_method_storage,
    BodyReadContext* read_ctx) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return ErrorCode::NoCurlHandle;
    }

    const CurlApi& curl_api = m_session->Api();
    const bool has_streamed_body = static_cast<bool>(request.stream_payload_provider);
    const bool has_body_view = !request.body_view.empty();
    const char* body_data = has_body_view ? request.body_view.data() : request.body.c_str();
    const auto body_size = has_body_view ? request.body_view.size() : request.body.size();
    const bool has_body = has_streamed_body || has_body_view || !request.body.empty();

    auto apply_request_body = [&]() -> ErrorCode {
        if (has_streamed_body) {
            if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_READFUNCTION))), &CurlHttpClient::ReadBodyCallback) ||
                !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_READDATA))), read_ctx) ||
                !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POSTFIELDSIZE_LARGE))), static_cast<curl_off_t>(request.streamed_payload_size))) {
                return ErrorCode::CurlOptionFailed;
            }
        } else if (has_body_view || !request.body.empty()) {
            return SetPostBody(curl_api, easy, body_data, body_size);
        }
        return ErrorCode::None;
    };

    ErrorCode result = ErrorCode::None;
    switch (request.method) {
    case HttpMethod::Get:
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HTTPGET))), 1L)) {
            result = ErrorCode::CurlOptionFailed;
        }
        break;
    case HttpMethod::Post:
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_POST))), 1L)) {
            result = ErrorCode::CurlOptionFailed;
        } else {
            result = apply_request_body();
        }
        break;
    case HttpMethod::Put:
    case HttpMethod::Delete:
    case HttpMethod::Patch:
        if (custom_method_storage != nullptr) {
            *custom_method_storage = ToCurlMethod(request.method);
            if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_CUSTOMREQUEST))), custom_method_storage->c_str())) {
                result = ErrorCode::CurlOptionFailed;
            }
        }
        if (result == ErrorCode::None && has_body) {
            result = apply_request_body();
        }
        break;
    }
    return result;
}

ErrorCode CurlHttpClient::ApplyTlsOptions(DarkString* cert_type_storage, DarkString* key_type_storage) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return ErrorCode::NoCurlHandle;
    }

    MtlsCredentials credentials{};
    if (m_config.mtls_provider) {
        if (!m_config.mtls_provider(credentials)) {
            return ErrorCode::CredentialProviderFailed;
        }
    } else {
        credentials = m_config.mtls;
    }

    if (!credentials.enabled) {
        return ErrorCode::None;
    }
    if (credentials.cert_pem.empty() || credentials.key_pem.empty()) {
        return ErrorCode::InvalidCredentials;
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
    if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLCERT_BLOB))), &cert_blob) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLKEY_BLOB))), &key_blob) ||
        !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_KEYPASSWD))), credentials.key_password.c_str())) {
        return ErrorCode::CurlOptionFailed;
    }
    if (cert_type_storage != nullptr) {
        *cert_type_storage = BURNER_OBF_LITERAL("PEM");
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLCERTTYPE))), cert_type_storage->c_str())) {
            return ErrorCode::CurlOptionFailed;
        }
    }
    if (key_type_storage != nullptr) {
        *key_type_storage = BURNER_OBF_LITERAL("PEM");
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_SSLKEYTYPE))), key_type_storage->c_str())) {
            return ErrorCode::CurlOptionFailed;
        }
    }
    return ErrorCode::None;
}

ErrorCode CurlHttpClient::ApplyDnsStrategy(const DnsStrategy& strategy) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return ErrorCode::NoCurlHandle;
    }

    if (strategy.mode == DnsMode::Doh) {
        const CurlApi& curl_api = m_session->Api();
        if (!SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_URL))), strategy.doh_url.c_str()) ||
            !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_SSL_VERIFYPEER))), m_config.verify_peer ? 1L : 0L) ||
            !SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_SSL_VERIFYHOST))), m_config.verify_host ? 2L : 0L)) {
            return ErrorCode::CurlOptionFailed;
        }
    }
    return ErrorCode::None;
}

ErrorCode CurlHttpClient::ClearDnsStrategy() {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return ErrorCode::NoCurlHandle;
    }

    const CurlApi& curl_api = m_session->Api();
    return SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_DOH_URL))), nullptr) &&
        SetCurlOption(curl_api, easy, static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_RESOLVE))), nullptr)
        ? ErrorCode::None
        : ErrorCode::CurlOptionFailed;
}

} // namespace burner::net

#endif
