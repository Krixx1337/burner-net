#if BURNER_ENABLE_CURL

#include "curl_http_client.h"

#include "curl_http_client_internal.h"
#include "curl_session.h"
#include "transport_orchestrator.h"
#include "burner/net/obfuscation.h"
#include "../internal/header_validation.h"

#include <algorithm>
#include <cctype>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#endif

namespace burner::net {

namespace detail {

bool WouldExceedBodyLimit(std::size_t current_size, std::size_t chunk_size, std::size_t max_body_bytes) noexcept {
    if (max_body_bytes == 0) {
        return false;
    }

    return current_size > max_body_bytes || chunk_size > (max_body_bytes - current_size);
}

} // namespace detail

namespace {

bool IsAuthorizationHeaderName(std::string_view name) {
    if (name.size() != 13) {
        return false;
    }
    std::string auth = BURNER_OBF_LITERAL("authorization");
    for (size_t i = 0; i < name.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(name[i]);
        if (static_cast<char>(std::tolower(ch)) != auth[i]) {
            SecureWipe(auth);
            return false;
        }
    }
    SecureWipe(auth);
    return true;
}

bool HasAuthorizationHeader(const HeaderMap& headers) {
    for (const auto& [name, value] : headers) {
        if (IsAuthorizationHeaderName(name) && !value.empty()) {
            return true;
        }
    }
    return false;
}

bool RequestBodyTooLargeForCurl(std::size_t body_size) {
    return body_size > static_cast<std::size_t>((std::numeric_limits<long>::max)());
}

std::string BuildHeaderLine(std::string_view name, std::string_view value) {
    std::string header;
    header.reserve(name.size() + 2 + value.size());
    header.append(name);
    header.append(": ");
    header.append(value);
    return header;
}

} // namespace

CurlHttpClient::CurlHttpClient(const ClientConfig& config)
    : m_config(config) {
    m_session = CreateCurlSession(m_config, &m_init_error);
}

CurlHttpClient::~CurlHttpClient() = default;

CurlHttpClient::CurlHttpClient(CurlHttpClient&& other) noexcept
    : m_config(std::move(other.m_config)),
      m_session(std::move(other.m_session)),
      m_init_error(other.m_init_error),
      m_heartbeat_aborted(other.m_heartbeat_aborted) {
    other.m_init_error = ErrorCode::None;
    other.m_heartbeat_aborted = false;
}

CurlHttpClient& CurlHttpClient::operator=(CurlHttpClient&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    m_config = std::move(other.m_config);
    m_session = std::move(other.m_session);
    m_init_error = other.m_init_error;
    m_heartbeat_aborted = other.m_heartbeat_aborted;

    other.m_init_error = ErrorCode::None;
    other.m_heartbeat_aborted = false;
    return *this;
}

HttpResponse CurlHttpClient::Send(const HttpRequest& request) {
    TransportOrchestrator orchestrator(*this);
    HttpResponse response = orchestrator.Execute(request);

    if (response.TransportOk()) {
        if (!m_config.security_policy.OnResponseReceived(request, response)) {
            response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
            response.transport_error = ErrorCode::HeartbeatAbort;
            WipeResponse(response);
            return response;
        }
    }

    if (response.TransportOk() && m_config.response_verifier.Enabled()) {
        if (request.on_chunk_received) {
            response.verified = false;
            response.verification_error = ErrorCode::VerifyGeneric;
            m_config.security_policy.OnSignatureVerified(false, response.verification_error);
            return response;
        }
        ErrorCode reason = ErrorCode::None;
        response.verified = m_config.response_verifier.Verify(request, response, &reason);
        m_config.security_policy.OnSignatureVerified(response.verified, reason);
        if (!response.verified) {
            response.verification_error = (reason == ErrorCode::None) ? ErrorCode::VerifyGeneric : reason;
        }
    }

    return response;
}

bool CurlHttpClient::IsInitialized() const {
    return m_session != nullptr && m_session->IsInitialized();
}

HttpResponse CurlHttpClient::PerformOnce(
    const HttpRequest& request,
    const std::optional<DnsStrategy>& strategy) {
    HttpResponse response{};

    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        response.transport_code = static_cast<int>(CURLE_FAILED_INIT);
        response.transport_error = ErrorCode::NoCurlHandle;
        return response;
    }
    const std::size_t request_body_size = request.body_view.empty() ? request.body.size() : request.body_view.size();
    if (RequestBodyTooLargeForCurl(request_body_size)) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::RequestBodyTooLarge;
        return response;
    }

    char error_buffer[CURL_ERROR_SIZE] = {0};
    auto wipe_error_buffer = [&]() {
#if defined(_WIN32)
        SecureZeroMemory(error_buffer, sizeof(error_buffer));
#else
        volatile char* ptr = error_buffer;
        for (size_t i = 0; i < sizeof(error_buffer); ++i) {
            ptr[i] = '\0';
        }
#endif
    };

    BodyWriteContext body_ctx{};
    body_ctx.body = &response.body;
    body_ctx.max_body_bytes = request.max_body_bytes;
    if (m_config.global_max_body_bytes != 0) {
        body_ctx.max_body_bytes =
            body_ctx.max_body_bytes == 0
                ? m_config.global_max_body_bytes
                : (std::min)(body_ctx.max_body_bytes, m_config.global_max_body_bytes);
    }
    body_ctx.on_chunk_received = request.on_chunk_received;

    std::string protocol_scheme;
    std::string redirect_protocol_scheme;
    std::string custom_user_agent;
    std::string custom_method;
    std::string cert_type;
    std::string key_type;

    m_heartbeat_aborted = false;
    m_session->Reset();
    ApplyCommonOptions(
        request,
        response,
        error_buffer,
        &body_ctx,
        &protocol_scheme,
        &redirect_protocol_scheme,
        &custom_user_agent,
        strategy);
    ApplyMethodAndBody(request, &custom_method);
    ApplyTlsOptions(&cert_type, &key_type);

    const CurlApi& curl_api = m_session->Api();
    curl_slist* headers = nullptr;
    for (const auto& [name, value] : m_config.default_headers) {
        if (!internal::IsValidHeaderName(name) || !internal::IsValidHeaderValue(value)) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::InvalidHeader;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        std::string header = BuildHeaderLine(name, value);
        headers = curl_api.slist_append(headers, header.c_str());
        SecureWipe(header);
    }
    for (const auto& [name, value] : request.headers) {
        if (!internal::IsValidHeaderName(name) || !internal::IsValidHeaderValue(value)) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::InvalidHeader;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        std::string header = BuildHeaderLine(name, value);
        headers = curl_api.slist_append(headers, header.c_str());
        SecureWipe(header);
    }

    std::string active_bearer_token;
    if (request.bearer_token_provider) {
        request.bearer_token_provider(active_bearer_token);
    } else if (m_config.bearer_token_provider) {
        m_config.bearer_token_provider(active_bearer_token);
    }

    const std::string_view active_bearer = active_bearer_token;
    const bool request_has_auth_header =
        !active_bearer.empty() || HasAuthorizationHeader(m_config.default_headers) || HasAuthorizationHeader(request.headers);
    if (request.follow_redirects && request_has_auth_header) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::RedirectAuth;
        SecureWipe(active_bearer_token);
        WipeHeaderList(headers);
        wipe_error_buffer();
        return response;
    }

    if (!active_bearer.empty()) {
        std::string auth_prefix = BURNER_OBF_LITERAL("Authorization: Bearer ");
        std::string auth;
        auth.reserve(auth_prefix.size() + active_bearer.size());
        auth.append(auth_prefix);
        auth.append(active_bearer.data(), active_bearer.size());
        SecureWipe(auth_prefix);
        headers = curl_api.slist_append(headers, auth.c_str());
        SecureWipe(auth);
    }
    SecureWipe(active_bearer_token);

    if (headers != nullptr) {
        curl_api.easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    }

    const CURLcode code = curl_api.easy_perform(easy);
    SecureWipe(protocol_scheme);
    SecureWipe(redirect_protocol_scheme);
    SecureWipe(custom_user_agent);
    SecureWipe(custom_method);
    SecureWipe(cert_type);
    SecureWipe(key_type);

    response.transport_code = static_cast<int>(code);
    if (code != CURLE_OK) {
        if (code == CURLE_PEER_FAILED_VERIFICATION
#ifdef CURLE_SSL_CACERT
            || code == CURLE_SSL_CACERT
#endif
        ) {
            response.transport_error = ErrorCode::TlsVerificationFailed;
        } else if (code == CURLE_WRITE_ERROR && body_ctx.limit_exceeded) {
            response.transport_error = ErrorCode::BodyTooLarge;
        } else if (code == CURLE_ABORTED_BY_CALLBACK && m_heartbeat_aborted) {
            response.transport_error = ErrorCode::HeartbeatAbort;
        } else {
            response.transport_error = ErrorCode::CurlGeneric;
        }
        WipeResponse(response);
    }

    if (response.TransportOk()) {
        char* primary_ip = nullptr;
        if (curl_api.easy_getinfo(easy, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK &&
            primary_ip != nullptr &&
            !m_config.security_policy.OnVerifyTransport(request.url.c_str(), primary_ip)) {
            response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
            response.transport_error = ErrorCode::TransportVerificationFailed;
            WipeResponse(response);
        }
    }

    response.dns_strategy_used = strategy.has_value() ? strategy->name : BURNER_OBF_LITERAL("System DNS");
    response.streamed_body_bytes = body_ctx.streamed_body_bytes;

    curl_api.easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response.status_code);

    if (headers != nullptr) {
        WipeHeaderList(headers);
    }

    ResetMethodState();
    wipe_error_buffer();
    return response;
}

bool CurlHttpClient::ShouldRetry(const HttpRequest& request, const HttpResponse& response, int attempt) const {
    const int attempts = (std::max)(1, request.retry.max_attempts);
    if (attempt >= attempts) {
        return false;
    }

    if (!response.TransportOk() && request.retry.retry_on_transport_error) {
        return true;
    }

    if (response.TransportOk() && request.retry.retry_on_5xx && response.status_code >= 500 && response.status_code < 600) {
        return true;
    }

    return false;
}

} // namespace burner::net

#endif
