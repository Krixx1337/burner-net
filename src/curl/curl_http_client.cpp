#if BURNER_ENABLE_CURL

#include "curl_http_client.h"
#include "burner/net/obfuscation.h"
#include "../error_strings.h"
#include "../internal/header_validation.h"
#include "../internal/import_pointer_trust.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdarg>
#include <curl/curl.h>
#include <limits>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

namespace burner::net {

namespace {

struct BodyWriteContext {
    std::string* body = nullptr;
    std::size_t max_body_bytes = 0;
    bool limit_exceeded = false;
    std::size_t streamed_body_bytes = 0;
    ChunkCallback on_chunk_received;
};

#ifdef _WIN32
template <typename TFn>
TFn ResolveCurlExport(std::string export_name) {
    std::string dll_names[] = {
        BURNER_OBF_LITERAL("libcurl.dll"),
        BURNER_OBF_LITERAL("libcurl-d.dll")
    };

    for (std::string& dll_name : dll_names) {
        HMODULE module = GetModuleHandleA(dll_name.c_str());
        if (module == nullptr) {
            SecureWipe(dll_name);
            continue;
        }

        FARPROC proc = GetProcAddress(module, export_name.c_str());
        SecureWipe(dll_name);
        if (proc != nullptr) {
            SecureWipe(export_name);
            return reinterpret_cast<TFn>(proc);
        }
    }

    SecureWipe(export_name);
    return nullptr;
}
#endif

bool IsCurlApiComplete(const CurlApi& api) {
    return api.easy_init != nullptr &&
        api.easy_cleanup != nullptr &&
        api.easy_reset != nullptr &&
        api.easy_setopt != nullptr &&
        api.easy_perform != nullptr &&
        api.easy_getinfo != nullptr &&
        api.slist_append != nullptr &&
        api.slist_free_all != nullptr &&
        api.easy_strerror != nullptr;
}

CURL* DefaultCurlEasyInit() {
    return curl_easy_init();
}

void DefaultCurlEasyCleanup(CURL* easy) {
    curl_easy_cleanup(easy);
}

void DefaultCurlEasyReset(CURL* easy) {
    curl_easy_reset(easy);
}

CURLcode DefaultCurlEasySetopt(CURL* easy, CURLoption option, ...) {
    va_list args;
    va_start(args, option);
    CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;

    switch (option) {
    case CURLOPT_WRITEDATA:
    case CURLOPT_HEADERDATA:
    case CURLOPT_XFERINFODATA:
        code = curl_easy_setopt(easy, option, va_arg(args, void*));
        break;
    case CURLOPT_HTTPHEADER:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_slist*));
        break;
    case CURLOPT_SSLCERT_BLOB:
    case CURLOPT_SSLKEY_BLOB:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_blob*));
        break;
    case CURLOPT_WRITEFUNCTION:
    case CURLOPT_HEADERFUNCTION:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_write_callback));
        break;
#ifdef CURLOPT_XFERINFOFUNCTION
    case CURLOPT_XFERINFOFUNCTION:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_xferinfo_callback));
        break;
#endif
    case CURLOPT_URL:
    case CURLOPT_ERRORBUFFER:
    case CURLOPT_PROXY:
    case CURLOPT_PINNEDPUBLICKEY:
    case CURLOPT_PROTOCOLS_STR:
    case CURLOPT_REDIR_PROTOCOLS_STR:
    case CURLOPT_USERAGENT:
    case CURLOPT_POSTFIELDS:
    case CURLOPT_CUSTOMREQUEST:
    case CURLOPT_KEYPASSWD:
    case CURLOPT_SSLCERTTYPE:
    case CURLOPT_SSLKEYTYPE:
    case CURLOPT_DOH_URL:
        code = curl_easy_setopt(easy, option, va_arg(args, char*));
        break;
    case CURLOPT_FOLLOWLOCATION:
    case CURLOPT_DISALLOW_USERNAME_IN_URL:
    case CURLOPT_MAXREDIRS:
    case CURLOPT_TIMEOUT:
    case CURLOPT_CONNECTTIMEOUT:
    case CURLOPT_SSL_VERIFYPEER:
    case CURLOPT_SSL_VERIFYHOST:
    case CURLOPT_SSLVERSION:
    case CURLOPT_SSL_OPTIONS:
    case CURLOPT_HTTPGET:
    case CURLOPT_POST:
    case CURLOPT_POSTFIELDSIZE:
    case CURLOPT_DOH_SSL_VERIFYPEER:
    case CURLOPT_DOH_SSL_VERIFYHOST:
    case CURLOPT_NOPROGRESS:
#ifdef CURLOPT_PROTOCOLS
    case CURLOPT_PROTOCOLS:
#endif
#ifdef CURLOPT_REDIR_PROTOCOLS
    case CURLOPT_REDIR_PROTOCOLS:
#endif
        code = curl_easy_setopt(easy, option, va_arg(args, long));
        break;
    default:
        break;
    }

    va_end(args);
    return code;
}

CURLcode DefaultCurlEasyPerform(CURL* easy) {
    return curl_easy_perform(easy);
}

CURLcode DefaultCurlEasyGetinfo(CURL* easy, CURLINFO info, ...) {
    va_list args;
    va_start(args, info);
    CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;

    switch (info) {
    case CURLINFO_RESPONSE_CODE:
        code = curl_easy_getinfo(easy, info, va_arg(args, long*));
        break;
    case CURLINFO_PRIMARY_IP:
        code = curl_easy_getinfo(easy, info, va_arg(args, char**));
        break;
    default:
        break;
    }

    va_end(args);
    return code;
}

curl_slist* DefaultCurlSlistAppend(curl_slist* list, const char* value) {
    return curl_slist_append(list, value);
}

void DefaultCurlSlistFreeAll(curl_slist* list) {
    curl_slist_free_all(list);
}

const char* DefaultCurlEasyStrerror(CURLcode code) {
    return curl_easy_strerror(code);
}

CurlApi MakeWrappedCurlApi() {
    CurlApi api{};
    api.easy_init = &DefaultCurlEasyInit;
    api.easy_cleanup = &DefaultCurlEasyCleanup;
    api.easy_reset = &DefaultCurlEasyReset;
    api.easy_setopt = &DefaultCurlEasySetopt;
    api.easy_perform = &DefaultCurlEasyPerform;
    api.easy_getinfo = &DefaultCurlEasyGetinfo;
    api.slist_append = &DefaultCurlSlistAppend;
    api.slist_free_all = &DefaultCurlSlistFreeAll;
    api.easy_strerror = &DefaultCurlEasyStrerror;
    return api;
}

CurlApi MakeResolvedCurlApi() {
    CurlApi api{};
#ifdef _WIN32
    api.easy_init = ResolveCurlExport<CurlEasyInitFn>(BURNER_OBF_LITERAL("curl_easy_init"));
    api.easy_cleanup = ResolveCurlExport<CurlEasyCleanupFn>(BURNER_OBF_LITERAL("curl_easy_cleanup"));
    api.easy_reset = ResolveCurlExport<CurlEasyResetFn>(BURNER_OBF_LITERAL("curl_easy_reset"));
    api.easy_setopt = ResolveCurlExport<CurlEasySetoptFn>(BURNER_OBF_LITERAL("curl_easy_setopt"));
    api.easy_perform = ResolveCurlExport<CurlEasyPerformFn>(BURNER_OBF_LITERAL("curl_easy_perform"));
    api.easy_getinfo = ResolveCurlExport<CurlEasyGetinfoFn>(BURNER_OBF_LITERAL("curl_easy_getinfo"));
    api.slist_append = ResolveCurlExport<CurlSlistAppendFn>(BURNER_OBF_LITERAL("curl_slist_append"));
    api.slist_free_all = ResolveCurlExport<CurlSlistFreeAllFn>(BURNER_OBF_LITERAL("curl_slist_free_all"));
    api.easy_strerror = ResolveCurlExport<CurlEasyStrerrorFn>(BURNER_OBF_LITERAL("curl_easy_strerror"));
#endif
    return api;
}

bool IsCurlApiTrusted(const CurlApi& api, const std::vector<std::wstring>& trusted_module_basenames) {
    return internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_init), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_cleanup), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_reset), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_setopt), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_perform), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_getinfo), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.slist_append), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.slist_free_all), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_strerror), trusted_module_basenames);
}

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

bool RequestBodyTooLargeForCurl(const std::string& body) {
    return body.size() > static_cast<size_t>((std::numeric_limits<long>::max)());
}

std::string BuildHeaderLine(std::string_view name, std::string_view value) {
    std::string header;
    header.reserve(name.size() + 2 + value.size());
    header.append(name);
    header.append(": ");
    header.append(value);
    return header;
}

std::string ToCurlMethod(HttpMethod method) {
    switch (method) {
    case HttpMethod::Get: return BURNER_OBF_LITERAL("GET");
    case HttpMethod::Post: return BURNER_OBF_LITERAL("POST");
    case HttpMethod::Put: return BURNER_OBF_LITERAL("PUT");
    case HttpMethod::Delete: return BURNER_OBF_LITERAL("DELETE");
    case HttpMethod::Patch: return BURNER_OBF_LITERAL("PATCH");
    default: return BURNER_OBF_LITERAL("GET");
    }
}

} // namespace

CurlHttpClient::CurlHttpClient(const ClientConfig& config)
    : m_config(config) {
    if (m_config.curl_api.has_value()) {
        m_curl_api = *m_config.curl_api;
        if (!IsCurlApiComplete(m_curl_api)) {
            m_init_error = ErrorCode::CurlApiIncomplete;
            return;
        }
        if (m_config.verify_curl_api_pointers &&
            !IsCurlApiTrusted(m_curl_api, m_config.trusted_curl_module_basenames)) {
            m_init_error = ErrorCode::CurlApiUntrusted;
            return;
        }
    } else {
#if BURNERNET_HARDEN_IMPORTS
        m_curl_api = MakeResolvedCurlApi();
        if (!IsCurlApiComplete(m_curl_api)) {
            m_init_error = ErrorCode::CurlApiIncomplete;
            return;
        }
        if (m_config.verify_curl_api_pointers &&
            !IsCurlApiTrusted(m_curl_api, m_config.trusted_curl_module_basenames)) {
            m_init_error = ErrorCode::CurlApiUntrusted;
            return;
        }
#else
        if (m_config.verify_curl_api_pointers) {
            m_curl_api = MakeResolvedCurlApi();
            if (!IsCurlApiComplete(m_curl_api)) {
                m_init_error = ErrorCode::CurlApiIncomplete;
                return;
            }
            if (!IsCurlApiTrusted(m_curl_api, m_config.trusted_curl_module_basenames)) {
                m_init_error = ErrorCode::CurlApiUntrusted;
                return;
            }
        } else {
            m_curl_api = MakeWrappedCurlApi();
        }
#endif
    }

    m_easy = m_curl_api.easy_init();
    if (!m_easy) {
        m_init_error = ErrorCode::InitCurl;
    }
}

CurlHttpClient::~CurlHttpClient() {
    if (m_easy != nullptr) {
        m_curl_api.easy_cleanup(static_cast<CURL*>(m_easy));
        m_easy = nullptr;
    }
}

HttpResponse CurlHttpClient::Send(const HttpRequest& request) {
    HttpResponse response{};
    bool verification_phase_completed = false;

    if (m_config.on_pre_flight && !m_config.on_pre_flight(request)) {
        response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
        response.transport_error = ErrorCode::PreFlightAbort;
        return response;
    }

    if (m_config.on_before_request && !m_config.on_before_request(request)) {
        response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
        response.transport_error = ErrorCode::HeartbeatAbort;
        return response;
    }

    const int attempts = (std::max)(1, request.retry.max_attempts);

    for (int attempt = 1; attempt <= attempts; ++attempt) {
        HttpRequest active_request = request;
        Security::OnPreRequest(active_request);
        response = PerformOnceWithDnsFallback(active_request);
        if (!response.TransportOk()) {
            Security::OnError(response.transport_error, active_request.url.c_str());
        }
        if (!ShouldRetry(request, response, attempt)) {
            break;
        }

        const int backoff = (std::max)(0, request.retry.backoff_ms);
        if (backoff > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }
    }

    if (response.TransportOk() && m_config.on_response_received) {
        if (!m_config.on_response_received(request, response)) {
            response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
            response.transport_error = ErrorCode::HeartbeatAbort;
            WipeResponse(response);
            return response;
        }
    }

    if (response.TransportOk() && m_config.response_verifier) {
        if (request.on_chunk_received) {
            response.verified = false;
            response.verification_error = ErrorCode::VerifyGeneric;
            verification_phase_completed = true;
            if (m_config.on_post_verification) {
                m_config.on_post_verification(response, response.verified);
            }
            return response;
        }
        ErrorCode reason = ErrorCode::None;
        response.verified = m_config.response_verifier->Verify(request, response, &reason);
        if (!response.verified) {
            response.verification_error = (reason == ErrorCode::None) ? ErrorCode::VerifyGeneric : reason;
        }
        verification_phase_completed = true;
    }

    if (verification_phase_completed && m_config.on_post_verification) {
        m_config.on_post_verification(response, response.verified);
    }

    return response;
}

HttpResponse CurlHttpClient::PerformOnce(const HttpRequest& request) {
    HttpResponse response{};

    auto* easy = static_cast<CURL*>(m_easy);
    if (easy == nullptr) {
        response.transport_code = static_cast<int>(CURLE_FAILED_INIT);
        response.transport_error = ErrorCode::NoCurlHandle;
        return response;
    }
    if (RequestBodyTooLargeForCurl(request.body)) {
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
    body_ctx.on_chunk_received = request.on_chunk_received;
    std::string protocol_scheme;
    std::string redirect_protocol_scheme;
    std::string custom_user_agent;
    std::string custom_method;
    std::string cert_type;
    std::string key_type;

    m_heartbeat_aborted = false;
    m_curl_api.easy_reset(easy);
    ApplyCommonOptions(
        request,
        response,
        error_buffer,
        &body_ctx,
        &protocol_scheme,
        &redirect_protocol_scheme,
        &custom_user_agent);
    ApplyMethodAndBody(request, &custom_method);
    ApplyTlsOptions(&cert_type, &key_type);

    curl_slist* headers = nullptr;
    for (const auto& [name, value] : m_config.default_headers) {
        if (!internal::IsValidHeaderName(name) || !internal::IsValidHeaderValue(value)) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::InvalidHeader;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        const std::string header = BuildHeaderLine(name, value);
        headers = m_curl_api.slist_append(headers, header.c_str());
    }
    for (const auto& [name, value] : request.headers) {
        if (!internal::IsValidHeaderName(name) || !internal::IsValidHeaderValue(value)) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::InvalidHeader;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        const std::string header = BuildHeaderLine(name, value);
        headers = m_curl_api.slist_append(headers, header.c_str());
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
        headers = m_curl_api.slist_append(headers, auth.c_str());
        SecureWipe(auth);
    }
    SecureWipe(active_bearer_token);
    if (headers != nullptr) {
        m_curl_api.easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    }

    const CURLcode code = m_curl_api.easy_perform(easy);
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
            (void)error_buffer;
            response.transport_error = ErrorCode::CurlGeneric;
        }
        WipeResponse(response);
    }

    if (response.TransportOk()) {
        char* primary_ip = nullptr;
        if (m_curl_api.easy_getinfo(easy, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK &&
            primary_ip != nullptr &&
            !detail::CallVerifyTransport<Security>(request.url.c_str(), primary_ip)) {
            response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
            response.transport_error = ErrorCode::TransportVerificationFailed;
            WipeResponse(response);
        }
    }

    response.dns_strategy_used = m_active_dns_strategy.has_value() ? m_active_dns_strategy->name : kDnsSystemTag;
    response.streamed_body_bytes = body_ctx.streamed_body_bytes;

    m_curl_api.easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response.status_code);

    if (headers != nullptr) {
        WipeHeaderList(headers);
    }

    ResetMethodState();
    wipe_error_buffer();
    return response;
}

HttpResponse CurlHttpClient::PerformOnceWithDnsFallback(const HttpRequest& request) {
    if (!request.dns_fallback.enabled || request.dns_fallback.strategies.empty()) {
        m_active_dns_strategy.reset();
        return PerformOnce(request);
    }

    HttpResponse last_response{};
    for (const DnsStrategy& strategy : request.dns_fallback.strategies) {
        m_active_dns_strategy = strategy;
        last_response = PerformOnce(request);
        if (last_response.TransportOk()) {
            return last_response;
        }
    }

    m_active_dns_strategy.reset();
    return last_response;
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

size_t CurlHttpClient::WriteBodyCallback(void* contents, size_t size, size_t nmemb, void* user_data) {
    if (size > 0 && nmemb > ((std::numeric_limits<size_t>::max)() / size)) {
        return 0;
    }
    const size_t total = size * nmemb;
    if (user_data == nullptr || contents == nullptr) {
        return total;
    }

    auto* ctx = static_cast<BodyWriteContext*>(user_data);
    if (ctx->body == nullptr) {
        return 0;
    }

    ctx->streamed_body_bytes += total;

    if (ctx->on_chunk_received) {
        ctx->on_chunk_received(reinterpret_cast<const uint8_t*>(contents), total);
        return total;
    }

    if (ctx->max_body_bytes > 0) {
        if (ctx->body->size() > ctx->max_body_bytes || total > (ctx->max_body_bytes - ctx->body->size())) {
            ctx->limit_exceeded = true;
            return 0;
        }
    }

    ctx->body->append(static_cast<const char*>(contents), total);
    return total;
}

size_t CurlHttpClient::WriteHeaderCallback(void* contents, size_t size, size_t nmemb, void* user_data) {
    const size_t total = size * nmemb;
    if (user_data == nullptr || contents == nullptr) {
        return total;
    }

    auto* headers = static_cast<HeaderMap*>(user_data);
    std::string line(static_cast<const char*>(contents), total);

    auto it = line.find(':');
    if (it != std::string::npos) {
        std::string name = line.substr(0, it);
        std::string value = line.substr(it + 1);

        auto trim = [](std::string& x) {
            while (!x.empty() && (x.back() == '\r' || x.back() == '\n' || x.back() == ' ' || x.back() == '\t')) x.pop_back();
            size_t start = 0;
            while (start < x.size() && (x[start] == ' ' || x[start] == '\t')) ++start;
            if (start > 0) x.erase(0, start);
        };

        trim(name);
        trim(value);

        if (!name.empty()) {
            headers->insert_or_assign(std::move(name), std::move(value));
        }
    }

    return total;
}

int CurlHttpClient::ProgressCallback(void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    auto* self = static_cast<CurlHttpClient*>(clientp);
    if (self == nullptr || !self->m_config.on_request_heartbeat) {
        return 0;
    }

    if (!self->m_config.on_request_heartbeat()) {
        self->m_heartbeat_aborted = true;
        return 1;
    }

    return 0;
}

void CurlHttpClient::WipeResponse(HttpResponse& response) const {
    SecureWipe(response.body);
    response.headers.clear();
    response.streamed_body_bytes = 0;
}

void CurlHttpClient::WipeHeaderList(curl_slist* headers) const {
    for (curl_slist* it = headers; it != nullptr; it = it->next) {
        if (it->data != nullptr) {
            const size_t len = std::char_traits<char>::length(it->data);
#if defined(_WIN32)
            SecureZeroMemory(it->data, len);
#else
            volatile char* ptr = it->data;
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = '\0';
            }
#endif
        }
    }

    m_curl_api.slist_free_all(headers);
}

void CurlHttpClient::ApplyCommonOptions(
    const HttpRequest& request,
    HttpResponse& response,
    char* error_buffer,
    void* body_ctx,
    std::string* protocol_scheme,
    std::string* redirect_protocol_scheme,
    std::string* user_agent_storage) {
    auto* easy = static_cast<CURL*>(m_easy);
    (void)protocol_scheme;
    (void)redirect_protocol_scheme;
    (void)user_agent_storage;

    m_curl_api.easy_setopt(easy, CURLOPT_URL, request.url.c_str());
    m_curl_api.easy_setopt(easy, CURLOPT_ERRORBUFFER, error_buffer);
    m_curl_api.easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CurlHttpClient::WriteBodyCallback);
    m_curl_api.easy_setopt(easy, CURLOPT_WRITEDATA, body_ctx);
    m_curl_api.easy_setopt(easy, CURLOPT_HEADERFUNCTION, &CurlHttpClient::WriteHeaderCallback);
    m_curl_api.easy_setopt(easy, CURLOPT_HEADERDATA, &response.headers);
#ifdef CURLOPT_XFERINFOFUNCTION
    m_curl_api.easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, &CurlHttpClient::ProgressCallback);
    m_curl_api.easy_setopt(easy, CURLOPT_XFERINFODATA, this);
    m_curl_api.easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
#endif
    m_curl_api.easy_setopt(easy, CURLOPT_FOLLOWLOCATION, request.follow_redirects ? 1L : 0L);
    if (!m_config.use_system_proxy) {
        m_curl_api.easy_setopt(easy, CURLOPT_PROXY, "");
    }
#ifdef CURLOPT_PROTOCOLS_STR
    if (protocol_scheme != nullptr) {
        *protocol_scheme = BURNER_OBF_LITERAL("https");
        m_curl_api.easy_setopt(easy, CURLOPT_PROTOCOLS_STR, protocol_scheme->c_str());
    }
#elif defined(CURLOPT_PROTOCOLS)
    m_curl_api.easy_setopt(easy, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#endif
#ifdef CURLOPT_DISALLOW_USERNAME_IN_URL
    m_curl_api.easy_setopt(easy, CURLOPT_DISALLOW_USERNAME_IN_URL, 1L);
#endif
    if (request.follow_redirects) {
#ifdef CURLOPT_REDIR_PROTOCOLS_STR
        if (redirect_protocol_scheme != nullptr) {
            *redirect_protocol_scheme = BURNER_OBF_LITERAL("https");
            m_curl_api.easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, redirect_protocol_scheme->c_str());
        }
#elif defined(CURLOPT_REDIR_PROTOCOLS)
        m_curl_api.easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
#endif
        m_curl_api.easy_setopt(easy, CURLOPT_MAXREDIRS, 10L);
    }
    m_curl_api.easy_setopt(easy, CURLOPT_TIMEOUT, request.timeout_seconds);
    m_curl_api.easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, request.connect_timeout_seconds);
    if (user_agent_storage != nullptr) {
        *user_agent_storage = Security::GetUserAgent();
    }
    if (user_agent_storage != nullptr && !user_agent_storage->empty()) {
        m_curl_api.easy_setopt(easy, CURLOPT_USERAGENT, user_agent_storage->c_str());
    } else if (!m_config.user_agent.empty()) {
        m_curl_api.easy_setopt(easy, CURLOPT_USERAGENT, m_config.user_agent.c_str());
    }

    m_curl_api.easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, m_config.verify_peer ? 1L : 0L);
    m_curl_api.easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, m_config.verify_host ? 2L : 0L);
    m_curl_api.easy_setopt(easy, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#ifdef CURLSSLOPT_NATIVE_CA
    if (m_config.use_native_ca) {
        m_curl_api.easy_setopt(easy, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    }
#endif
    if (!m_config.pinned_public_keys.empty()) {
        std::string pinned_keys;
        pinned_keys.reserve(m_config.pinned_public_keys.size() * 64);
        for (size_t i = 0; i < m_config.pinned_public_keys.size(); ++i) {
            pinned_keys += m_config.pinned_public_keys[i];
            if (i + 1 < m_config.pinned_public_keys.size()) {
                pinned_keys.push_back(';');
            }
        }
        m_curl_api.easy_setopt(easy, CURLOPT_PINNEDPUBLICKEY, pinned_keys.c_str());
        SecureWipe(pinned_keys);
    }

    ClearDnsStrategy();
    if (m_active_dns_strategy.has_value()) {
        ApplyDnsStrategy(*m_active_dns_strategy);
    }
}

void CurlHttpClient::ApplyMethodAndBody(const HttpRequest& request, std::string* custom_method_storage) {
    auto* easy = static_cast<CURL*>(m_easy);

    switch (request.method) {
    case HttpMethod::Get:
        m_curl_api.easy_setopt(easy, CURLOPT_HTTPGET, 1L);
        break;
    case HttpMethod::Post:
        m_curl_api.easy_setopt(easy, CURLOPT_POST, 1L);
        m_curl_api.easy_setopt(easy, CURLOPT_POSTFIELDS, request.body.c_str());
        m_curl_api.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
        break;
    case HttpMethod::Put:
    case HttpMethod::Delete:
    case HttpMethod::Patch:
        if (custom_method_storage != nullptr) {
            *custom_method_storage = ToCurlMethod(request.method);
            m_curl_api.easy_setopt(easy, CURLOPT_CUSTOMREQUEST, custom_method_storage->c_str());
        }
        if (!request.body.empty()) {
            m_curl_api.easy_setopt(easy, CURLOPT_POSTFIELDS, request.body.c_str());
            m_curl_api.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
        }
        break;
    }
}

void CurlHttpClient::ApplyTlsOptions(std::string* cert_type_storage, std::string* key_type_storage) {
    auto* easy = static_cast<CURL*>(m_easy);

    MtlsCredentials credentials{};
    if (m_config.mtls_provider) {
        if (!m_config.mtls_provider(credentials)) {
            SecureWipe(credentials.cert_pem);
            SecureWipe(credentials.key_pem);
            SecureWipe(credentials.key_password);
            return;
        }
    } else {
        credentials = m_config.mtls;
    }

    if (!credentials.enabled) {
        SecureWipe(credentials.cert_pem);
        SecureWipe(credentials.key_pem);
        SecureWipe(credentials.key_password);
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
    m_curl_api.easy_setopt(easy, CURLOPT_SSLCERT_BLOB, &cert_blob);
    m_curl_api.easy_setopt(easy, CURLOPT_SSLKEY_BLOB, &key_blob);
    m_curl_api.easy_setopt(easy, CURLOPT_KEYPASSWD, credentials.key_password.c_str());
    if (cert_type_storage != nullptr) {
        *cert_type_storage = BURNER_OBF_LITERAL("PEM");
        m_curl_api.easy_setopt(easy, CURLOPT_SSLCERTTYPE, cert_type_storage->c_str());
    }
    if (key_type_storage != nullptr) {
        *key_type_storage = BURNER_OBF_LITERAL("PEM");
        m_curl_api.easy_setopt(easy, CURLOPT_SSLKEYTYPE, key_type_storage->c_str());
    }

    SecureWipe(credentials.cert_pem);
    SecureWipe(credentials.key_pem);
    SecureWipe(credentials.key_password);
}

void CurlHttpClient::ApplyDnsStrategy(const DnsStrategy& strategy) {
    auto* easy = static_cast<CURL*>(m_easy);
    if (easy == nullptr) {
        return;
    }

    if (strategy.mode == DnsMode::Doh) {
        m_curl_api.easy_setopt(easy, CURLOPT_DOH_URL, strategy.doh_url.c_str());
        m_curl_api.easy_setopt(easy, CURLOPT_DOH_SSL_VERIFYPEER, m_config.verify_peer ? 1L : 0L);
        m_curl_api.easy_setopt(easy, CURLOPT_DOH_SSL_VERIFYHOST, m_config.verify_host ? 2L : 0L);
    }
}

void CurlHttpClient::ClearDnsStrategy() {
    auto* easy = static_cast<CURL*>(m_easy);
    if (easy == nullptr) {
        return;
    }

    m_curl_api.easy_setopt(easy, CURLOPT_DOH_URL, nullptr);
}

void CurlHttpClient::ResetMethodState() {
    auto* easy = static_cast<CURL*>(m_easy);

    m_curl_api.easy_setopt(easy, CURLOPT_HTTPGET, 0L);
    m_curl_api.easy_setopt(easy, CURLOPT_POST, 0L);
    m_curl_api.easy_setopt(easy, CURLOPT_CUSTOMREQUEST, nullptr);
    m_curl_api.easy_setopt(easy, CURLOPT_POSTFIELDS, nullptr);
    m_curl_api.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, 0L);
#ifdef CURLOPT_XFERINFOFUNCTION
    m_curl_api.easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, nullptr);
    m_curl_api.easy_setopt(easy, CURLOPT_XFERINFODATA, nullptr);
    m_curl_api.easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
#endif
}

} // namespace burner::net

#endif
