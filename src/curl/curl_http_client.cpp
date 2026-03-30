#if BURNER_ENABLE_CURL

#include "curl_http_client.h"

#include "burner/net/obfuscation.h"
#include "../internal/header_validation.h"
#include "../internal/import_pointer_trust.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdarg>
#include <curl/curl.h>
#include <limits>
#include <memory>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include "burner/net/external/lazy_importer/lazy_importer.hpp"

#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "normaliz.lib")
#endif
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

struct BodyWriteContext {
    std::string* body = nullptr;
    std::size_t max_body_bytes = 0;
    bool limit_exceeded = false;
    std::size_t streamed_body_bytes = 0;
    ChunkCallback on_chunk_received;
};

#ifdef _WIN32
void* ResolveLoadedCurlModule() noexcept {
    if (void* module = LI_MODULE("libcurl.dll").safe_cached()) {
        return module;
    }
    if (void* module = LI_MODULE("libcurl-d.dll").safe_cached()) {
        return module;
    }
    if (void* module = LI_MODULE("libcurl-x64.dll").safe_cached()) {
        return module;
    }
    return LI_MODULE("libcurl-x86.dll").safe_cached();
}
#endif

bool IsCurlApiComplete(const CurlApi& api) {
    return static_cast<bool>(api.easy_init) &&
        static_cast<bool>(api.easy_cleanup) &&
        static_cast<bool>(api.easy_reset) &&
        static_cast<bool>(api.easy_setopt) &&
        static_cast<bool>(api.easy_perform) &&
        static_cast<bool>(api.easy_getinfo) &&
        static_cast<bool>(api.slist_append) &&
        static_cast<bool>(api.slist_free_all) &&
        static_cast<bool>(api.easy_strerror);
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
    const void* curl_module = ResolveLoadedCurlModule();
    if (curl_module == nullptr) {
        return api;
    }

    api.easy_init = LI_FN(curl_easy_init).in_safe<CurlEasyInitFn>(curl_module);
    api.easy_cleanup = LI_FN(curl_easy_cleanup).in_safe<CurlEasyCleanupFn>(curl_module);
    api.easy_reset = LI_FN(curl_easy_reset).in_safe<CurlEasyResetFn>(curl_module);
    api.easy_setopt = LI_FN(curl_easy_setopt).in_safe<CurlEasySetoptFn>(curl_module);
    api.easy_perform = LI_FN(curl_easy_perform).in_safe<CurlEasyPerformFn>(curl_module);
    api.easy_getinfo = LI_FN(curl_easy_getinfo).in_safe<CurlEasyGetinfoFn>(curl_module);
    api.slist_append = LI_FN(curl_slist_append).in_safe<CurlSlistAppendFn>(curl_module);
    api.slist_free_all = LI_FN(curl_slist_free_all).in_safe<CurlSlistFreeAllFn>(curl_module);
    api.easy_strerror = LI_FN(curl_easy_strerror).in_safe<CurlEasyStrerrorFn>(curl_module);
#endif
    return api;
}

bool IsCurlApiTrusted(const CurlApi& api, const std::vector<std::wstring>& trusted_module_basenames) {
    return internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_init.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_cleanup.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_reset.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_setopt.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_perform.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_getinfo.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.slist_append.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.slist_free_all.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_strerror.get()), trusted_module_basenames);
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

class CurlSession {
public:
    explicit CurlSession(CurlApi api)
        : m_api(std::move(api)),
          m_easy(m_api.easy_init ? m_api.easy_init() : nullptr) {}

    ~CurlSession() {
        if (m_easy != nullptr) {
            m_api.easy_cleanup(m_easy);
        }
    }

    CurlSession(const CurlSession&) = delete;
    CurlSession& operator=(const CurlSession&) = delete;
    CurlSession(CurlSession&&) = delete;
    CurlSession& operator=(CurlSession&&) = delete;

    [[nodiscard]] bool IsInitialized() const noexcept { return m_easy != nullptr; }
    [[nodiscard]] CURL* EasyHandle() const noexcept { return m_easy; }
    [[nodiscard]] const CurlApi& Api() const noexcept { return m_api; }

    void Reset() const {
        if (m_easy != nullptr) {
            m_api.easy_reset(m_easy);
        }
    }

private:
    CurlApi m_api;
    CURL* m_easy = nullptr;
};

class TransportOrchestrator {
public:
    explicit TransportOrchestrator(CurlHttpClient& client)
        : m_client(client) {}

    HttpResponse Execute(const HttpRequest& request) {
        HttpResponse response{};
        const int attempts = (std::max)(1, request.retry.max_attempts);

        for (int attempt = 1; attempt <= attempts; ++attempt) {
            HttpRequest active_request = request;
            if (!m_client.SecurityPolicy()->OnPreRequest(active_request)) {
                response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
                response.transport_error = ErrorCode::PreFlightAbort;
                return response;
            }

            response = PerformWithDnsFallback(active_request);
            if (!response.TransportOk()) {
                m_client.SecurityPolicy()->OnError(response.transport_error, active_request.url.c_str());
            }
            if (!m_client.ShouldRetry(request, response, attempt)) {
                break;
            }

            const int backoff = (std::max)(0, request.retry.backoff_ms);
            if (backoff > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
            }
        }

        return response;
    }

private:
    HttpResponse PerformWithDnsFallback(const HttpRequest& request) {
        if (!request.dns_fallback.enabled || request.dns_fallback.strategies.empty()) {
            return m_client.PerformOnce(request, std::nullopt);
        }

        HttpResponse last_response{};
        for (const DnsStrategy& strategy : request.dns_fallback.strategies) {
            last_response = m_client.PerformOnce(request, strategy);
            if (last_response.TransportOk()) {
                return last_response;
            }
        }

        return last_response;
    }

    CurlHttpClient& m_client;
};

CurlHttpClient::CurlHttpClient(const ClientConfig& config)
    : m_config(config) {
    CurlApi curl_api{};
#if BURNERNET_HARDEN_IMPORTS
    curl_api = MakeResolvedCurlApi();
    if (!IsCurlApiComplete(curl_api)) {
        m_init_error = ErrorCode::CurlApiIncomplete;
        return;
    }
    if (m_config.verify_curl_api_pointers &&
        !IsCurlApiTrusted(curl_api, m_config.trusted_curl_module_basenames)) {
        m_config.security_policy.OnTamper();
        m_init_error = ErrorCode::CurlApiUntrusted;
        return;
    }
#else
    if (m_config.verify_curl_api_pointers) {
        curl_api = MakeResolvedCurlApi();
        if (!IsCurlApiComplete(curl_api)) {
            m_init_error = ErrorCode::CurlApiIncomplete;
            return;
        }
        if (!IsCurlApiTrusted(curl_api, m_config.trusted_curl_module_basenames)) {
            m_config.security_policy.OnTamper();
            m_init_error = ErrorCode::CurlApiUntrusted;
            return;
        }
    } else {
        curl_api = MakeWrappedCurlApi();
    }
#endif

    m_session = std::make_unique<CurlSession>(curl_api);
    if (!m_session->IsInitialized()) {
        m_init_error = ErrorCode::InitCurl;
    }
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

    if (detail::WouldExceedBodyLimit(ctx->streamed_body_bytes - total, total, ctx->max_body_bytes)) {
        ctx->limit_exceeded = true;
        return 0;
    }

    if (ctx->on_chunk_received) {
        ctx->on_chunk_received(reinterpret_cast<const uint8_t*>(contents), total);
        return total;
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
            while (!x.empty() && (x.back() == '\r' || x.back() == '\n' || x.back() == ' ' || x.back() == '\t')) {
                x.pop_back();
            }
            size_t start = 0;
            while (start < x.size() && (x[start] == ' ' || x[start] == '\t')) {
                ++start;
            }
            if (start > 0) {
                x.erase(0, start);
            }
        };

        trim(name);
        trim(value);

        if (!name.empty()) {
            headers->insert_or_assign(std::move(name), std::move(value));
        }
    }

    SecureWipe(line);
    return total;
}

int CurlHttpClient::ProgressCallback(void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    auto* self = static_cast<CurlHttpClient*>(clientp);
    if (self == nullptr) {
        return 0;
    }

    if (!self->m_config.security_policy.OnHeartbeat()) {
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

    if (headers != nullptr && m_session != nullptr) {
        m_session->Api().slist_free_all(headers);
    }
}

void CurlHttpClient::ApplyCommonOptions(
    const HttpRequest& request,
    HttpResponse& response,
    char* error_buffer,
    void* body_ctx,
    std::string* protocol_scheme,
    std::string* redirect_protocol_scheme,
    std::string* user_agent_storage,
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

    curl_api.easy_setopt(easy, CURLOPT_URL, request.url.c_str());
    curl_api.easy_setopt(easy, CURLOPT_ERRORBUFFER, error_buffer);
    curl_api.easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CurlHttpClient::WriteBodyCallback);
    curl_api.easy_setopt(easy, CURLOPT_WRITEDATA, body_ctx);
    curl_api.easy_setopt(easy, CURLOPT_HEADERFUNCTION, &CurlHttpClient::WriteHeaderCallback);
    curl_api.easy_setopt(easy, CURLOPT_HEADERDATA, &response.headers);
#ifdef CURLOPT_XFERINFOFUNCTION
    curl_api.easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, &CurlHttpClient::ProgressCallback);
    curl_api.easy_setopt(easy, CURLOPT_XFERINFODATA, this);
    curl_api.easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
#endif
    curl_api.easy_setopt(easy, CURLOPT_FOLLOWLOCATION, request.follow_redirects ? 1L : 0L);
    if (!m_config.use_system_proxy) {
        curl_api.easy_setopt(easy, CURLOPT_PROXY, "");
    }
#ifdef CURLOPT_PROTOCOLS_STR
    if (protocol_scheme != nullptr) {
        *protocol_scheme = BURNER_OBF_LITERAL("https");
        curl_api.easy_setopt(easy, CURLOPT_PROTOCOLS_STR, protocol_scheme->c_str());
    }
#elif defined(CURLOPT_PROTOCOLS)
    curl_api.easy_setopt(easy, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#endif
#ifdef CURLOPT_DISALLOW_USERNAME_IN_URL
    curl_api.easy_setopt(easy, CURLOPT_DISALLOW_USERNAME_IN_URL, 1L);
#endif
    if (request.follow_redirects) {
#ifdef CURLOPT_REDIR_PROTOCOLS_STR
        if (redirect_protocol_scheme != nullptr) {
            *redirect_protocol_scheme = BURNER_OBF_LITERAL("https");
            curl_api.easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, redirect_protocol_scheme->c_str());
        }
#elif defined(CURLOPT_REDIR_PROTOCOLS)
        curl_api.easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
#endif
        curl_api.easy_setopt(easy, CURLOPT_MAXREDIRS, 10L);
    }
    curl_api.easy_setopt(easy, CURLOPT_TIMEOUT, request.timeout_seconds);
    curl_api.easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, request.connect_timeout_seconds);

    if (user_agent_storage != nullptr) {
        *user_agent_storage = m_config.security_policy.GetUserAgent();
    }
    if (user_agent_storage != nullptr && !user_agent_storage->empty()) {
        curl_api.easy_setopt(easy, CURLOPT_USERAGENT, user_agent_storage->c_str());
    } else if (!m_config.user_agent.empty()) {
        curl_api.easy_setopt(easy, CURLOPT_USERAGENT, m_config.user_agent.c_str());
    }

    curl_api.easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, m_config.verify_peer ? 1L : 0L);
    curl_api.easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, m_config.verify_host ? 2L : 0L);
    curl_api.easy_setopt(easy, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#ifdef CURLSSLOPT_NATIVE_CA
    if (m_config.use_native_ca) {
        curl_api.easy_setopt(easy, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
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
        curl_api.easy_setopt(easy, CURLOPT_PINNEDPUBLICKEY, pinned_keys.c_str());
        SecureWipe(pinned_keys);
    }

    ClearDnsStrategy();
    if (strategy.has_value()) {
        ApplyDnsStrategy(*strategy);
    }
}

void CurlHttpClient::ApplyMethodAndBody(const HttpRequest& request, std::string* custom_method_storage) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    const CurlApi& curl_api = m_session->Api();

    switch (request.method) {
    case HttpMethod::Get:
        curl_api.easy_setopt(easy, CURLOPT_HTTPGET, 1L);
        break;
    case HttpMethod::Post:
        curl_api.easy_setopt(easy, CURLOPT_POST, 1L);
        curl_api.easy_setopt(easy, CURLOPT_POSTFIELDS, request.body.c_str());
        curl_api.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
        break;
    case HttpMethod::Put:
    case HttpMethod::Delete:
    case HttpMethod::Patch:
        if (custom_method_storage != nullptr) {
            *custom_method_storage = ToCurlMethod(request.method);
            curl_api.easy_setopt(easy, CURLOPT_CUSTOMREQUEST, custom_method_storage->c_str());
        }
        if (!request.body.empty()) {
            curl_api.easy_setopt(easy, CURLOPT_POSTFIELDS, request.body.c_str());
            curl_api.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
        }
        break;
    }
}

void CurlHttpClient::ApplyTlsOptions(std::string* cert_type_storage, std::string* key_type_storage) {
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
    curl_api.easy_setopt(easy, CURLOPT_SSLCERT_BLOB, &cert_blob);
    curl_api.easy_setopt(easy, CURLOPT_SSLKEY_BLOB, &key_blob);
    curl_api.easy_setopt(easy, CURLOPT_KEYPASSWD, credentials.key_password.c_str());
    if (cert_type_storage != nullptr) {
        *cert_type_storage = BURNER_OBF_LITERAL("PEM");
        curl_api.easy_setopt(easy, CURLOPT_SSLCERTTYPE, cert_type_storage->c_str());
    }
    if (key_type_storage != nullptr) {
        *key_type_storage = BURNER_OBF_LITERAL("PEM");
        curl_api.easy_setopt(easy, CURLOPT_SSLKEYTYPE, key_type_storage->c_str());
    }
}

void CurlHttpClient::ApplyDnsStrategy(const DnsStrategy& strategy) {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    if (strategy.mode == DnsMode::Doh) {
        const CurlApi& curl_api = m_session->Api();
        curl_api.easy_setopt(easy, CURLOPT_DOH_URL, strategy.doh_url.c_str());
        curl_api.easy_setopt(easy, CURLOPT_DOH_SSL_VERIFYPEER, m_config.verify_peer ? 1L : 0L);
        curl_api.easy_setopt(easy, CURLOPT_DOH_SSL_VERIFYHOST, m_config.verify_host ? 2L : 0L);
    }
}

void CurlHttpClient::ClearDnsStrategy() {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    m_session->Api().easy_setopt(easy, CURLOPT_DOH_URL, nullptr);
}

void CurlHttpClient::ResetMethodState() {
    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        return;
    }

    const CurlApi& curl_api = m_session->Api();
    curl_api.easy_setopt(easy, CURLOPT_HTTPGET, 0L);
    curl_api.easy_setopt(easy, CURLOPT_POST, 0L);
    curl_api.easy_setopt(easy, CURLOPT_CUSTOMREQUEST, nullptr);
    curl_api.easy_setopt(easy, CURLOPT_POSTFIELDS, nullptr);
    curl_api.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, 0L);
#ifdef CURLOPT_XFERINFOFUNCTION
    curl_api.easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, nullptr);
    curl_api.easy_setopt(easy, CURLOPT_XFERINFODATA, nullptr);
    curl_api.easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
#endif
}

} // namespace burner::net

#endif
