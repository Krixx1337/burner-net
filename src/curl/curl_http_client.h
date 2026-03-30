#pragma once

#include "burner/net/http.h"
#include "burner/net/detail/pointer_mangling.h"

#include <curl/curl.h>
#include <optional>

namespace burner::net {

namespace detail {

bool WouldExceedBodyLimit(std::size_t current_size, std::size_t chunk_size, std::size_t max_body_bytes) noexcept;

} // namespace detail

using CurlEasyInitFn = CURL* (*)();
using CurlEasyCleanupFn = void (*)(CURL*);
using CurlEasyResetFn = void (*)(CURL*);
using CurlEasySetoptFn = CURLcode (*)(CURL*, CURLoption, ...);
using CurlEasyPerformFn = CURLcode (*)(CURL*);
using CurlEasyGetinfoFn = CURLcode (*)(CURL*, CURLINFO, ...);
using CurlSlistAppendFn = curl_slist* (*)(curl_slist*, const char*);
using CurlSlistFreeAllFn = void (*)(curl_slist*);
using CurlEasyStrerrorFn = const char* (*)(CURLcode);

struct CurlApi {
    EncodedPointer<CurlEasyInitFn> easy_init = nullptr;
    EncodedPointer<CurlEasyCleanupFn> easy_cleanup = nullptr;
    EncodedPointer<CurlEasyResetFn> easy_reset = nullptr;
    EncodedPointer<CurlEasySetoptFn> easy_setopt = nullptr;
    EncodedPointer<CurlEasyPerformFn> easy_perform = nullptr;
    EncodedPointer<CurlEasyGetinfoFn> easy_getinfo = nullptr;
    EncodedPointer<CurlSlistAppendFn> slist_append = nullptr;
    EncodedPointer<CurlSlistFreeAllFn> slist_free_all = nullptr;
    EncodedPointer<CurlEasyStrerrorFn> easy_strerror = nullptr;
};

class CurlHttpClient final : public IHttpClient {
public:
    explicit CurlHttpClient(const ClientConfig& config);
    ~CurlHttpClient() override;

    HttpResponse Send(const HttpRequest& request) override;
    const ISecurityPolicy* SecurityPolicy() const override { return m_config.security_policy.get(); }

    bool IsInitialized() const { return m_easy != nullptr; }
    ErrorCode InitError() const { return m_init_error; }

private:
    HttpResponse PerformOnce(const HttpRequest& request);
    HttpResponse PerformOnceWithDnsFallback(const HttpRequest& request);
    bool ShouldRetry(const HttpRequest& request, const HttpResponse& response, int attempt) const;

    static size_t WriteBodyCallback(void* contents, size_t size, size_t nmemb, void* user_data);
    static size_t WriteHeaderCallback(void* contents, size_t size, size_t nmemb, void* user_data);
    static int ProgressCallback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);

    void ApplyCommonOptions(
        const HttpRequest& request,
        HttpResponse& response,
        char* error_buffer,
        void* body_ctx,
        std::string* protocol_scheme,
        std::string* redirect_protocol_scheme,
        std::string* user_agent_storage);
    void ApplyMethodAndBody(const HttpRequest& request, std::string* custom_method_storage);
    void ApplyTlsOptions(std::string* cert_type_storage, std::string* key_type_storage);
    void ApplyDnsStrategy(const DnsStrategy& strategy);
    void ClearDnsStrategy();
    void ResetMethodState();
    void WipeResponse(HttpResponse& response) const;
    void WipeHeaderList(curl_slist* headers) const;

private:
    void* m_easy = nullptr;
    ClientConfig m_config;
#if BURNER_ENABLE_CURL
    CurlApi m_curl_api{};
#endif
    ErrorCode m_init_error = ErrorCode::None;
    bool m_heartbeat_aborted = false;
    std::optional<DnsStrategy> m_active_dns_strategy;
};

} // namespace burner::net
