#pragma once

#include "burner/net/http.h"

#include <optional>

namespace burner::net {

class CurlHttpClient final : public IHttpClient {
public:
    explicit CurlHttpClient(const ClientConfig& config);
    ~CurlHttpClient() override;

    HttpResponse Send(const HttpRequest& request) override;

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
