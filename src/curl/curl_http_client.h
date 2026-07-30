#pragma once

#include "burner/net/http.h"
#include "curl_api.h"

#include <memory>
#include <optional>

namespace burner::net {

namespace detail {

bool WouldExceedBodyLimit(std::size_t current_size, std::size_t chunk_size, std::size_t max_body_bytes) noexcept;

} // namespace detail

class CurlSession;
class TransportOrchestrator;
struct BodyReadContext;

class CurlHttpClient final {
public:
    explicit CurlHttpClient(const ClientConfig& config);
    ~CurlHttpClient();

    CurlHttpClient(const CurlHttpClient&) = delete;
    CurlHttpClient& operator=(const CurlHttpClient&) = delete;
    CurlHttpClient(CurlHttpClient&& other) noexcept;
    CurlHttpClient& operator=(CurlHttpClient&& other) noexcept;

    HttpResponse Send(const HttpRequest& request);

    bool IsInitialized() const;
    ErrorCode InitError() const { return m_init_error; }

private:
    friend struct CurlHttpClientTestAccess;
    HttpResponse PerformOnceInternal(const HttpRequest& request, const std::optional<DnsStrategy>& strategy);
    HttpResponse PerformOnce(HttpRequest request, std::optional<DnsStrategy> strategy);
    bool IsRetryable(ErrorCode error) const noexcept;
    bool ShouldRetry(const HttpRequest& request, const HttpResponse& response, int attempt) const;

    static size_t WriteBodyCallback(void* contents, size_t size, size_t nmemb, void* user_data);
    static size_t WriteHeaderCallback(void* contents, size_t size, size_t nmemb, void* user_data);
    static size_t ReadBodyCallback(char* buffer, size_t size, size_t nmemb, void* user_data);
    static int ProgressCallback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
    static int PrereqCallback(void* clientp, char* conn_primary_ip, char* conn_local_ip, int conn_primary_port, int conn_local_port);

    ErrorCode ApplyCommonOptions(
        const HttpRequest& request,
        char* error_buffer,
        void* body_ctx,
        void* header_ctx,
        DarkString* protocol_scheme,
        DarkString* redirect_protocol_scheme,
        DarkString* user_agent_storage,
        const std::optional<DnsStrategy>& strategy);
    ErrorCode ApplyMethodAndBody(const HttpRequest& request, DarkString* custom_method_storage, BodyReadContext* read_ctx);
    ErrorCode ApplyTlsOptions(DarkString* cert_type_storage, DarkString* key_type_storage);
    ErrorCode ApplyDnsStrategy(const DnsStrategy& strategy);
    ErrorCode ClearDnsStrategy();
    void WipeResponse(HttpResponse& response) const;
    void WipeHeaderList(curl_slist* headers) const;

private:
    friend class TransportOrchestrator;

    ClientConfig m_config;
    std::unique_ptr<CurlSession> m_session;
    ErrorCode m_init_error = ErrorCode::None;
    bool m_transfer_cancelled = false;
    bool m_connected_peer_rejected = false;
    bool m_callback_failed = false;
};

} // namespace burner::net
