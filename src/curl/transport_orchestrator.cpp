#include "transport_orchestrator.h"

#include "curl_http_client.h"

#include <algorithm>
#include <chrono>
#include <thread>

namespace burner::net {

TransportOrchestrator::TransportOrchestrator(CurlHttpClient& client)
    : m_client(client) {}

HttpResponse TransportOrchestrator::Execute(const HttpRequest& request) {
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

HttpResponse TransportOrchestrator::PerformWithDnsFallback(const HttpRequest& request) {
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

} // namespace burner::net
