#include "transport_orchestrator.h"

#include "curl_http_client.h"

#include <algorithm>
#include <chrono>
#include <thread>

namespace burner::net {

TransportOrchestrator::TransportOrchestrator(CurlHttpClient& client)
    : m_client(client) {}

HttpResponse TransportOrchestrator::Execute(HttpRequest request) {
    HttpResponse response{};
    if (m_client.m_config.require_response_verification && request.follow_redirects) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::HardenedRedirectForbidden;
        return response;
    }
    if (request.follow_redirects &&
        (request.bearer_token_provider ||
         m_client.m_config.bearer_token_provider ||
         m_client.m_config.mtls_provider ||
         m_client.m_config.response_verifier)) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::RedirectAuth;
        return response;
    }
    if (m_client.m_config.request_guard) {
        try {
            if (!m_client.m_config.request_guard(request)) {
                response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
                response.transport_error = ErrorCode::RequestGuardRejected;
                return response;
            }
        } catch (...) {
            response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
            response.transport_error = ErrorCode::CallbackFailed;
            return response;
        }
    }

    const int attempts = (std::max)(1, request.retry.max_attempts);

    for (int attempt = 1; attempt <= attempts; ++attempt) {
        response = PerformWithDnsFallback(request);
        if (!m_client.ShouldRetry(request, response, attempt)) {
            break;
        }
        m_client.WipeResponse(response);

        const int backoff = (std::max)(0, request.retry.backoff_ms);
        if (backoff > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }
    }

    return response;
}

HttpResponse TransportOrchestrator::PerformWithDnsFallback(HttpRequest request) {
    if (!request.dns_fallback.enabled || request.dns_fallback.strategies.empty()) {
        return m_client.PerformOnce(std::move(request), std::nullopt);
    }

    HttpResponse last_response{};
    for (const DnsStrategy& strategy : request.dns_fallback.strategies) {
        last_response = m_client.PerformOnce(request, strategy);
        if (last_response.TransportOk()) {
            return last_response;
        }
        if (!m_client.IsRetryable(last_response.transport_error)) {
            return last_response;
        }
        m_client.WipeResponse(last_response);
    }

    return last_response;
}

} // namespace burner::net
