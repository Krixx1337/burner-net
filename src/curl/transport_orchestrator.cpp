#include "transport_orchestrator.h"

#include "curl_http_client.h"
#include "../internal/header_validation.h"

#include <algorithm>
#include <chrono>
#include <thread>

namespace burner::net {

namespace {

// Total transport attempts (retry attempts x DNS strategies) allowed for one
// Execute call. Bounds memory, time, and server-side replay exposure from
// pathological retry x fallback combinations.
constexpr int kMaxTotalTransportAttempts = 32;

bool RequestHasBody(const HttpRequest& request) {
    return !request.body.empty() ||
        !request.body_view.empty() ||
        static_cast<bool>(request.stream_payload_provider);
}

// Redirects are followed internally by curl, so the request guard would only
// ever see the original URL and custom headers/bodies could cross origins.
// Without an explicit per-hop trust model, redirects are rejected whenever
// any of those are present.
bool RedirectBlockedByPolicy(const ClientConfig& config, const HttpRequest& request) {
    if (!request.follow_redirects) {
        return false;
    }
    if (request.bearer_token_provider ||
        config.bearer_token_provider ||
        config.mtls_provider ||
        config.response_verifier) {
        return true;
    }
    if (config.request_guard) {
        return true;
    }
    if (!config.default_headers.empty() || !request.headers.empty()) {
        return true;
    }
    if (RequestHasBody(request)) {
        return true;
    }
    return false;
}

ErrorCode ValidateEffectiveDnsPolicy(const ClientConfig& config, const HttpRequest& request) {
    // Reject malformed strategies on every profile before any network
    // activity; a bad DoH URL must never silently degrade to system DNS, and
    // an unknown mode must never be treated as DoH or system by accident.
    // This is the same validator the builder path uses.
    for (const DnsStrategy& strategy : request.dns_fallback.strategies) {
        if (const ErrorCode strategy_error = internal::ValidateDnsStrategy(strategy);
            strategy_error != ErrorCode::None) {
            return strategy_error;
        }
    }

    if (!config.require_response_verification) {
        return ErrorCode::None;
    }

    // Hardened profile: the effective policy must carry at least one valid
    // DoH strategy. System DNS is accepted only as an explicit trailing
    // fallback after every DoH entry, mirroring the build-time ordering rule.
    if (!request.dns_fallback.enabled || request.dns_fallback.strategies.empty()) {
        return ErrorCode::HardenedDohRequired;
    }
    bool has_doh = false;
    bool seen_system_dns = false;
    for (const DnsStrategy& strategy : request.dns_fallback.strategies) {
        switch (strategy.mode) {
        case DnsMode::System:
            seen_system_dns = true;
            break;
        case DnsMode::Doh:
            has_doh = true;
            if (seen_system_dns) {
                return ErrorCode::HardenedSystemDnsOrder;
            }
            break;
        default:
            // Unreachable after ValidateDnsStrategy above; defense in depth.
            return ErrorCode::InvalidDnsMode;
        }
    }
    if (!has_doh) {
        return ErrorCode::HardenedDohRequired;
    }
    return ErrorCode::None;
}

} // namespace

TransportOrchestrator::TransportOrchestrator(CurlHttpClient& client)
    : m_client(client) {}

HttpResponse TransportOrchestrator::Execute(HttpRequest request) {
    HttpResponse response{};
    // Validate the request URL before invoking guards: guards inspect the
    // length-aware DarkString while curl receives a C string, so an embedded
    // NUL (or control characters) would let a guard or log inspect more
    // bytes than curl sends. The same HTTPS-only check gates DoH endpoints,
    // giving guards one consistent URL contract.
    if (!internal::IsValidHttpsUrl(std::string_view(request.url.data(), request.url.size()))) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::InvalidRequestUrl;
        return response;
    }
    // User-Agent values reach CURLOPT_USERAGENT without ordinary header
    // validation (including direct ClientConfig construction), so reject
    // CR/LF/NUL/controls and overlong values before any provider or guard
    // runs. Never silently sanitize.
    if (!m_client.m_config.user_agent.empty() &&
        !internal::IsValidUserAgent(std::string_view(
            m_client.m_config.user_agent.data(),
            m_client.m_config.user_agent.size()))) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::InvalidUserAgent;
        return response;
    }
    if (m_client.m_config.require_response_verification && request.follow_redirects) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::HardenedRedirectForbidden;
        return response;
    }
    if (RedirectBlockedByPolicy(m_client.m_config, request)) {
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
    if (const ErrorCode dns_error = ValidateEffectiveDnsPolicy(m_client.m_config, request);
        dns_error != ErrorCode::None) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = dns_error;
        return response;
    }

    // Timing contract: request timeouts apply per physical attempt, so a
    // multi-attempt operation can run longer than a single timeout. There is
    // no overall operation deadline yet; backoff sleeps do not poll transfer
    // cancellation. Callers needing a global bound must enforce it around
    // Send() (e.g. via WithTransferCancellation or their own deadline).
    const int attempts = std::clamp(
        (std::max)(1, request.retry.max_attempts), 1, kMaxTotalTransportAttempts);

    int remaining_attempts = kMaxTotalTransportAttempts;
    for (int attempt = 1; attempt <= attempts && remaining_attempts > 0; ++attempt) {
        response = PerformWithDnsFallback(request, remaining_attempts);
        if (!m_client.ShouldRetry(request, response, attempt)) {
            break;
        }
        // Only wipe and back off when another physical attempt will actually
        // occur. When the per-request attempt cap or the total transport
        // budget is exhausted, the final response must be preserved instead
        // of wiped with no follow-up attempt.
        if (attempt >= attempts || remaining_attempts <= 0) {
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

HttpResponse TransportOrchestrator::PerformWithDnsFallback(HttpRequest request, int& remaining_attempts) {
    if (!request.dns_fallback.enabled || request.dns_fallback.strategies.empty()) {
        if (remaining_attempts <= 0) {
            HttpResponse response{};
            response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
            response.transport_error = ErrorCode::CallbackFailed;
            return response;
        }
        --remaining_attempts;
        return m_client.PerformOnce(std::move(request), std::nullopt);
    }

    HttpResponse last_response{};
    for (const DnsStrategy& strategy : request.dns_fallback.strategies) {
        if (remaining_attempts <= 0) {
            break;
        }
        --remaining_attempts;
        last_response = m_client.PerformOnce(request, strategy);
        if (last_response.TransportOk()) {
            return last_response;
        }
        // DNS fallback replays only failures known to occur before the
        // application request was sent (resolution/connect). Timeouts and
        // other outcomes are ambiguous: the server may already have committed
        // a non-idempotent request, so they never trigger another strategy.
        if (!m_client.IsDnsFallbackRetryable(last_response.transport_error)) {
            return last_response;
        }
        m_client.WipeResponse(last_response);
    }

    return last_response;
}

} // namespace burner::net
