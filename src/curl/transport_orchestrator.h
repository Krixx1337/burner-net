#pragma once

#include "burner/net/http.h"

#include <optional>
#include <vector>

namespace burner::net {

class CurlHttpClient;

class TransportOrchestrator {
public:
    explicit TransportOrchestrator(CurlHttpClient& client);

    HttpResponse Execute(HttpRequest request);

private:
    HttpResponse PerformWithDnsFallback(
        HttpRequest request,
        int& remaining_attempts,
        std::vector<bool>& timed_out_strategies);

    HttpResponse RetryConnectSetup(
        HttpRequest& request,
        const std::optional<DnsStrategy>& strategy,
        int& remaining_attempts,
        HttpResponse last_response);

    CurlHttpClient& m_client;
};

} // namespace burner::net
