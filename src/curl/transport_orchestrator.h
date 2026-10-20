#pragma once

#include "burner/net/http.h"

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
        bool& resolution_timed_out);

    CurlHttpClient& m_client;
};

} // namespace burner::net
