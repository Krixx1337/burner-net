#pragma once

#include "burner/net/http.h"

namespace burner::net {

class CurlHttpClient;

class TransportOrchestrator {
public:
    explicit TransportOrchestrator(CurlHttpClient& client);

    HttpResponse Execute(const HttpRequest& request);

private:
    HttpResponse PerformWithDnsFallback(const HttpRequest& request);

    CurlHttpClient& m_client;
};

} // namespace burner::net
