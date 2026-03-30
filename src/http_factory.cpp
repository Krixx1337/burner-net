#include "burner/net/http.h"

#if BURNER_ENABLE_CURL
#include "curl/curl_http_client.h"
#endif

namespace burner::net {

ClientCreateResult CreateHttpClient(const ClientConfig& config) {
#if BURNER_ENABLE_CURL
    ClientCreateResult result;
    auto client = std::make_unique<CurlHttpClient>(config);
    if (!client->IsInitialized()) {
        result.error = client->InitError();
        return result;
    }

    result.client = std::move(client);
    return result;
#else
    (void)config;
    return {nullptr, ErrorCode::DisabledBackend};
#endif
}

} // namespace burner::net
