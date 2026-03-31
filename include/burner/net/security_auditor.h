#pragma once

#include "concepts.h"
#include "http.h"

namespace burner::net {

class BURNER_API SecurityAuditor {
public:
    template <HttpClientConcept TClient>
    static bool CheckTransportIntegrity(TClient* client, const std::vector<std::string>& canary_urls) {
        return CheckTransportIntegrity(client, client != nullptr ? client->SecurityPolicy() : nullptr, canary_urls);
    }

    template <HttpClientConcept TClient>
    static bool CheckTransportIntegrity(
        TClient* client,
        const burner::net::SecurityPolicy* policy,
        const std::vector<std::string>& canary_urls) {
        if (client == nullptr) {
            return false;
        }
        if (canary_urls.empty()) {
            return true;
        }

        auto check_domain = [&](const std::string& url) -> bool {
            HttpRequest request{};
            request.method = HttpMethod::Get;
            request.url = url;
            request.timeout_seconds = 10;
            request.connect_timeout_seconds = 5;
            request.follow_redirects = false;
            request.retry.max_attempts = 1;

            const HttpResponse response = client->Send(request);
            return response.transport_error == ErrorCode::TlsVerificationFailed;
        };

        bool ok = true;
        for (const auto& url : canary_urls) {
            if (!check_domain(url)) {
                ok = false;
                break;
            }
        }
        if (!ok && policy != nullptr) {
            policy->OnTamper();
        }
        return ok;
    }
};

} // namespace burner::net

