#include "burner/net/security_auditor.h"

namespace burner::net {

bool SecurityAuditor::CheckTransportIntegrity(IHttpClient* client) {
    return CheckTransportIntegrity(client, client != nullptr ? client->SecurityPolicy() : nullptr);
}

bool SecurityAuditor::CheckTransportIntegrity(IHttpClient* client, const ISecurityPolicy* policy) {
    if (client == nullptr) {
        return false;
    }

    auto check_domain = [&](const char* url) -> bool {
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

    const bool expired_rejected = check_domain("https://expired.badssl.com");
    const bool wrong_host_rejected = check_domain("https://wrong.host.badssl.com");
    const bool ok = expired_rejected && wrong_host_rejected;
    if (!ok && policy != nullptr) {
        policy->OnTamper();
    }
    return ok;
}

} // namespace burner::net
