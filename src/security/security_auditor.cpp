#include "burner/net/security_auditor.h"

namespace burner::net {

bool SecurityAuditor::CheckTransportIntegrity(IHttpClient* client) {
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

    return expired_rejected && wrong_host_rejected;
}

} // namespace burner::net
