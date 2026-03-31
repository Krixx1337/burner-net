#pragma once

#include "concepts.h"
#include "http.h"
#include "detail/kernel_resolver.h"

#include <cstdint>

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
        if (!HasExpectedSystemModuleShape()) {
            if (policy != nullptr) {
                policy->OnTamper();
            }
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

private:
    [[nodiscard]] static bool HasExpectedSystemModuleShape() {
#ifdef _WIN32
        void* const ntdll = ::burner::net::detail::KernelResolver::GetSystemModule(
            ::burner::net::detail::fnv1a_ci("ntdll.dll"));
        if (ntdll == nullptr) {
            return false;
        }

        return ::burner::net::detail::KernelResolver::FindModuleSignature(
                   ntdll,
                   static_cast<std::uint8_t>(0xC3u)) != nullptr;
#else
        return true;
#endif
    }
};

} // namespace burner::net

