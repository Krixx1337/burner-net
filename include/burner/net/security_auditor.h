#pragma once

#include "concepts.h"
#include "http.h"
#include "detail/kernel_resolver.h"

#include <cstdint>

namespace burner::net {

enum class AuditResult {
    Trusted,
    Compromised,
    Inconclusive
};

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
        const AuditResult result = AuditTransportTrust(client, canary_urls);
        const bool ok = result == AuditResult::Trusted;
        if (!ok && policy != nullptr) {
            policy->OnTamper();
        }
        return ok;
    }

    template <HttpClientConcept TClient>
    static AuditResult AuditTransportTrust(TClient* client, const std::vector<std::string>& canary_urls) {
        if (client == nullptr) {
            return AuditResult::Inconclusive;
        }
        if (!HasExpectedSystemModuleShape()) {
            return AuditResult::Compromised;
        }
        if (canary_urls.empty()) {
            return AuditResult::Trusted;
        }

        for (const auto& url : canary_urls) {
            HttpRequest request{};
            request.method = HttpMethod::Get;
            request.url = url;
            request.timeout_seconds = 10;
            request.connect_timeout_seconds = 5;
            request.follow_redirects = false;
            request.retry.max_attempts = 1;

            const HttpResponse response = client->Send(request);
            if (response.transport_error == ErrorCode::TlsVerificationFailed) {
                continue;
            }
            if (response.TransportOk()) {
                return AuditResult::Compromised;
            }
            return AuditResult::Inconclusive;
        }

        return AuditResult::Trusted;
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

