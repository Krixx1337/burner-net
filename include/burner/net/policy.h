#pragma once

#include "burner/net/concepts.h"
#include "burner/net/detail/dark_allocator.h"
#include "burner/net/detail/dark_callables.h"
#include "burner/net/detail/pointer_mangling.h"
#include "burner/net/export.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <utility>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct TransportTelemetry;
struct HttpRequest;
struct HttpResponse;
struct TransferProgress;

struct BURNER_API ISecurityPolicy {
    bool OnVerifyEnvironment() const {
        return true;
    }

    bool OnPreRequest(HttpRequest&) const {
        return true;
    }

    bool OnVerifyTransport(const char* url, const char* remote_ip) const {
        (void)url;
        (void)remote_ip;
        return true;
    }

    bool OnAuditTelemetry(const TransportTelemetry& telemetry) const {
        (void)telemetry;
        return true;
    }

    bool OnHeartbeat(const TransferProgress& progress) const {
        (void)progress;
        return true;
    }

    bool OnResponseReceived(const HttpRequest& request, const HttpResponse& response) const {
        (void)request;
        (void)response;
        return true;
    }

    void OnSignatureVerified(bool success, ErrorCode reason) const {
        (void)success;
        (void)reason;
    }

    [[noreturn]] void OnTamper() const {
        std::abort();
    }

    void OnError(ErrorCode code, const char* url) const {
        (void)code;
        (void)url;
    }

    // Called inside the isolated worker thread immediately after it starts.
    // Return false to abort the request before any networking occurs.
    bool OnIsolatedWorkerStart() const { return true; }

    // Called inside the isolated worker thread immediately before it terminates.
    void OnIsolatedWorkerEnd() const {}

    DarkString GetUserAgent() const {
        return "";
    }
};

struct BURNER_API DefaultSecurityPolicy : ISecurityPolicy {};

class BURNER_API SecurityPolicy {
public:
    SecurityPolicy()
        : SecurityPolicy(DefaultSecurityPolicy{}) {}

    template <SecurityPolicyConcept TPolicy>
    SecurityPolicy(TPolicy policy) {
        emplace(std::move(policy));
    }

    [[nodiscard]] bool OnVerifyEnvironment() const {
        return m_on_verify_environment(m_state.get());
    }

    [[nodiscard]] bool OnPreRequest(HttpRequest& request) const {
        return m_on_pre_request(m_state.get(), request);
    }

    [[nodiscard]] bool OnVerifyTransport(const char* url, const char* remote_ip) const {
        return m_on_verify_transport(m_state.get(), url, remote_ip);
    }

    [[nodiscard]] bool OnAuditTelemetry(const TransportTelemetry& telemetry) const {
        return m_on_audit_telemetry(m_state.get(), telemetry);
    }

    [[nodiscard]] bool OnHeartbeat(const TransferProgress& progress) const {
        return m_on_heartbeat(m_state.get(), progress);
    }

    [[nodiscard]] bool OnResponseReceived(const HttpRequest& request, const HttpResponse& response) const {
        return m_on_response_received(m_state.get(), request, response);
    }

    void OnSignatureVerified(bool success, ErrorCode reason) const {
        m_on_signature_verified(m_state.get(), success, reason);
    }

    void OnTamper() const {
        m_on_tamper(m_state.get());
    }

    void OnError(ErrorCode code, const char* url) const {
        m_on_error(m_state.get(), code, url);
    }

    [[nodiscard]] DarkString GetUserAgent() const {
        return m_get_user_agent(m_state.get());
    }

    [[nodiscard]] bool OnIsolatedWorkerStart() const {
        return m_on_isolated_worker_start(m_state.get());
    }

    void OnIsolatedWorkerEnd() const {
        m_on_isolated_worker_end(m_state.get());
    }

private:
    template <SecurityPolicyConcept TPolicy>
    void emplace(TPolicy policy) {
        using PolicyType = std::decay_t<TPolicy>;

        m_state = detail::SecureHandle<const void>::template make<PolicyType>(std::move(policy));
        m_on_verify_environment = [](const void* raw) {
            return static_cast<const PolicyType*>(raw)->OnVerifyEnvironment();
        };
        m_on_pre_request = [](const void* raw, HttpRequest& request) {
            return static_cast<const PolicyType*>(raw)->OnPreRequest(request);
        };
        m_on_verify_transport = [](const void* raw, const char* url, const char* remote_ip) {
            return static_cast<const PolicyType*>(raw)->OnVerifyTransport(url, remote_ip);
        };
        m_on_audit_telemetry = [](const void* raw, const TransportTelemetry& telemetry) {
            if constexpr (requires(const PolicyType& policy, const TransportTelemetry& value) {
                              { policy.OnAuditTelemetry(value) } -> std::convertible_to<bool>;
                          }) {
                return static_cast<const PolicyType*>(raw)->OnAuditTelemetry(telemetry);
            } else {
                (void)raw;
                (void)telemetry;
                return true;
            }
        };
        m_on_heartbeat = [](const void* raw, const TransferProgress& progress) {
            return static_cast<const PolicyType*>(raw)->OnHeartbeat(progress);
        };
        m_on_response_received = [](const void* raw, const HttpRequest& request, const HttpResponse& response) {
            return static_cast<const PolicyType*>(raw)->OnResponseReceived(request, response);
        };
        m_on_signature_verified = [](const void* raw, bool success, ErrorCode reason) {
            static_cast<const PolicyType*>(raw)->OnSignatureVerified(success, reason);
        };
        m_on_tamper = [](const void* raw) {
            static_cast<const PolicyType*>(raw)->OnTamper();
        };
        m_on_error = [](const void* raw, ErrorCode code, const char* url) {
            static_cast<const PolicyType*>(raw)->OnError(code, url);
        };
        m_get_user_agent = [](const void* raw) -> DarkString {
            return DarkString(static_cast<const PolicyType*>(raw)->GetUserAgent());
        };
        m_on_isolated_worker_start = [](const void* raw) {
            return static_cast<const PolicyType*>(raw)->OnIsolatedWorkerStart();
        };
        m_on_isolated_worker_end = [](const void* raw) {
            static_cast<const PolicyType*>(raw)->OnIsolatedWorkerEnd();
        };
    }

    detail::SecureHandle<const void> m_state;
    EncodedPointer<bool (*)(const void*)> m_on_verify_environment = nullptr;
    EncodedPointer<bool (*)(const void*, HttpRequest&)> m_on_pre_request = nullptr;
    EncodedPointer<bool (*)(const void*, const char*, const char*)> m_on_verify_transport = nullptr;
    EncodedPointer<bool (*)(const void*, const TransportTelemetry&)> m_on_audit_telemetry = nullptr;
    EncodedPointer<bool (*)(const void*, const TransferProgress&)> m_on_heartbeat = nullptr;
    EncodedPointer<bool (*)(const void*, const HttpRequest&, const HttpResponse&)> m_on_response_received = nullptr;
    EncodedPointer<void (*)(const void*, bool, ErrorCode)> m_on_signature_verified = nullptr;
    EncodedPointer<void (*)(const void*)> m_on_tamper = nullptr;
    EncodedPointer<void (*)(const void*, ErrorCode, const char*)> m_on_error = nullptr;
    EncodedPointer<DarkString (*)(const void*)> m_get_user_agent = nullptr;
    EncodedPointer<bool (*)(const void*)> m_on_isolated_worker_start = nullptr;
    EncodedPointer<void (*)(const void*)> m_on_isolated_worker_end = nullptr;
};

} // namespace burner::net
