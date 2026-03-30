#pragma once

#include "burner/net/concepts.h"
#include "burner/net/export.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct HttpRequest;
struct HttpResponse;

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

    bool OnHeartbeat() const {
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

    std::string GetUserAgent() const {
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

    [[nodiscard]] bool OnHeartbeat() const {
        return m_on_heartbeat(m_state.get());
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

    [[nodiscard]] std::string GetUserAgent() const {
        return m_get_user_agent(m_state.get());
    }

private:
    template <SecurityPolicyConcept TPolicy>
    void emplace(TPolicy policy) {
        using PolicyType = std::decay_t<TPolicy>;

        auto state = std::make_shared<PolicyType>(std::move(policy));
        m_state = state;
        m_on_verify_environment = [](const void* raw) {
            return static_cast<const PolicyType*>(raw)->OnVerifyEnvironment();
        };
        m_on_pre_request = [](const void* raw, HttpRequest& request) {
            return static_cast<const PolicyType*>(raw)->OnPreRequest(request);
        };
        m_on_verify_transport = [](const void* raw, const char* url, const char* remote_ip) {
            return static_cast<const PolicyType*>(raw)->OnVerifyTransport(url, remote_ip);
        };
        m_on_heartbeat = [](const void* raw) {
            return static_cast<const PolicyType*>(raw)->OnHeartbeat();
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
        m_get_user_agent = [](const void* raw) {
            return static_cast<const PolicyType*>(raw)->GetUserAgent();
        };
    }

    std::shared_ptr<const void> m_state;
    bool (*m_on_verify_environment)(const void*) = nullptr;
    bool (*m_on_pre_request)(const void*, HttpRequest&) = nullptr;
    bool (*m_on_verify_transport)(const void*, const char*, const char*) = nullptr;
    bool (*m_on_heartbeat)(const void*) = nullptr;
    bool (*m_on_response_received)(const void*, const HttpRequest&, const HttpResponse&) = nullptr;
    void (*m_on_signature_verified)(const void*, bool, ErrorCode) = nullptr;
    void (*m_on_tamper)(const void*) = nullptr;
    void (*m_on_error)(const void*, ErrorCode, const char*) = nullptr;
    std::string (*m_get_user_agent)(const void*) = nullptr;
};

} // namespace burner::net
