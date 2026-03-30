#pragma once

#include "burner/net/export.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct HttpRequest;
struct HttpResponse;

class BURNER_API ISecurityPolicy {
public:
    virtual ~ISecurityPolicy() = default;

    // Guardrail: keep this interface aligned with ClientBuilder hook coverage.
    // If a new "fire-and-burn" builder lambda is added for a security stage,
    // add the corresponding "global policy" hook here too so both composition
    // paths stay available and BuilderSecurityPolicy can mirror the lifecycle.

    virtual bool OnVerifyEnvironment() const {
        return true;
    }

    virtual bool OnPreRequest(HttpRequest&) const {
        return true;
    }

    virtual bool OnVerifyTransport(const char* url, const char* remote_ip) const {
        (void)url;
        (void)remote_ip;
        return true;
    }

    virtual bool OnHeartbeat() const {
        return true;
    }

    virtual bool OnResponseReceived(const HttpRequest& request, const HttpResponse& response) const {
        (void)request;
        (void)response;
        return true;
    }

    virtual void OnSignatureVerified(bool success, ErrorCode reason) const {
        (void)success;
        (void)reason;
    }

    virtual void OnTamper() const {
        std::abort();
    }

    virtual void OnError(ErrorCode code, const char* url) const {
        (void)code;
        (void)url;
    }

    virtual std::string GetUserAgent() const {
        return "";
    }
};

class BURNER_API DefaultSecurityPolicy : public ISecurityPolicy {};

inline std::shared_ptr<ISecurityPolicy> DefaultSecurityPolicyInstance() {
    static std::shared_ptr<ISecurityPolicy> instance = std::make_shared<DefaultSecurityPolicy>();
    return instance;
}

inline std::shared_ptr<ISecurityPolicy> ResolveSecurityPolicy(std::shared_ptr<ISecurityPolicy> policy) {
    return policy ? std::move(policy) : DefaultSecurityPolicyInstance();
}

} // namespace burner::net
