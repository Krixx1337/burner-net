#pragma once

#include "burner/net/export.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct HttpRequest;

class BURNER_API ISecurityPolicy {
public:
    virtual ~ISecurityPolicy() = default;

    virtual bool OnVerifyEnvironment() const {
        return true;
    }

    virtual void OnPreRequest(HttpRequest&) const {}

    virtual bool OnVerifyTransport(const char* url, const char* remote_ip) const {
        (void)url;
        (void)remote_ip;
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

class BURNER_API DefaultSecurityPolicy final : public ISecurityPolicy {};

inline std::shared_ptr<ISecurityPolicy> DefaultSecurityPolicyInstance() {
    static std::shared_ptr<ISecurityPolicy> instance = std::make_shared<DefaultSecurityPolicy>();
    return instance;
}

inline std::shared_ptr<ISecurityPolicy> ResolveSecurityPolicy(std::shared_ptr<ISecurityPolicy> policy) {
    return policy ? std::move(policy) : DefaultSecurityPolicyInstance();
}

} // namespace burner::net
