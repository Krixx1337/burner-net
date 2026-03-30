#pragma once

#include <functional>

#include "export.h"
#include "http.h"

namespace burner::net {

struct SignatureVerifierConfig {
    std::string signature_header;
    SecureString secret;
    std::function<bool(std::string& out)> secret_provider;
};

class BURNER_API HmacSha256HeaderVerifier final {
public:
    explicit HmacSha256HeaderVerifier(SignatureVerifierConfig config);

    bool Verify(const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) const;

private:
    SignatureVerifierConfig m_config;
};

} // namespace burner::net
