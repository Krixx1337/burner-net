#include <iostream>
#include <memory>
#include <string_view>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/policy.h"

namespace {

class ExampleSecurityPolicy final : public burner::net::ISecurityPolicy {
public:
    bool OnVerifyTransport(const char* url, const char* remote_ip) const override {
        (void)url;
        return remote_ip != nullptr && std::string_view(remote_ip) != "127.0.0.1";
    }

    std::string GetUserAgent() const override {
        return "BurnerNetExampleCustomPolicy/1.0";
    }
};

} // namespace

int main() {
    auto build_result = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithSecurityPolicy(std::make_shared<ExampleSecurityPolicy>())
        .Build();

    if (build_result.client == nullptr) {
        std::cerr << "failed to build client: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "Runtime security policy example initialized.\n";
    std::cout << "If ExampleSecurityPolicy rejects a remote IP in OnVerifyTransport,\n";
    std::cout << "BurnerNet will fail the request with TransportVerificationFailed.\n";
    return 0;
}
