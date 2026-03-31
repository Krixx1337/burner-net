#include <iostream>
#include <string_view>

int RunBasicUsage();
int RunZeroTrustPipeline();
int RunCustomPolicy();
int RunBootstrapRuntime();
int RunMtlsUsage();
int RunCustomHmacWeapon();

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "BurnerNet Example Suite\n"
                  << "Usage: BurnerNetExamples <example_name>\n\n"
                  << "Available examples:\n"
                  << "  basic      - Simple request with secure DoH defaults\n"
                  << "  hardened   - Audit check, pinning, and custom policy flow\n"
                  << "  policy     - Custom ISecurityPolicy implementation\n"
                  << "  bootstrap  - Load curl/OpenSSL runtime DLLs from a custom folder\n"
                  << "  mtls       - Short-lived mTLS credential provider pattern\n"
                  << "  hmac       - App-owned HMAC response verification via lambda\n";
        return 0;
    }

    const std::string_view example(argv[1]);
    if (example == "basic") {
        return RunBasicUsage();
    }
    if (example == "hardened") {
        return RunZeroTrustPipeline();
    }
    if (example == "policy") {
        return RunCustomPolicy();
    }
    if (example == "bootstrap") {
        return RunBootstrapRuntime();
    }
    if (example == "mtls") {
        return RunMtlsUsage();
    }
    if (example == "hmac") {
        return RunCustomHmacWeapon();
    }

    std::cerr << "Unknown example: " << example << '\n';
    return 1;
}
