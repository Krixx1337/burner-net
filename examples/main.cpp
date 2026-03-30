#include <iostream>
#include <string_view>

int RunBasicUsage();
int RunZeroTrustPipeline();
int RunCustomPolicy();
int RunBootstrapRuntime();

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "BurnerNet Example Suite\n"
                  << "Usage: BurnerNetExamples <example_name>\n\n"
                  << "Available examples:\n"
                  << "  basic      - Simple request with secure DoH defaults\n"
                  << "  hardened   - Audit check, pinned key, and HMAC verification flow\n"
                  << "  policy     - Custom ISecurityPolicy implementation\n"
                  << "  bootstrap  - Load curl/OpenSSL runtime DLLs from a custom folder\n";
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

    std::cerr << "Unknown example: " << example << '\n';
    return 1;
}
