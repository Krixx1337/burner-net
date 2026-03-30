#include <iostream>
#include <string_view>

int RunBasicUsage();
int RunSecurityAudit();
int RunTrafficLanes();
int RunCustomPolicy();

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: BurnerNetExamples <example_name>\n"
                  << "Available examples:\n"
                  << "  basic   - Basic usage and DoH\n"
                  << "  audit   - Security auditor and TLS checks\n"
                  << "  lanes   - Paranoid vs Utility traffic lanes\n"
                  << "  policy  - Custom security policy\n";
        return 1;
    }

    const std::string_view example(argv[1]);
    if (example == "basic") {
        return RunBasicUsage();
    }
    if (example == "audit") {
        return RunSecurityAudit();
    }
    if (example == "lanes") {
        return RunTrafficLanes();
    }
    if (example == "policy") {
        return RunCustomPolicy();
    }

    std::cerr << "Unknown example: " << example << '\n';
    return 1;
}
