#include <filesystem>
#include <iostream>

#include <curl/curl.h>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/version.h"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {

std::filesystem::path ResolveExecutableDirectory(const char* argv0) {
#if defined(_WIN32)
    wchar_t module_path[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::filesystem::path(module_path).parent_path();
    }
#endif

    if (argv0 == nullptr || *argv0 == '\0') {
        return std::filesystem::current_path();
    }

    return std::filesystem::absolute(argv0).parent_path();
}

} // namespace

int main(int argc, char** argv) {
    std::cout << "curl: " << curl_version() << '\n';
    std::cout << "BurnerNet version: " << burner::net::VersionString << '\n';
    (void)argc;
    (void)argv;

#if defined(_WIN32) && !defined(CURL_STATICLIB)
    const std::filesystem::path executable_directory =
        ResolveExecutableDirectory(argc > 0 ? argv[0] : nullptr);

    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = executable_directory / "redist";

    const auto boot_result = burner::net::InitializeNetworkingRuntime(boot);
    std::cout << "bootstrap: " << burner::net::ErrorCodeToString(boot_result.code) << '\n';
    if (!boot_result.success) {
        return 1;
    }
#endif

    burner::net::ErrorCode build_error = burner::net::ErrorCode::None;
    auto client = burner::net::ClientBuilder().Build(&build_error);

    if (client == nullptr) {
        std::cerr << "Failed to build client. Error: "
                  << burner::net::ErrorCodeToString(build_error) << '\n';
        return 1;
    }

    std::cout << "Sending secure DoH request to example.com...\n";
    const auto response = client->Get("https://example.com").Send();
    std::cout << "Response code: " << response.status_code << '\n';
    if (response.TransportOk()) {
        std::cout << "Transport succeeded securely.\n";
        return 0;
    }

    std::cout << "Transport failed: "
              << burner::net::ErrorCodeToString(response.transport_error) << '\n';
    return 1;
}
