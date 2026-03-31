#include <filesystem>
#include <iostream>

#include "burner/net/bootstrap.h"
#include "burner/net/error.h"

int RunBootstrapRuntime() {
    using namespace burner::net;

#ifndef _WIN32
    std::cout << "Bootstrap runtime example is Windows-only.\n";
    return 0;
#else
    BootstrapConfig boot{};
    boot.link_mode = LinkMode::Dynamic;
    boot.dependency_directory = std::filesystem::current_path() / "redist";
    boot.dependency_dlls.push_back(
#if defined(_DEBUG)
        L"libcurl-d.dll"
#else
        L"libcurl.dll"
#endif
    );
    boot.integrity_policy.enabled = true;
    boot.integrity_policy.fail_closed = false;
    boot.integrity_policy.integrity_provider =
        [](const std::filesystem::path& dll_path, const std::wstring&) {
            // Implement your own hash/signature verification here.
            return std::filesystem::exists(dll_path);
        };

    std::cout << "Initializing BurnerNet runtime from: "
              << boot.dependency_directory.string() << '\n';

    const auto init = InitializeNetworkingRuntime(boot);
    if (!init.success) {
        std::cerr << "Bootstrap initialization failed: "
                  << ErrorCodeToString(init.code) << '\n';
        return 1;
    }

    std::cout << "Bootstrap initialization result: "
              << ErrorCodeToString(init.code) << '\n';
    std::cout << "Replace the example path and integrity callback with your packaged runtime policy.\n";
    return 0;
#endif
}
