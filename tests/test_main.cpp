#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

#include <filesystem>
#include <iostream>

#include "burner/net/bootstrap.h"
#include "burner/net/error.h"

namespace {

bool InitializeTestRuntime(const char* argv0) {
#if BURNERNET_HARDEN_IMPORTS && defined(_WIN32)
    const std::filesystem::path executable_path = std::filesystem::absolute(argv0);

    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = executable_path.parent_path() / "redist";
    boot.dependency_dlls.push_back(
#if defined(_DEBUG)
        L"libcurl-d.dll"
#else
        L"libcurl.dll"
#endif
    );

    const burner::net::BootstrapResult init = burner::net::InitializeNetworkingRuntime(boot);
    if (!init.success) {
        std::cerr << "Test runtime bootstrap failed: "
                  << static_cast<unsigned int>(init.code) << '\n';
        return false;
    }
#else
    (void)argv0;
#endif

    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (!InitializeTestRuntime(argc > 0 ? argv[0] : "")) {
        return 1;
    }

    doctest::Context context;
    context.applyCommandLine(argc, argv);
    return context.run();
}
