#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "internal/runtime_module_registry.h"

#include <filesystem>

#if defined(_WIN32)
#include <windows.h>
#endif

int main(int argc, char** argv) {
#if !defined(_WIN32)
    (void)argc;
    (void)argv;
    return 0;
#else
    if (argc < 1) {
        return 1;
    }

    const std::filesystem::path executable =
        std::filesystem::absolute(std::filesystem::path(argv[0]));
    const std::filesystem::path redist = executable.parent_path() / "redist";
#if defined(_DEBUG)
    constexpr wchar_t curl_name[] = L"libcurl-d.dll";
    constexpr char curl_name_ascii[] = "libcurl-d.dll";
#else
    constexpr wchar_t curl_name[] = L"libcurl.dll";
    constexpr char curl_name_ascii[] = "libcurl.dll";
#endif
    if (!std::filesystem::exists(redist / curl_name)) {
        return 0;
    }

    burner::net::BootstrapConfig invalid{};
    invalid.link_mode = burner::net::LinkMode::Dynamic;
    invalid.dependency_directory = redist;
    invalid.dependency_dlls = {L"..\\untrusted.dll"};
    const auto invalid_result = burner::net::InitializeNetworkingRuntime(invalid);
    if (invalid_result.success ||
        invalid_result.code != burner::net::ErrorCode::InvalidBootstrapDependency) {
        return 2;
    }

    burner::net::BootstrapConfig throwing{};
    throwing.link_mode = burner::net::LinkMode::Dynamic;
    throwing.dependency_directory = redist;
    throwing.dependency_dlls = {curl_name};
    throwing.dependency_directory_guard =
        [](const std::filesystem::path&) -> bool { throw 7; };
    const auto throwing_result =
        burner::net::InitializeNetworkingRuntime(throwing);
    if (throwing_result.success ||
        throwing_result.code != burner::net::ErrorCode::CallbackFailed) {
        return 3;
    }

    burner::net::ErrorCode reentry_code = burner::net::ErrorCode::None;
    burner::net::BootstrapConfig reentrant{};
    reentrant.link_mode = burner::net::LinkMode::Dynamic;
    reentrant.dependency_directory = redist;
    reentrant.dependency_dlls = {curl_name};
    reentrant.dependency_directory_guard =
        [&](const std::filesystem::path&) {
            burner::net::BootstrapConfig nested = reentrant;
            nested.dependency_directory_guard = {};
            reentry_code =
                burner::net::InitializeNetworkingRuntime(nested).code;
            return false;
        };
    const auto reentrant_result =
        burner::net::InitializeNetworkingRuntime(reentrant);
    if (reentrant_result.success ||
        reentrant_result.code != burner::net::ErrorCode::BootstrapDirectoryRejected ||
        reentry_code != burner::net::ErrorCode::BootstrapBusy) {
        return 4;
    }

    burner::net::BootstrapConfig partial{};
    partial.link_mode = burner::net::LinkMode::Dynamic;
    partial.dependency_directory = redist;
    partial.dependency_dlls = {curl_name, L"missing-runtime.dll"};
    const auto partial_result = burner::net::InitializeNetworkingRuntime(partial);
    if (partial_result.success ||
        burner::net::detail::AcquireRuntimeModule(curl_name_ascii)) {
        return 5;
    }

    burner::net::BootstrapConfig valid{};
    valid.link_mode = burner::net::LinkMode::Dynamic;
    valid.dependency_directory = redist;
    valid.dependency_dlls = {curl_name};
    const auto valid_result = burner::net::InitializeNetworkingRuntime(valid);
    if (!valid_result.success) {
        return 6;
    }

    auto lease = burner::net::detail::AcquireRuntimeModule(curl_name_ascii);
    if (!lease || lease->handle == nullptr) {
        return 7;
    }

    auto client = burner::net::ClientBuilder().Build();
    if (!client.Ok()) {
        return 8;
    }

    burner::net::ShutdownNetworkingRuntime();
    if (burner::net::detail::AcquireRuntimeModule(curl_name_ascii)) {
        return 9;
    }
#if BURNERNET_HARDEN_IMPORTS
    const auto unavailable = burner::net::ClientBuilder().Build();
    if (unavailable.Ok() ||
        unavailable.error != burner::net::ErrorCode::NetworkingRuntimeUnavailable) {
        return 10;
    }
#endif
    if (!client.client->Raw()->IsInitialized()) {
        return 11;
    }
    if (::GetProcAddress(
            static_cast<HMODULE>(lease->handle),
            "curl_easy_init") == nullptr) {
        return 12;
    }

    client.client.reset();
    lease.reset();
    return 0;
#endif
}
