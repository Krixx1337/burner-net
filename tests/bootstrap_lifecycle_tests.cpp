#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "internal/runtime_module_registry.h"

#include <array>
#include <filesystem>

#if defined(_WIN32)
#include <windows.h>
#endif

TEST_CASE("Windows bootstrap validates, publishes, and releases one runtime transaction") {
#if !defined(_WIN32)
    MESSAGE("Bootstrap lifecycle is Windows-only");
#else
    using burner::net::BootstrapConfig;
    using burner::net::ErrorCode;
    using burner::net::InitializeNetworkingRuntime;
    using burner::net::LinkMode;

    std::array<wchar_t, 32768> executable_buffer{};
    const DWORD executable_length = ::GetModuleFileNameW(
        nullptr,
        executable_buffer.data(),
        static_cast<DWORD>(executable_buffer.size()));
    REQUIRE(executable_length > 0);
    REQUIRE(executable_length < executable_buffer.size());

    const std::filesystem::path executable(
        executable_buffer.data(),
        executable_buffer.data() + executable_length);
    const std::filesystem::path redist = executable.parent_path() / "redist";
#if defined(_DEBUG)
    constexpr wchar_t curl_name[] = L"libcurl-d.dll";
    constexpr char curl_name_ascii[] = "libcurl-d.dll";
#else
    constexpr wchar_t curl_name[] = L"libcurl.dll";
    constexpr char curl_name_ascii[] = "libcurl.dll";
#endif
    if (!std::filesystem::exists(redist / curl_name)) {
        MESSAGE("Runtime redist absent; lifecycle test has no packaged DLL to exercise");
        return;
    }

#if BURNERNET_MAXIMUM_GHOST
    const auto before_bootstrap = burner::net::ClientBuilder().Build();
    REQUIRE_FALSE(before_bootstrap.Ok());
    REQUIRE(before_bootstrap.error == ErrorCode::MaximumGhostRuntimeRequired);
#else
    REQUIRE_FALSE(burner::net::GlobalAllocatorHooksEnabled());
#endif

    BootstrapConfig invalid{};
    invalid.link_mode = LinkMode::Dynamic;
    invalid.dependency_directory = redist;
    invalid.dependency_dlls = {L"..\\untrusted.dll"};
    const auto invalid_result = InitializeNetworkingRuntime(invalid);
    REQUIRE_FALSE(invalid_result.success);
    REQUIRE(invalid_result.code == ErrorCode::InvalidBootstrapDependency);

    BootstrapConfig throwing{};
    throwing.link_mode = LinkMode::Dynamic;
    throwing.dependency_directory = redist;
    throwing.dependency_dlls = {curl_name};
    throwing.dependency_directory_guard =
        [](const std::filesystem::path&) -> bool { throw 7; };
    const auto throwing_result = InitializeNetworkingRuntime(throwing);
    REQUIRE_FALSE(throwing_result.success);
    REQUIRE(throwing_result.code == ErrorCode::CallbackFailed);

    ErrorCode reentry_code = ErrorCode::None;
    BootstrapConfig reentrant{};
    reentrant.link_mode = LinkMode::Dynamic;
    reentrant.dependency_directory = redist;
    reentrant.dependency_dlls = {curl_name};
    reentrant.dependency_directory_guard =
        [&](const std::filesystem::path&) {
            BootstrapConfig nested = reentrant;
            nested.dependency_directory_guard = {};
            reentry_code = InitializeNetworkingRuntime(nested).code;
            return false;
        };
    const auto reentrant_result = InitializeNetworkingRuntime(reentrant);
    REQUIRE_FALSE(reentrant_result.success);
    REQUIRE(reentrant_result.code == ErrorCode::BootstrapDirectoryRejected);
    REQUIRE(reentry_code == ErrorCode::BootstrapBusy);

    BootstrapConfig partial{};
    partial.link_mode = LinkMode::Dynamic;
    partial.dependency_directory = redist;
    partial.dependency_dlls = {curl_name, L"missing-runtime.dll"};
    const auto partial_result = InitializeNetworkingRuntime(partial);
    REQUIRE_FALSE(partial_result.success);
    REQUIRE_FALSE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));

    BootstrapConfig valid{};
    valid.link_mode = LinkMode::Dynamic;
    valid.dependency_directory = redist;
    valid.dependency_dlls = {curl_name};
    const auto valid_result = InitializeNetworkingRuntime(valid);
    REQUIRE(valid_result.success);
#if BURNERNET_MAXIMUM_GHOST
    const auto repeated_result = InitializeNetworkingRuntime(valid);
    REQUIRE(repeated_result.success);
    REQUIRE(repeated_result.code == ErrorCode::BootstrapSkip);
#else
    REQUIRE_FALSE(burner::net::GlobalAllocatorHooksEnabled());
#endif

    auto lease = burner::net::detail::AcquireRuntimeModule(curl_name_ascii);
    REQUIRE(lease);
    REQUIRE(lease->handle != nullptr);

    auto client = burner::net::ClientBuilder().Build();
    REQUIRE(client.Ok());

    burner::net::ShutdownNetworkingRuntime();
#if BURNERNET_MAXIMUM_GHOST
    REQUIRE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));
    REQUIRE(burner::net::GlobalAllocatorHooksEnabled());
#else
    REQUIRE_FALSE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));
#endif

#if BURNERNET_HARDEN_IMPORTS
    const auto unavailable = burner::net::ClientBuilder().Build();
#if BURNERNET_MAXIMUM_GHOST
    REQUIRE(unavailable.Ok());
#else
    REQUIRE_FALSE(unavailable.Ok());
    REQUIRE(unavailable.error == ErrorCode::NetworkingRuntimeUnavailable);
#endif
#endif

    REQUIRE(client.client->Raw()->IsInitialized());
    REQUIRE(
        ::GetProcAddress(
            static_cast<HMODULE>(lease->handle),
            "curl_easy_init") != nullptr);

    client.client.reset();
    lease.reset();
#endif
}
