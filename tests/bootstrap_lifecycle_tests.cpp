#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "internal/runtime_module_registry.h"

#include <array>
#include <filesystem>
#include <string>
#include <vector>

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

#if BURNERNET_HARDEN_IMPORTS
    const auto before_bootstrap = burner::net::ClientBuilder().Build();
    REQUIRE_FALSE(before_bootstrap.Ok());
    REQUIRE(before_bootstrap.error == ErrorCode::NetworkingRuntimeUnavailable);
#endif
    REQUIRE_FALSE(burner::net::GlobalAllocatorHooksEnabled());

    std::vector<std::wstring> packaged_dlls;
    for (const auto& entry : std::filesystem::directory_iterator(redist)) {
        if (entry.path().extension() == L".dll") {
            packaged_dlls.push_back(entry.path().filename().wstring());
        }
    }
    REQUIRE_FALSE(packaged_dlls.empty());
    const auto accept_packaged_dependency =
        [](const std::filesystem::path& path, const std::wstring&) {
            return std::filesystem::exists(path);
        };

    BootstrapConfig invalid{};
    invalid.link_mode = LinkMode::Dynamic;
    invalid.dependency_directory = redist;
    invalid.dependency_dlls = {L"..\\untrusted.dll"};
    invalid.integrity_provider = accept_packaged_dependency;
    const auto invalid_result = InitializeNetworkingRuntime(invalid);
    REQUIRE_FALSE(invalid_result.success);
    REQUIRE(invalid_result.code == ErrorCode::InvalidBootstrapDependency);

#if BURNERNET_HARDEN_IMPORTS
    BootstrapConfig missing_integrity{};
    missing_integrity.link_mode = LinkMode::Dynamic;
    missing_integrity.dependency_directory = redist;
    missing_integrity.dependency_dlls = packaged_dlls;
    const auto missing_integrity_result =
        InitializeNetworkingRuntime(missing_integrity);
    REQUIRE_FALSE(missing_integrity_result.success);
    REQUIRE(missing_integrity_result.code == ErrorCode::BootstrapIntegrityCfg);

    BootstrapConfig rejected_integrity = missing_integrity;
    rejected_integrity.integrity_provider =
        [](const std::filesystem::path&, const std::wstring&) {
            return false;
        };
    const auto rejected_integrity_result =
        InitializeNetworkingRuntime(rejected_integrity);
    REQUIRE_FALSE(rejected_integrity_result.success);
    REQUIRE(
        rejected_integrity_result.code ==
        ErrorCode::BootstrapIntegrityMismatch);
    REQUIRE_FALSE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));

    const std::filesystem::path reparse_directory =
        executable.parent_path() /
        ("burnernet-reparse-" + std::to_string(::GetCurrentProcessId()));
    std::error_code reparse_error;
    std::filesystem::create_directory_symlink(
        redist,
        reparse_directory,
        reparse_error);
    if (!reparse_error) {
        BootstrapConfig reparse = missing_integrity;
        reparse.dependency_directory = reparse_directory;
        reparse.integrity_provider = accept_packaged_dependency;
        const auto reparse_result = InitializeNetworkingRuntime(reparse);
        CHECK_FALSE(reparse_result.success);
        CHECK(
            reparse_result.code ==
            ErrorCode::InvalidBootstrapDependency);
        std::error_code cleanup_error;
        (void)std::filesystem::remove(reparse_directory, cleanup_error);
        CHECK_FALSE(cleanup_error);
    }

    if (packaged_dlls.size() > 1) {
        BootstrapConfig incomplete_manifest{};
        incomplete_manifest.link_mode = LinkMode::Dynamic;
        incomplete_manifest.dependency_directory = redist;
        incomplete_manifest.dependency_dlls = {curl_name};
        incomplete_manifest.integrity_provider = accept_packaged_dependency;
        const auto incomplete_manifest_result =
            InitializeNetworkingRuntime(incomplete_manifest);
        REQUIRE_FALSE(incomplete_manifest_result.success);
        REQUIRE(
            incomplete_manifest_result.code ==
            ErrorCode::InvalidBootstrapDependency);
    }
#endif

    BootstrapConfig throwing{};
    throwing.link_mode = LinkMode::Dynamic;
    throwing.dependency_directory = redist;
    throwing.dependency_dlls = packaged_dlls;
    throwing.integrity_provider = accept_packaged_dependency;
    throwing.dependency_directory_guard =
        [](const std::filesystem::path&) -> bool { throw 7; };
    const auto throwing_result = InitializeNetworkingRuntime(throwing);
    REQUIRE_FALSE(throwing_result.success);
    REQUIRE(throwing_result.code == ErrorCode::CallbackFailed);

    ErrorCode reentry_code = ErrorCode::None;
    BootstrapConfig reentrant{};
    reentrant.link_mode = LinkMode::Dynamic;
    reentrant.dependency_directory = redist;
    reentrant.dependency_dlls = packaged_dlls;
    reentrant.integrity_provider = accept_packaged_dependency;
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
    partial.dependency_dlls = packaged_dlls;
    partial.dependency_dlls.push_back(L"missing-runtime.dll");
    partial.integrity_provider = accept_packaged_dependency;
    const auto partial_result = InitializeNetworkingRuntime(partial);
    REQUIRE_FALSE(partial_result.success);
    REQUIRE_FALSE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));

    BootstrapConfig valid{};
    valid.link_mode = LinkMode::Dynamic;
    valid.dependency_directory = redist;
    valid.dependency_dlls = packaged_dlls;
    valid.integrity_provider = accept_packaged_dependency;
    const auto valid_result = InitializeNetworkingRuntime(valid);
    REQUIRE(valid_result.success);
    const bool hooks_active = burner::net::GlobalAllocatorHooksEnabled();
#if !BURNERNET_MAXIMUM_GHOST && !BURNERNET_HARDEN_IMPORTS
    (void)hooks_active;
#endif
#if BURNERNET_MAXIMUM_GHOST
    const auto repeated_result = InitializeNetworkingRuntime(valid);
    REQUIRE(repeated_result.success);
    REQUIRE(repeated_result.code == ErrorCode::BootstrapSkip);
#endif

    auto lease = burner::net::detail::AcquireRuntimeModule(curl_name_ascii);
    REQUIRE(lease);
    REQUIRE(lease->handle != nullptr);

    auto client = burner::net::ClientBuilder().Build();
    REQUIRE(client.Ok());

    burner::net::ShutdownNetworkingRuntime();
#if BURNERNET_MAXIMUM_GHOST
    if (hooks_active) {
        REQUIRE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));
        REQUIRE(burner::net::GlobalAllocatorHooksEnabled());
    } else {
        REQUIRE_FALSE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));
        REQUIRE_FALSE(burner::net::GlobalAllocatorHooksEnabled());
    }
#else
    REQUIRE_FALSE(burner::net::detail::AcquireRuntimeModule(curl_name_ascii));
#endif

#if BURNERNET_HARDEN_IMPORTS
    const auto unavailable = burner::net::ClientBuilder().Build();
    if (hooks_active) {
        REQUIRE(unavailable.Ok());
    } else {
        REQUIRE_FALSE(unavailable.Ok());
        REQUIRE(unavailable.error == ErrorCode::NetworkingRuntimeUnavailable);
    }
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
