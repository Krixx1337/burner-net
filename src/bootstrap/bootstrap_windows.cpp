#include "burner/net/bootstrap.h"
#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/obfuscation.h"
#include "burner/net/detail/pointer_mangling.h"

#ifdef _WIN32
#if !BURNERNET_HARDEN_IMPORTS
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#include <windows.h>
#include <algorithm>
#include <cwctype>
#include <mutex>
#include <vector>

namespace burner::net {

namespace {

std::mutex g_loader_mutex;
std::vector<HMODULE> g_loaded_modules;
DLL_DIRECTORY_COOKIE g_dependency_cookie = nullptr;

using AddDllDirectoryFn = decltype(&AddDllDirectory);
using SetDefaultDllDirectoriesFn = decltype(&SetDefaultDllDirectories);

constexpr std::uint32_t kKernel32Hash = ::burner::net::detail::fnv1a_ci("kernel32.dll");
constexpr std::uint32_t kKernelBaseHash = ::burner::net::detail::fnv1a_ci("kernelbase.dll");
constexpr std::uint32_t kAddDllDirectoryHash = ::burner::net::detail::fnv1a("AddDllDirectory");
constexpr std::uint32_t kSetDefaultDllDirectoriesHash =
    ::burner::net::detail::fnv1a("SetDefaultDllDirectories");

template <typename TFn>
TFn ResolveLoaderFunc(std::uint32_t export_hash) noexcept {
    // Bootstrap is the DLL-search-path boundary for BurnerNet's dynamic runtime mode.
    // We intentionally use KernelResolver here instead of lazy-importer because these
    // specific loader APIs must come from the real kernel32/kernelbase images, not
    // from whatever the host process may have hooked in its IAT or loader façade.
    //
    // This also handles the modern Windows split where loader exports are frequently
    // forwarded between kernel32.dll and kernelbase.dll during the bootstrap phase.
    if (void* const kernelbase =
            ::burner::net::detail::KernelResolver::GetSystemModule(kKernelBaseHash)) {
        if (void* const resolved =
                ::burner::net::detail::KernelResolver::ResolveInternalExport(kernelbase, export_hash)) {
            return reinterpret_cast<TFn>(resolved);
        }
    }

    if (void* const kernel32 =
            ::burner::net::detail::KernelResolver::GetSystemModule(kKernel32Hash)) {
        if (void* const resolved =
                ::burner::net::detail::KernelResolver::ResolveInternalExport(kernel32, export_hash)) {
            return reinterpret_cast<TFn>(resolved);
        }
    }

    return nullptr;
}

std::wstring ToLowerWide(const std::wstring& value) {
    std::wstring out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return out;
}

bool PathsEqualCaseInsensitive(const std::filesystem::path& a, const std::filesystem::path& b) {
    return ToLowerWide(a.wstring()) == ToLowerWide(b.wstring());
}

} // namespace

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config) {
    ::burner::net::detail::InitializeEncodedPointerKey(
        reinterpret_cast<std::uintptr_t>(&config));

    const SecurityPolicy& security_policy = config.security_policy;
    if (config.link_mode == LinkMode::Static || !config.preload_dependencies) {
        return {true, ErrorCode::BootstrapSkip};
    }

    if (config.dependency_directory.empty()) {
        return {false, ErrorCode::BootstrapConfig};
    }

    if (!security_policy.OnVerifyEnvironment()) {
        return {false, ErrorCode::EnvironmentCompromised};
    }

    std::lock_guard<std::mutex> lock(g_loader_mutex);

    if (g_dependency_cookie == nullptr) {
        // Keep loader-search-path mutation on the provenance-checked resolver path.
        // lazy-importer is fine for many runtime imports, but bootstrap needs to
        // anchor these calls to the genuine backing module before loading redist DLLs.
        const SetDefaultDllDirectoriesFn set_default_dll_directories =
            ResolveLoaderFunc<SetDefaultDllDirectoriesFn>(kSetDefaultDllDirectoriesHash);
        if (set_default_dll_directories != nullptr) {
            (void)set_default_dll_directories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        }

        const AddDllDirectoryFn add_dll_directory =
            ResolveLoaderFunc<AddDllDirectoryFn>(kAddDllDirectoryHash);
        if (add_dll_directory == nullptr) {
            return {false, ErrorCode::BootstrapAddDir};
        }

        g_dependency_cookie = add_dll_directory(config.dependency_directory.c_str());
        if (g_dependency_cookie == nullptr) {
            return {false, ErrorCode::BootstrapAddDir};
        }
    }

    for (const auto& dll_name : config.dependency_dlls) {
        const std::filesystem::path full_path = config.dependency_directory / dll_name;

        if (config.integrity_policy.enabled) {
            if (!config.integrity_policy.integrity_provider) {
                if (config.integrity_policy.fail_closed) {
                    return {false, ErrorCode::BootstrapIntegrityCfg};
                }
            } else {
                const bool ok = config.integrity_policy.integrity_provider(full_path, dll_name);
                if (!ok && config.integrity_policy.fail_closed) {
                    return {false, ErrorCode::BootstrapIntegrityMismatch};
                }
            }
        }

        // Guardrail: LoadLibraryExW/GetModuleFileNameW/FreeLibrary remain direct.
        // Bootstrap owns DLL loading and path verification, so this must stay on the
        // OS loader path rather than hidden-import helpers.
        HMODULE module = ::LoadLibraryExW(
            full_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);

        if (module == nullptr) {
            return {false, ErrorCode::BootstrapLoad};
        }

        wchar_t loaded_path[MAX_PATH] = {};
        const DWORD n = ::GetModuleFileNameW(module, loaded_path, MAX_PATH);
        if (n == 0 || n == MAX_PATH || !PathsEqualCaseInsensitive(std::filesystem::path(loaded_path), full_path)) {
            ::FreeLibrary(module);
            return {false, ErrorCode::BootstrapModulePath};
        }

        g_loaded_modules.push_back(module);
    }

    return {true, ErrorCode::BootstrapLoaded};
}

} // namespace burner::net

#else

namespace burner::net {

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig&) {
    ::burner::net::detail::InitializeEncodedPointerKey();
    return {true, ErrorCode::BootstrapWinOnly};
}

} // namespace burner::net

#endif
