#include "burner/net/bootstrap.h"
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

using SetDefaultDllDirectoriesFn = decltype(&SetDefaultDllDirectories);

SetDefaultDllDirectoriesFn ResolveSetDefaultDllDirectories() noexcept {
    // Bootstrap stays on direct Win32 loader APIs; this path is reliability-critical
    // and should not depend on lazy-import indirection.
    const HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<SetDefaultDllDirectoriesFn>(
        ::GetProcAddress(kernel32, "SetDefaultDllDirectories"));
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
        const SetDefaultDllDirectoriesFn set_default_dll_directories = ResolveSetDefaultDllDirectories();
        if (set_default_dll_directories != nullptr) {
            (void)set_default_dll_directories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        }

        // Use the loader directly once we know the dependency directory.
        g_dependency_cookie = ::AddDllDirectory(config.dependency_directory.c_str());
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
